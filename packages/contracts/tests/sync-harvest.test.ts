import assert from "node:assert/strict"
import test from "node:test"

import type { ObjectScopeV1, OpaqueObjectHeaderV1 } from "../src/sync-client"
import {
  DurableVaultItemHarvester,
  type EncryptedVaultInventory,
  type VaultItemSyncStateReader,
} from "../src/sync-harvest"
import {
  DurableSyncOutbox,
  type QueuedOpaqueMutation,
  type SyncOutboxStore,
} from "../src/sync-queue"
import type { VaultItemSyncState } from "../src/sync-vault-acceptance"
import {
  prepareVaultItemMutation,
  type EncryptedVaultItemV1,
} from "../src/sync-vault-item"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const HOUSEHOLD_ID = "22222222-2222-4222-8222-222222222222"
const SPACE_ID = "33333333-3333-4333-8333-333333333333"
const CREATE_ID = "44444444-4444-4444-8444-444444444444"
const UPDATE_ID = "55555555-5555-4555-8555-555555555555"
const CURRENT_ID = "66666666-6666-4666-8666-666666666666"
const CONFLICT_ID = "77777777-7777-4777-8777-777777777777"

const scope: ObjectScopeV1 = {
  scope: "space",
  account_id: ACCOUNT_ID,
  household_id: HOUSEHOLD_ID,
  space_id: SPACE_ID,
}

function item(objectId: string, revision: number, marker = revision): EncryptedVaultItemV1 {
  return {
    format_version: 1,
    payload_schema_version: 8,
    algorithm: "xchacha20poly1305",
    object_id: objectId,
    key_id: "88888888-8888-4888-8888-888888888888",
    revision,
    key_nonce: Array.from({ length: 24 }, (_, index) => index),
    wrapped_item_key: [1, 2, 3, 4],
    payload_nonce: Array.from({ length: 24 }, (_, index) => 23 - index),
    ciphertext: [9, 8, 7, marker],
  }
}

async function header(value: EncryptedVaultItemV1): Promise<OpaqueObjectHeaderV1> {
  return (await prepareVaultItemMutation(
    value,
    null,
    scope,
    "99999999-9999-4999-8999-999999999999",
  )).mutation.object
}

class MemoryOutboxStore implements SyncOutboxStore {
  entries = new Map<string, QueuedOpaqueMutation>()
  reverseReads = false

  async enqueue(_accountId: string, entry: QueuedOpaqueMutation): Promise<boolean> {
    const operationId = entry.mutation.operation_id
    const existing = this.entries.get(operationId)
    if (existing !== undefined) {
      assert.deepEqual(
        { mutation: entry.mutation, ciphertext: entry.ciphertext },
        { mutation: existing.mutation, ciphertext: existing.ciphertext },
        "a deterministic operation ID must bind identical content",
      )
      return false
    }
    this.entries.set(operationId, structuredClone(entry))
    return true
  }

  async list(_accountId: string, limit: number): Promise<QueuedOpaqueMutation[]> {
    const entries = Array.from(this.entries.values())
    if (this.reverseReads) entries.reverse()
    return structuredClone(entries.slice(0, limit))
  }

  async acknowledge(_accountId: string, operationId: string): Promise<void> {
    this.entries.delete(operationId)
  }

  async count(): Promise<number> {
    return this.entries.size
  }
}

class MemoryStateReader implements VaultItemSyncStateReader {
  readonly accountId = ACCOUNT_ID
  states = new Map<string, VaultItemSyncState>()

  async state(objectId: string): Promise<VaultItemSyncState> {
    return structuredClone(
      this.states.get(objectId) ?? { version: 0, baseline: null, conflict: null },
    )
  }
}

class MemoryInventory implements EncryptedVaultInventory {
  constructor(
    readonly items: Map<string, EncryptedVaultItemV1>,
    readonly tombstones = new Set<string>(),
  ) {}

  async listEncryptedItemIdsForSync(): Promise<string[]> {
    return Array.from(this.items.keys()).reverse()
  }

  async loadEncryptedItemForSync(objectId: string): Promise<unknown | null> {
    return structuredClone(this.items.get(objectId) ?? null)
  }

  async encryptedItemIsTombstoneForSync(objectId: string): Promise<boolean> {
    return this.tombstones.has(objectId)
  }
}

test("harvester reconstructs create/update entries and retries exact operations", async () => {
  const created = item(CREATE_ID, 1)
  const updateBase = item(UPDATE_ID, 1)
  const updated = item(UPDATE_ID, 2)
  const current = item(CURRENT_ID, 3)
  const conflicted = item(CONFLICT_ID, 2)
  const stateReader = new MemoryStateReader()
  stateReader.states.set(UPDATE_ID, {
    version: 1,
    baseline: await header(updateBase),
    conflict: null,
  })
  stateReader.states.set(CURRENT_ID, {
    version: 1,
    baseline: await header(current),
    conflict: null,
  })
  stateReader.states.set(CONFLICT_ID, {
    version: 2,
    baseline: await header(item(CONFLICT_ID, 1)),
    conflict: {
      remoteHeader: await header(item(CONFLICT_ID, 2, 99)),
      remoteCiphertext: new Uint8Array([1]),
    },
  })
  const store = new MemoryOutboxStore()
  const harvester = new DurableVaultItemHarvester(
    scope,
    new DurableSyncOutbox(ACCOUNT_ID, store),
    stateReader,
  )
  const inventory = new MemoryInventory(
    new Map([
      [CREATE_ID, created],
      [UPDATE_ID, updated],
      [CURRENT_ID, current],
      [CONFLICT_ID, conflicted],
    ]),
    new Set([CREATE_ID]),
  )

  assert.deepEqual(await harvester.harvest(inventory), {
    scanned: 4,
    enqueued: 2,
    alreadyQueued: 0,
    current: 1,
    blockedObjectIds: [CONFLICT_ID],
  })
  const queued = Array.from(store.entries.values())
  assert.equal(queued.length, 2)
  assert.equal(
    queued.find((entry) => entry.mutation.object.object_id === CREATE_ID)
      ?.mutation.object.tombstone,
    true,
  )
  assert.deepEqual(
    queued.map((entry) => entry.mutation.object.object_id).sort(),
    [CREATE_ID, UPDATE_ID],
  )
  const update = queued.find((entry) => entry.mutation.object.object_id === UPDATE_ID)
  assert.equal(update?.mutation.precondition.condition, "match")
  if (update?.mutation.precondition.condition === "match") {
    assert.equal(update.mutation.precondition.revision, 1)
  }

  assert.deepEqual(await harvester.harvest(inventory), {
    scanned: 4,
    enqueued: 0,
    alreadyQueued: 2,
    current: 1,
    blockedObjectIds: [CONFLICT_ID],
  })

  inventory.items.set(UPDATE_ID, item(UPDATE_ID, 3))
  assert.deepEqual(await harvester.harvest(inventory), {
    scanned: 4,
    enqueued: 1,
    alreadyQueued: 1,
    current: 1,
    blockedObjectIds: [CONFLICT_ID],
  })
  const chained = Array.from(store.entries.values())
    .find((entry) => entry.mutation.object.object_id === UPDATE_ID && entry.mutation.object.revision === 3)
  assert.equal(chained?.mutation.precondition.condition, "match")
  if (chained?.mutation.precondition.condition === "match") {
    assert.equal(chained.mutation.precondition.revision, 2)
  }
  store.reverseReads = true
  assert.equal((await harvester.harvest(inventory)).alreadyQueued, 2)
})

test("harvester fails closed on duplicate, missing, and substituted inventory records", async () => {
  const store = new MemoryOutboxStore()
  const harvester = new DurableVaultItemHarvester(
    scope,
    new DurableSyncOutbox(ACCOUNT_ID, store),
    new MemoryStateReader(),
  )
  const local = item(CREATE_ID, 1)

  await assert.rejects(
    harvester.harvest({
      async listEncryptedItemIdsForSync() { return [CREATE_ID, CREATE_ID] },
      async loadEncryptedItemForSync() { return local },
      async encryptedItemIsTombstoneForSync() { return false },
    }),
    /duplicate/,
  )
  await assert.rejects(
    harvester.harvest({
      async listEncryptedItemIdsForSync() { return [CREATE_ID] },
      async loadEncryptedItemForSync() { return null },
      async encryptedItemIsTombstoneForSync() { return false },
    }),
    /missing object/,
  )
  await assert.rejects(
    harvester.harvest({
      async listEncryptedItemIdsForSync() { return [CREATE_ID] },
      async loadEncryptedItemForSync() { return item(UPDATE_ID, 1) },
      async encryptedItemIsTombstoneForSync() { return false },
    }),
    /substituted object/,
  )
})
