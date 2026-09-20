import assert from "node:assert/strict"
import test from "node:test"

import type { OpaqueObjectHeaderV1, ObjectScopeV1 } from "../src/sync-client"
import {
  DurableVaultItemAcceptor,
  type VaultItemSyncState,
  type VaultItemSyncStateStore,
} from "../src/sync-vault-acceptance"
import {
  prepareVaultItemMutation,
  type EncryptedVaultItemV1,
} from "../src/sync-vault-item"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const HOUSEHOLD_ID = "22222222-2222-4222-8222-222222222222"
const SPACE_ID = "33333333-3333-4333-8333-333333333333"
const ITEM_ID = "44444444-4444-4444-8444-444444444444"
const KEY_ID = "55555555-5555-4555-8555-555555555555"
const OPERATION_ID = "66666666-6666-4666-8666-666666666666"
const scope: ObjectScopeV1 = {
  scope: "space",
  account_id: ACCOUNT_ID,
  household_id: HOUSEHOLD_ID,
  space_id: SPACE_ID,
}

class MemoryStateStore implements VaultItemSyncStateStore {
  state: VaultItemSyncState = { version: 0, baseline: null, conflict: null }
  failNextCommit = false

  async load(): Promise<VaultItemSyncState> {
    return structuredClone(this.state)
  }

  async commit(
    _accountId: string,
    _objectId: string,
    expectedVersion: number,
    next: Omit<VaultItemSyncState, "version">,
  ): Promise<number> {
    if (this.failNextCommit) {
      this.failNextCommit = false
      throw new Error("state disk unavailable")
    }
    if (this.state.version !== expectedVersion) throw new Error("state changed")
    this.state = { version: expectedVersion + 1, ...structuredClone(next) }
    return this.state.version
  }
}

function item(revision: number, marker = revision): EncryptedVaultItemV1 {
  return {
    format_version: 1,
    payload_schema_version: 8,
    algorithm: "xchacha20poly1305",
    object_id: ITEM_ID,
    key_id: KEY_ID,
    revision,
    key_nonce: Array(24).fill(1),
    wrapped_item_key: [2, 3, 4],
    payload_nonce: Array(24).fill(5),
    ciphertext: [6, 7, marker],
  }
}

async function pulled(next: EncryptedVaultItemV1, operationId = OPERATION_ID) {
  const prepared = await prepareVaultItemMutation(next, null, scope, operationId)
  return {
    metadata: { object: prepared.mutation.object, change_seq: next.revision, etag: `v${next.revision}` },
    ciphertext: prepared.ciphertext,
  }
}

test("acceptor applies a bootstrap item before advancing its durable baseline", async () => {
  const store = new MemoryStateStore()
  const acceptor = new DurableVaultItemAcceptor(ACCOUNT_ID, store)
  let local: EncryptedVaultItemV1 | null = null
  const result = await acceptor.accept(
    await pulled(item(1)),
    async () => local,
    async (remote, expected) => {
      assert.equal(expected, null)
      local = remote
      assert.equal(store.state.baseline, null)
    },
  )

  assert.equal(result.reconciliation.action, "apply_remote")
  assert.equal((local as unknown as EncryptedVaultItemV1).revision, 1)
  assert.equal((store.state.baseline as unknown as OpaqueObjectHeaderV1).revision, 1)
  assert.equal(store.state.version, 1)
})

test("replay repairs a baseline when state persistence failed after remote application", async () => {
  const store = new MemoryStateStore()
  const acceptor = new DurableVaultItemAcceptor(ACCOUNT_ID, store)
  let local: EncryptedVaultItemV1 | null = null
  let applications = 0
  const remote = await pulled(item(1))
  const apply = async (next: EncryptedVaultItemV1) => {
    applications += 1
    local = next
  }

  store.failNextCommit = true
  await assert.rejects(
    acceptor.accept(remote, async () => local, apply),
    /state disk unavailable/,
  )
  assert.equal((local as unknown as EncryptedVaultItemV1).revision, 1)
  assert.equal(store.state.baseline, null)

  const replay = await acceptor.accept(remote, async () => local, apply)
  assert.equal(replay.reconciliation.action, "unchanged")
  assert.equal(applications, 1)
  assert.equal((store.state.baseline as unknown as OpaqueObjectHeaderV1).revision, 1)
})

test("failed local application never advances the accepted server baseline", async () => {
  const store = new MemoryStateStore()
  const acceptor = new DurableVaultItemAcceptor(ACCOUNT_ID, store)
  await assert.rejects(
    acceptor.accept(
      await pulled(item(1)),
      async () => null,
      async () => {
        throw new Error("snapshot CAS failed")
      },
    ),
    /snapshot CAS failed/,
  )
  assert.deepEqual(store.state, { version: 0, baseline: null, conflict: null })
})

test("concurrent encrypted revisions are durably retained without replacing local state", async () => {
  const store = new MemoryStateStore()
  const acceptor = new DurableVaultItemAcceptor(ACCOUNT_ID, store)
  const baselinePull = await pulled(item(1))
  store.state = {
    version: 1,
    baseline: baselinePull.metadata.object as OpaqueObjectHeaderV1,
    conflict: null,
  }
  const local = item(2, 20)
  let applied = false
  const remote = await pulled(
    item(2, 21),
    "77777777-7777-4777-8777-777777777777",
  )
  const result = await acceptor.accept(
    remote,
    async () => local,
    async () => {
      applied = true
    },
  )

  assert.equal(result.reconciliation.action, "conflict")
  assert.equal(applied, false)
  assert.equal(store.state.baseline?.revision, 1)
  assert.equal(store.state.conflict?.remoteHeader.revision, 2)
  assert.deepEqual(store.state.conflict?.remoteCiphertext, remote.ciphertext)
})

test("a local-ahead item keeps its accepted baseline and is never overwritten", async () => {
  const store = new MemoryStateStore()
  const baselinePull = await pulled(item(1))
  store.state = {
    version: 3,
    baseline: baselinePull.metadata.object as OpaqueObjectHeaderV1,
    conflict: null,
  }
  const acceptor = new DurableVaultItemAcceptor(ACCOUNT_ID, store)
  const result = await acceptor.accept(
    baselinePull,
    async () => item(2),
    async () => assert.fail("local-ahead ciphertext must not be replaced"),
  )
  assert.equal(result.reconciliation.action, "keep_local")
  assert.equal(result.stateVersion, 3)
  assert.equal(store.state.version, 3)
})
