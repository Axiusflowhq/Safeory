import assert from "node:assert/strict"
import test from "node:test"

import { CURRENT_SYNC_COMPATIBILITY } from "../src/sync-compatibility"
import type {
  SingleOwnerSyncBootstrapState,
  SingleOwnerSyncBootstrapStore,
} from "../src/sync-bootstrap"
import {
  SyncClient,
  type OpaqueMutationV1,
  type SyncObjectMetadataV1,
} from "../src/sync-client"
import {
  connectSingleOwnerVaultSync,
  type VaultSyncSession,
} from "../src/sync-runtime"
import { DurableSyncPuller, type SyncCursorStore } from "../src/sync-pull"
import {
  DurableSyncOutbox,
  type QueuedOpaqueMutation,
  type SyncOutboxStore,
} from "../src/sync-queue"
import {
  DurableVaultItemAcceptor,
  type VaultItemSyncState,
  type VaultItemSyncStateStore,
} from "../src/sync-vault-acceptance"
import type { EncryptedVaultItemV1 } from "../src/sync-vault-item"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const DEVICE_ID = "22222222-2222-4222-8222-222222222222"
const ITEM_ID = "55555555-5555-4555-8555-555555555555"
const DEVICE_TOKEN = `sfo_dev_v1_${"a".repeat(64)}`

const local: EncryptedVaultItemV1 = {
  format_version: 1,
  payload_schema_version: 8,
  algorithm: "xchacha20poly1305",
  object_id: ITEM_ID,
  key_id: "66666666-6666-4666-8666-666666666666",
  revision: 1,
  key_nonce: Array.from({ length: 24 }, (_, index) => index),
  wrapped_item_key: [1, 2, 3, 4],
  payload_nonce: Array.from({ length: 24 }, (_, index) => 23 - index),
  ciphertext: [9, 8, 7, 6],
}

class MemoryOutboxStore implements SyncOutboxStore {
  entries = new Map<string, QueuedOpaqueMutation>()

  async enqueue(_accountId: string, entry: QueuedOpaqueMutation): Promise<boolean> {
    if (this.entries.has(entry.mutation.operation_id)) return false
    this.entries.set(entry.mutation.operation_id, structuredClone(entry))
    return true
  }

  async list(_accountId: string, limit: number): Promise<QueuedOpaqueMutation[]> {
    return structuredClone(Array.from(this.entries.values()).slice(0, limit))
  }

  async acknowledge(_accountId: string, operationId: string): Promise<void> {
    this.entries.delete(operationId)
  }

  async count(): Promise<number> {
    return this.entries.size
  }
}

class MemoryCursorStore implements SyncCursorStore {
  cursor = 0

  async load(): Promise<number> {
    return this.cursor
  }

  async advance(_accountId: string, expected: number, next: number): Promise<void> {
    assert.equal(this.cursor, expected)
    this.cursor = next
  }
}

class MemoryItemStateStore implements VaultItemSyncStateStore {
  stateValue: VaultItemSyncState = { version: 0, baseline: null, conflict: null }

  async load(): Promise<VaultItemSyncState> {
    return structuredClone(this.stateValue)
  }

  async commit(
    _accountId: string,
    _objectId: string,
    expectedVersion: number,
    next: Omit<VaultItemSyncState, "version">,
  ): Promise<number> {
    assert.equal(this.stateValue.version, expectedVersion)
    this.stateValue = { version: expectedVersion + 1, ...structuredClone(next) }
    return this.stateValue.version
  }
}

class MemoryBootstrapStore implements SingleOwnerSyncBootstrapStore {
  value: SingleOwnerSyncBootstrapState | null = null

  async load(): Promise<SingleOwnerSyncBootstrapState | null> {
    return this.value === null ? null : structuredClone(this.value)
  }

  async create(
    _key: string,
    state: SingleOwnerSyncBootstrapState,
  ): Promise<SingleOwnerSyncBootstrapState> {
    this.value ??= structuredClone(state)
    return structuredClone(this.value)
  }

  async markPublished(
    _key: string,
    expectedVersion: number,
  ): Promise<SingleOwnerSyncBootstrapState> {
    assert.equal(this.value?.version, expectedVersion)
    this.value = {
      ...(this.value as SingleOwnerSyncBootstrapState),
      version: expectedVersion + 1,
      publication: "published",
    }
    return structuredClone(this.value)
  }
}

class MemorySession implements VaultSyncSession {
  async listEncryptedItemIdsForSync(): Promise<string[]> {
    return [ITEM_ID]
  }

  async loadEncryptedItemForSync(objectId: string): Promise<unknown | null> {
    return objectId === ITEM_ID ? structuredClone(local) : null
  }

  async encryptedItemIsTombstoneForSync(): Promise<boolean> {
    return false
  }

  async applyRemoteEncryptedItemForSync(): Promise<void> {
    assert.fail("the uploaded local ciphertext should reconcile as unchanged")
  }
}

test("runtime harvests after pull and converges the uploaded item on the next cycle", async () => {
  let committed: { metadata: SyncObjectMetadataV1; ciphertext: Uint8Array } | null = null
  const events: string[] = []
  const fetcher: typeof fetch = async (input, init = {}) => {
    const url = new URL(String(input))
    if (url.pathname.endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    if (url.pathname.endsWith("/v1/objects")) {
      events.push("list")
      const after = Number(url.searchParams.get("after"))
      return Response.json({
        objects: after === 0 && committed !== null ? [committed.metadata] : [],
        next_change_seq: committed === null ? 0 : 1,
      })
    }
    if (url.pathname.endsWith("/topology") && init.method === "PUT") {
      events.push("topology")
      return new Response(null, { status: 204 })
    }
    if (init.method === "PUT") {
      events.push("upload")
      const mutation = JSON.parse(
        new Headers(init.headers).get("x-safeory-mutation") ?? "null",
      ) as OpaqueMutationV1
      const ciphertext = new Uint8Array(await new Response(init.body).arrayBuffer())
      const metadata = { object: mutation.object, change_seq: 1, etag: '"item-1"' }
      committed = { metadata, ciphertext }
      return Response.json(metadata)
    }
    if (url.pathname.endsWith(`/${ITEM_ID}`) && committed !== null) {
      events.push("download")
      return new Response(committed.ciphertext.slice().buffer, {
        headers: { "content-length": String(committed.ciphertext.byteLength) },
      })
    }
    return new Response(null, { status: 404 })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher, deviceId: DEVICE_ID },
  )
  const outbox = new DurableSyncOutbox(ACCOUNT_ID, new MemoryOutboxStore())
  const puller = new DurableSyncPuller(ACCOUNT_ID, new MemoryCursorStore())
  const stateStore = new MemoryItemStateStore()
  const connected = await connectSingleOwnerVaultSync(
    client,
    "https://sync.example.test",
    new MemorySession(),
    {
      bootstrapStore: new MemoryBootstrapStore(),
      runtimeDependencies: {
        outbox,
        puller,
        acceptor: new DurableVaultItemAcceptor(ACCOUNT_ID, stateStore),
      },
    },
  )
  assert.equal(connected.bootstrap.publication, "published")
  assert.deepEqual(events, ["topology"])
  events.length = 0
  const runtime = connected.runtime

  const first = await runtime.syncOnce()
  assert.deepEqual(first.harvest, {
    scanned: 1,
    enqueued: 1,
    alreadyQueued: 0,
    current: 0,
    blockedObjectIds: [],
  })
  assert.equal(first.push.uploaded.length, 1)
  assert.deepEqual(events, ["list", "upload"])

  events.length = 0
  const second = await runtime.syncOnce()
  assert.deepEqual(second.pull, { accepted: 1, cursor: 1 })
  assert.deepEqual(second.harvest, {
    scanned: 1,
    enqueued: 0,
    alreadyQueued: 0,
    current: 1,
    blockedObjectIds: [],
  })
  assert.equal(second.push.uploaded.length, 0)
  assert.deepEqual(events, ["list", "download"])
  assert.equal(stateStore.stateValue.baseline?.object_id, ITEM_ID)
})
