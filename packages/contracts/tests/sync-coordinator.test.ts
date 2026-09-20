import assert from "node:assert/strict"
import test from "node:test"

import { CURRENT_SYNC_COMPATIBILITY } from "../src/sync-compatibility"
import {
  SyncClient,
  SyncClientError,
  type OpaqueMutationV1,
  type OpaqueObjectHeaderV1,
} from "../src/sync-client"
import { DurableSyncCoordinator } from "../src/sync-coordinator"
import { DurableSyncPuller, type SyncCursorStore } from "../src/sync-pull"
import {
  DurableSyncOutbox,
  type QueuedOpaqueMutation,
  type SyncOutboxStore,
} from "../src/sync-queue"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const OTHER_ACCOUNT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const REMOTE_OBJECT_ID = "22222222-2222-4222-8222-222222222222"
const LOCAL_OBJECT_ID = "33333333-3333-4333-8333-333333333333"
const OPERATION_ID = "44444444-4444-4444-8444-444444444444"
const DEVICE_TOKEN = `sfo_dev_v1_${"a".repeat(64)}`
const REMOTE_CIPHERTEXT = new TextEncoder().encode("remote ciphertext")
const LOCAL_CIPHERTEXT = new TextEncoder().encode("local ciphertext")

class MemoryOutboxStore implements SyncOutboxStore {
  entries: QueuedOpaqueMutation[] = []

  async enqueue(_accountId: string, entry: QueuedOpaqueMutation): Promise<boolean> {
    this.entries.push(structuredClone(entry))
    return true
  }

  async list(_accountId: string, limit: number): Promise<QueuedOpaqueMutation[]> {
    return structuredClone(this.entries.slice(0, limit))
  }

  async acknowledge(_accountId: string, operationId: string): Promise<void> {
    this.entries = this.entries.filter(
      (entry) => entry.mutation.operation_id !== operationId,
    )
  }

  async count(): Promise<number> {
    return this.entries.length
  }
}

class MemoryCursorStore implements SyncCursorStore {
  value = 0

  async load(): Promise<number> {
    return this.value
  }

  async advance(
    _accountId: string,
    expectedCursor: number,
    nextCursor: number,
  ): Promise<void> {
    if (this.value !== expectedCursor) {
      throw new SyncClientError("precondition_failed", "cursor changed")
    }
    this.value = nextCursor
  }
}

async function header(
  objectId: string,
  ciphertext: Uint8Array,
): Promise<OpaqueObjectHeaderV1> {
  return {
    format_version: 1,
    protocol_version: 1,
    object_id: objectId,
    class: "item",
    scope: { scope: "account", account_id: ACCOUNT_ID },
    revision: 0,
    payload_version: 1,
    envelope_version: 1,
    ciphertext_size_bytes: ciphertext.byteLength,
    ciphertext_sha256: Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", Uint8Array.from(ciphertext).buffer),
      ),
    ),
    tombstone: false,
  }
}

async function localMutation(): Promise<OpaqueMutationV1> {
  return {
    format_version: 1,
    operation_id: OPERATION_ID,
    object: await header(LOCAL_OBJECT_ID, LOCAL_CIPHERTEXT),
    precondition: { condition: "create_only" },
  }
}

test("coordinator pulls durably before flushing the local outbox", async () => {
  const remoteHeader = await header(REMOTE_OBJECT_ID, REMOTE_CIPHERTEXT)
  const events: string[] = []
  const fetcher: typeof fetch = async (input, init) => {
    const url = new URL(String(input))
    if (url.pathname.endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    if (url.pathname.endsWith("/v1/objects")) {
      events.push("list")
      return Response.json({
        objects: [{ object: remoteHeader, change_seq: 1, etag: '"remote"' }],
        next_change_seq: 1,
      })
    }
    if (url.pathname.endsWith(`/${REMOTE_OBJECT_ID}`)) {
      events.push("download")
      return new Response(REMOTE_CIPHERTEXT, {
        headers: { "content-length": String(REMOTE_CIPHERTEXT.byteLength) },
      })
    }
    events.push("upload")
    const mutation = JSON.parse(
      new Headers(init?.headers).get("x-safeory-mutation") ?? "null",
    ) as OpaqueMutationV1
    return Response.json({
      object: mutation.object,
      change_seq: 2,
      etag: '"local"',
    })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )
  const outboxStore = new MemoryOutboxStore()
  const outbox = new DurableSyncOutbox(ACCOUNT_ID, outboxStore)
  await outbox.enqueue(await localMutation(), LOCAL_CIPHERTEXT, 1)
  const puller = new DurableSyncPuller(ACCOUNT_ID, new MemoryCursorStore())
  const coordinator = new DurableSyncCoordinator(client, outbox, puller)
  const accepted: string[] = []

  const result = await coordinator.syncOnce(async ({ metadata, ciphertext }) => {
    accepted.push(metadata.object.object_id)
    assert.deepEqual(ciphertext, REMOTE_CIPHERTEXT)
  })

  assert.deepEqual(events, ["list", "download", "upload"])
  assert.deepEqual(accepted, [REMOTE_OBJECT_ID])
  assert.deepEqual(result.pull, { accepted: 1, cursor: 1 })
  assert.equal(result.push.uploaded.length, 1)
  assert.equal(result.push.remaining, 0)
})

test("failed cycles do not poison later serialized sync attempts", async () => {
  let fail = true
  const fetcher: typeof fetch = async (input) => {
    const url = new URL(String(input))
    if (url.pathname.endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    if (fail) return new Response(null, { status: 503 })
    return Response.json({ objects: [], next_change_seq: 0 })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )
  const coordinator = new DurableSyncCoordinator(
    client,
    new DurableSyncOutbox(ACCOUNT_ID, new MemoryOutboxStore()),
    new DurableSyncPuller(ACCOUNT_ID, new MemoryCursorStore()),
  )

  await assert.rejects(
    coordinator.syncOnce(async () => assert.fail()),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "request_failed",
  )
  fail = false
  assert.deepEqual(await coordinator.syncOnce(async () => assert.fail()), {
    pull: { accepted: 0, cursor: 0 },
    push: { uploaded: [], remaining: 0 },
  })
})

test("coordinator rejects mixed account durability state", async () => {
  const fetcher: typeof fetch = async () => Response.json(CURRENT_SYNC_COMPATIBILITY)
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )

  assert.throws(
    () =>
      new DurableSyncCoordinator(
        client,
        new DurableSyncOutbox(OTHER_ACCOUNT_ID, new MemoryOutboxStore()),
        new DurableSyncPuller(ACCOUNT_ID, new MemoryCursorStore()),
      ),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_configuration",
  )
})
