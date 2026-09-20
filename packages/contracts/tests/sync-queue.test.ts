import assert from "node:assert/strict"
import test from "node:test"

import { CURRENT_SYNC_COMPATIBILITY } from "../src/sync-compatibility"
import {
  SyncClient,
  SyncClientError,
  type OpaqueMutationV1,
  type OpaqueObjectHeaderV1,
} from "../src/sync-client"
import {
  DurableSyncOutbox,
  type QueuedOpaqueMutation,
  type SyncOutboxStore,
} from "../src/sync-queue"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const OBJECT_ID = "22222222-2222-4222-8222-222222222222"
const OPERATION_ID = "33333333-3333-4333-8333-333333333333"
const DEVICE_TOKEN = `sfo_dev_v1_${"a".repeat(64)}`
const CIPHERTEXT = new TextEncoder().encode("queued opaque ciphertext")

class MemoryOutboxStore implements SyncOutboxStore {
  entries: QueuedOpaqueMutation[] = []
  failAcknowledgement = false

  async enqueue(_accountId: string, entry: QueuedOpaqueMutation): Promise<boolean> {
    const existing = this.entries.find(
      (candidate) => candidate.mutation.operation_id === entry.mutation.operation_id,
    )
    if (existing !== undefined) {
      if (
        JSON.stringify(existing.mutation) !== JSON.stringify(entry.mutation) ||
        !bytesEqual(existing.ciphertext, entry.ciphertext)
      ) {
        throw new SyncClientError(
          "operation_conflict",
          "The operation ID is already queued with different input.",
        )
      }
      return false
    }
    this.entries.push(structuredClone(entry))
    this.entries.sort(
      (left, right) =>
        left.queued_at_ms - right.queued_at_ms ||
        left.mutation.operation_id.localeCompare(right.mutation.operation_id),
    )
    return true
  }

  async list(_accountId: string, limit: number): Promise<QueuedOpaqueMutation[]> {
    return structuredClone(this.entries.slice(0, limit))
  }

  async acknowledge(_accountId: string, operationId: string): Promise<void> {
    if (this.failAcknowledgement) throw new Error("local disk unavailable")
    this.entries = this.entries.filter(
      (entry) => entry.mutation.operation_id !== operationId,
    )
  }

  async count(): Promise<number> {
    return this.entries.length
  }
}

async function header(): Promise<OpaqueObjectHeaderV1> {
  return {
    format_version: 1,
    protocol_version: 1,
    object_id: OBJECT_ID,
    class: "item",
    scope: { scope: "account", account_id: ACCOUNT_ID },
    revision: 0,
    payload_version: 1,
    envelope_version: 1,
    ciphertext_size_bytes: CIPHERTEXT.byteLength,
    ciphertext_sha256: Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-256", CIPHERTEXT)),
    ),
    tombstone: false,
  }
}

async function mutation(): Promise<OpaqueMutationV1> {
  return {
    format_version: 1,
    operation_id: OPERATION_ID,
    object: await header(),
    precondition: { condition: "create_only" },
  }
}

async function client(
  onUpload: (mutation: OpaqueMutationV1) => Response,
): Promise<SyncClient> {
  const fetcher: typeof fetch = async (input, init) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    return onUpload(
      JSON.parse(new Headers(init?.headers).get("x-safeory-mutation") ?? "null") as
        OpaqueMutationV1,
    )
  }
  return SyncClient.connect("https://sync.example.test", ACCOUNT_ID, DEVICE_TOKEN, {
    fetcher,
  })
}

function metadata(mutationValue: OpaqueMutationV1): object {
  return {
    object: mutationValue.object,
    change_seq: 1,
    etag: `"safeory-r0-${"0".repeat(64)}"`,
  }
}

test("outbox validates and copies ciphertext before durable enqueue", async () => {
  const store = new MemoryOutboxStore()
  const outbox = new DurableSyncOutbox(ACCOUNT_ID, store)
  const candidate = await mutation()
  const bytes = Uint8Array.from(CIPHERTEXT)

  assert.equal(await outbox.enqueue(candidate, bytes, 10), true)
  bytes.fill(0)
  assert.deepEqual(store.entries[0]?.ciphertext, CIPHERTEXT)
  assert.equal(await outbox.enqueue(candidate, CIPHERTEXT, 20), false)
  assert.equal(await outbox.count(), 1)

  await assert.rejects(
    outbox.enqueue(candidate, Uint8Array.of(1), 30),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "ciphertext_mismatch",
  )
})

test("flush acknowledges only after a matching server response", async () => {
  const store = new MemoryOutboxStore()
  const outbox = new DurableSyncOutbox(ACCOUNT_ID, store)
  const candidate = await mutation()
  await outbox.enqueue(candidate, CIPHERTEXT, 10)

  const connected = await client((uploaded) => Response.json(metadata(uploaded)))
  const result = await outbox.flush(connected)

  assert.equal(result.uploaded.length, 1)
  assert.equal(result.remaining, 0)
})

test("failed requests and failed local acknowledgements remain retryable", async () => {
  const store = new MemoryOutboxStore()
  const outbox = new DurableSyncOutbox(ACCOUNT_ID, store)
  const candidate = await mutation()
  await outbox.enqueue(candidate, CIPHERTEXT, 10)

  const unavailable = await client(() => new Response(null, { status: 503 }))
  await assert.rejects(
    outbox.flush(unavailable),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "request_failed",
  )
  assert.equal(await outbox.count(), 1)

  store.failAcknowledgement = true
  const accepted = await client((uploaded) => Response.json(metadata(uploaded)))
  await assert.rejects(outbox.flush(accepted), /local disk unavailable/)
  assert.equal(await outbox.count(), 1)

  store.failAcknowledgement = false
  assert.equal((await outbox.flush(accepted)).remaining, 0)
})

test("mismatched upload metadata never removes the queued operation", async () => {
  const store = new MemoryOutboxStore()
  const outbox = new DurableSyncOutbox(ACCOUNT_ID, store)
  const candidate = await mutation()
  await outbox.enqueue(candidate, CIPHERTEXT, 10)
  const connected = await client((uploaded) =>
    Response.json({
      ...metadata(uploaded),
      object: { ...uploaded.object, revision: 1 },
    }),
  )

  await assert.rejects(
    outbox.flush(connected),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_response",
  )
  assert.equal(await outbox.count(), 1)
})

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    left.every((byte, index) => byte === right[index])
  )
}
