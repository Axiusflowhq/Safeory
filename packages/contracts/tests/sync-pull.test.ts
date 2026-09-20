import assert from "node:assert/strict"
import test from "node:test"

import { CURRENT_SYNC_COMPATIBILITY } from "../src/sync-compatibility"
import {
  SyncClient,
  SyncClientError,
  type OpaqueObjectHeaderV1,
  type SyncObjectMetadataV1,
} from "../src/sync-client"
import {
  DurableSyncPuller,
  type SyncCursorStore,
} from "../src/sync-pull"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const DEVICE_TOKEN = `sfo_dev_v1_${"a".repeat(64)}`
const FIRST_ID = "22222222-2222-4222-8222-222222222222"
const SECOND_ID = "33333333-3333-4333-8333-333333333333"
const FIRST_CIPHERTEXT = new TextEncoder().encode("first opaque ciphertext")
const SECOND_CIPHERTEXT = new TextEncoder().encode("second opaque ciphertext")

class MemoryCursorStore implements SyncCursorStore {
  value = 0
  failAdvance = false

  async load(): Promise<number> {
    return this.value
  }

  async advance(
    _accountId: string,
    expectedCursor: number,
    nextCursor: number,
  ): Promise<void> {
    if (this.failAdvance) throw new Error("cursor disk unavailable")
    if (this.value !== expectedCursor) {
      throw new SyncClientError("precondition_failed", "cursor changed")
    }
    this.value = nextCursor
  }
}

async function objectHeader(
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
        await crypto.subtle.digest(
          "SHA-256",
          Uint8Array.from(ciphertext).buffer,
        ),
      ),
    ),
    tombstone: false,
  }
}

async function metadataPage(): Promise<{
  metadata: SyncObjectMetadataV1[]
  ciphertext: Map<string, Uint8Array>
}> {
  const first = await objectHeader(FIRST_ID, FIRST_CIPHERTEXT)
  const second = await objectHeader(SECOND_ID, SECOND_CIPHERTEXT)
  return {
    metadata: [
      { object: first, change_seq: 1, etag: '"first"' },
      { object: second, change_seq: 2, etag: '"second"' },
    ],
    ciphertext: new Map([
      [FIRST_ID, FIRST_CIPHERTEXT],
      [SECOND_ID, SECOND_CIPHERTEXT],
    ]),
  }
}

async function connectedClient(
  metadata: SyncObjectMetadataV1[],
  ciphertext: Map<string, Uint8Array>,
): Promise<SyncClient> {
  const fetcher: typeof fetch = async (input) => {
    const url = new URL(String(input))
    if (url.pathname.endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    if (url.pathname.endsWith("/v1/objects")) {
      const after = Number(url.searchParams.get("after"))
      const objects = metadata.filter((object) => object.change_seq > after)
      return Response.json({
        objects,
        next_change_seq: objects.at(-1)?.change_seq ?? after,
      })
    }
    const objectId = url.pathname.split("/").at(-1) ?? ""
    const bytes = ciphertext.get(objectId)
    return bytes === undefined
      ? new Response(null, { status: 404 })
      : new Response(Uint8Array.from(bytes).buffer, {
          headers: { "content-length": String(bytes.byteLength) },
        })
  }
  return SyncClient.connect("https://sync.example.test", ACCOUNT_ID, DEVICE_TOKEN, {
    fetcher,
  })
}

test("pull advances the durable cursor only after verified acceptance", async () => {
  const page = await metadataPage()
  const client = await connectedClient(page.metadata, page.ciphertext)
  const store = new MemoryCursorStore()
  const puller = new DurableSyncPuller(ACCOUNT_ID, store)
  const accepted: string[] = []

  const result = await puller.pullPage(client, async ({ metadata, ciphertext }) => {
    accepted.push(metadata.object.object_id)
    assert.deepEqual(ciphertext, page.ciphertext.get(metadata.object.object_id))
  })

  assert.deepEqual(result, { accepted: 2, cursor: 2 })
  assert.deepEqual(accepted, [FIRST_ID, SECOND_ID])
  assert.equal(await puller.cursor(), 2)
  assert.deepEqual(await puller.pullPage(client, async () => assert.fail()), {
    accepted: 0,
    cursor: 2,
  })
})

test("acceptance failure checkpoints only earlier durable objects", async () => {
  const page = await metadataPage()
  const client = await connectedClient(page.metadata, page.ciphertext)
  const store = new MemoryCursorStore()
  const puller = new DurableSyncPuller(ACCOUNT_ID, store)
  let calls = 0

  await assert.rejects(
    puller.pullPage(client, async () => {
      calls += 1
      if (calls === 2) throw new Error("local object write failed")
    }),
    /local object write failed/,
  )
  assert.equal(store.value, 1)

  const retried: string[] = []
  assert.deepEqual(
    await puller.pullPage(client, async ({ metadata }) => {
      retried.push(metadata.object.object_id)
    }),
    { accepted: 1, cursor: 2 },
  )
  assert.deepEqual(retried, [SECOND_ID])
})

test("cursor persistence failure never reports the object as checkpointed", async () => {
  const page = await metadataPage()
  const client = await connectedClient(page.metadata.slice(0, 1), page.ciphertext)
  const store = new MemoryCursorStore()
  store.failAdvance = true
  const puller = new DurableSyncPuller(ACCOUNT_ID, store)
  let accepted = 0

  await assert.rejects(
    puller.pullPage(client, async () => {
      accepted += 1
    }),
    /cursor disk unavailable/,
  )
  assert.equal(accepted, 1)
  assert.equal(store.value, 0)
})

test("list rejects cursor rollback and repeated acknowledged changes", async () => {
  const header = await objectHeader(FIRST_ID, FIRST_CIPHERTEXT)
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    return Response.json({
      objects: [{ object: header, change_seq: 5, etag: '"stale"' }],
      next_change_seq: 5,
    })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )

  await assert.rejects(
    client.listObjects({ after: 5 }),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_response",
  )
})

test("pull checkpoints gaps created by server-side authorization filtering", async () => {
  const fetcher: typeof fetch = async (input) => {
    const url = new URL(String(input))
    if (url.pathname.endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    return Response.json({ objects: [], next_change_seq: 7 })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )
  const store = new MemoryCursorStore()
  const puller = new DurableSyncPuller(ACCOUNT_ID, store)

  assert.deepEqual(await puller.pullPage(client, async () => assert.fail()), {
    accepted: 0,
    cursor: 7,
  })
  assert.equal(store.value, 7)
})
