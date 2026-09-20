import assert from "node:assert/strict"
import test from "node:test"

import { CURRENT_SYNC_COMPATIBILITY } from "../src/sync-compatibility"
import {
  SyncClient,
  SyncClientError,
  parseOpaqueMutation,
  parseOpaqueObjectHeader,
  parseSyncObjectPage,
  type OpaqueMutationV1,
  type OpaqueObjectHeaderV1,
  type SyncObjectMetadataV1,
} from "../src/sync-client"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const OBJECT_ID = "22222222-2222-4222-8222-222222222222"
const OPERATION_ID = "33333333-3333-4333-8333-333333333333"
const DEVICE_TOKEN = `sfo_dev_v1_${"a".repeat(64)}`
const CIPHERTEXT = new TextEncoder().encode("opaque ciphertext")

async function header(): Promise<OpaqueObjectHeaderV1> {
  return {
    format_version: 1,
    protocol_version: 1,
    object_id: OBJECT_ID,
    class: "item",
    scope: { scope: "account", account_id: ACCOUNT_ID },
    revision: 0,
    payload_version: 10,
    envelope_version: 1,
    ciphertext_size_bytes: CIPHERTEXT.byteLength,
    ciphertext_sha256: Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", Uint8Array.from(CIPHERTEXT).buffer),
      ),
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

function metadata(object: OpaqueObjectHeaderV1): SyncObjectMetadataV1 {
  return {
    object,
    change_seq: 1,
    etag: `"safeory-r0-${"0".repeat(64)}"`,
  }
}

test("opaque contracts reject unknown fields, nil IDs, bad bounds, and stale revisions", async () => {
  const valid = await mutation()
  assert.deepEqual(parseOpaqueMutation(valid), valid)

  assert.throws(
    () => parseOpaqueMutation({ ...valid, future_required_field: true }),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_contract",
  )
  assert.throws(
    () =>
      parseOpaqueObjectHeader({
        ...valid.object,
        object_id: "00000000-0000-0000-0000-000000000000",
      }),
    SyncClientError,
  )
  assert.throws(
    () =>
      parseOpaqueObjectHeader({
        ...valid.object,
        ciphertext_size_bytes: 128 * 1024 * 1024 + 1,
      }),
    SyncClientError,
  )
  assert.throws(
    () =>
      parseOpaqueMutation({
        ...valid,
        object: { ...valid.object, revision: 4 },
        precondition: {
          condition: "match",
          revision: 4,
          ciphertext_sha256: valid.object.ciphertext_sha256,
        },
      }),
    SyncClientError,
  )
})

test("client negotiates first and uploads a body-bound canonical mutation", async () => {
  const expectedMutation = await mutation()
  const expectedMetadata = metadata(expectedMutation.object)
  const requests: Array<{ url: string; init: RequestInit }> = []
  const fetcher: typeof fetch = async (input, init = {}) => {
    requests.push({ url: String(input), init })
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    return Response.json(expectedMetadata, { status: 201 })
  }

  const client = await SyncClient.connect(
    "https://sync.example.test/api",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )
  assert.deepEqual(client.compatibility, {
    protocol_version: 1,
    object_header_version: 1,
    envelope_version: 1,
  })
  assert.deepEqual(await client.putObject(expectedMutation, CIPHERTEXT), expectedMetadata)
  assert.equal(requests.length, 2)
  assert.equal(
    requests[1]?.url,
    `https://sync.example.test/api/v1/objects/${OBJECT_ID}`,
  )
  const headers = requests[1]?.init.headers as Headers
  assert.equal(headers.get("authorization"), `Bearer ${DEVICE_TOKEN}`)
  assert.deepEqual(JSON.parse(headers.get("x-safeory-mutation") ?? ""), expectedMutation)
  assert.deepEqual(
    new Uint8Array(requests[1]?.init.body as ArrayBuffer),
    CIPHERTEXT,
  )
})

test("client verifies downloaded ciphertext and rejects digest substitution", async () => {
  const expected = await header()
  let tampered = false
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    const body = tampered ? new TextEncoder().encode("opaque ciphertexu") : CIPHERTEXT
    return new Response(body, {
      headers: { "content-length": String(body.byteLength) },
    })
  }
  const client = await SyncClient.connect(
    "http://127.0.0.1:8081",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )
  assert.deepEqual(await client.getObject(expected), CIPHERTEXT)
  tampered = true
  await assert.rejects(
    client.getObject(expected),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "ciphertext_mismatch",
  )
})

test("client bounds ordered pages and maps idempotency conflicts", async () => {
  const expectedMutation = await mutation()
  const expectedMetadata = metadata(expectedMutation.object)
  let conflict = false
  let crossAccount = false
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    if (conflict) return new Response(null, { status: 409 })
    if (crossAccount) {
      return Response.json({
        objects: [
          {
            ...expectedMetadata,
            object: {
              ...expectedMetadata.object,
              scope: {
                scope: "account",
                account_id: "44444444-4444-4444-8444-444444444444",
              },
            },
          },
        ],
        next_change_seq: 1,
      })
    }
    return Response.json({ objects: [expectedMetadata], next_change_seq: 1 })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )
  assert.deepEqual(await client.listObjects(), {
    objects: [expectedMetadata],
    next_change_seq: 1,
  })
  assert.throws(
    () =>
      parseSyncObjectPage({
        objects: [
          { ...expectedMetadata, change_seq: 2 },
          { ...expectedMetadata, change_seq: 1 },
        ],
        next_change_seq: 2,
      }),
    SyncClientError,
  )

  crossAccount = true
  await assert.rejects(
    client.listObjects(),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_contract",
  )
  crossAccount = false

  conflict = true
  await assert.rejects(
    client.putObject(expectedMutation, CIPHERTEXT),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "operation_conflict",
  )
})

test("device credentials cannot be sent to insecure remote HTTP origins", async () => {
  await assert.rejects(
    SyncClient.connect("http://sync.example.test", ACCOUNT_ID, DEVICE_TOKEN),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_configuration",
  )
  await assert.rejects(
    SyncClient.connect(
      "https://sync.example.test",
      ACCOUNT_ID,
      "registration-secret",
    ),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_configuration",
  )
})
