import assert from "node:assert/strict"
import test from "node:test"

import { CURRENT_SYNC_COMPATIBILITY } from "../src/sync-compatibility"
import { SyncClient, SyncClientError } from "../src/sync-client"
import {
  decodePulledAccountBootstrap,
  fetchAccountBootstrap,
  parseRemoteAccountRootWrap,
  prepareAccountBootstrapMutation,
} from "../src/sync-account-bootstrap"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const OTHER_ACCOUNT_ID = "22222222-2222-4222-8222-222222222222"
const FIRST_OPERATION_ID = "33333333-3333-4333-8333-333333333333"
const SECOND_OPERATION_ID = "44444444-4444-4444-8444-444444444444"
const DEVICE_TOKEN = `sfo_dev_v1_${"a".repeat(64)}`

function rootWrap(accountId = ACCOUNT_ID): Record<string, unknown> {
  return {
    format_version: 1,
    algorithm: "argon2id-v19+hkdf-sha256+xchacha20poly1305",
    account_id: accountId,
    argon2_memory_kib: 65_536,
    argon2_iterations: 3,
    argon2_parallelism: 1,
    passphrase_salt: Array.from({ length: 16 }, (_, index) => index),
    nonce: Array.from({ length: 24 }, (_, index) => index + 16),
    ciphertext: Array.from({ length: 48 }, (_, index) => 255 - index),
  }
}

test("account bootstrap prepares a stable account-scoped CAS mutation", async () => {
  const wrappedJson = JSON.stringify(rootWrap())
  const first = await prepareAccountBootstrapMutation(
    wrappedJson,
    ACCOUNT_ID,
    FIRST_OPERATION_ID,
    null,
  )
  assert.equal(first.mutation.object.object_id, ACCOUNT_ID)
  assert.equal(first.mutation.object.class, "account_bootstrap")
  assert.deepEqual(first.mutation.object.scope, {
    scope: "account",
    account_id: ACCOUNT_ID,
  })
  assert.equal(first.mutation.object.revision, 1)
  assert.deepEqual(first.mutation.precondition, { condition: "create_only" })
  assert.equal(new TextDecoder().decode(first.ciphertext), wrappedJson)

  const rotated = await prepareAccountBootstrapMutation(
    JSON.stringify({ ...rootWrap(), nonce: Array(24).fill(9) }),
    ACCOUNT_ID,
    SECOND_OPERATION_ID,
    first.mutation.object,
  )
  assert.equal(rotated.mutation.object.revision, 2)
  assert.deepEqual(rotated.mutation.precondition, {
    condition: "match",
    revision: 1,
    ciphertext_sha256: first.mutation.object.ciphertext_sha256,
  })
})

test("account bootstrap rejects malformed envelopes and substituted CAS context", async () => {
  assert.throws(
    () => parseRemoteAccountRootWrap({ ...rootWrap(), future_field: true }),
    SyncClientError,
  )
  assert.throws(
    () => parseRemoteAccountRootWrap({ ...rootWrap(), argon2_memory_kib: 600_000 }),
    SyncClientError,
  )
  await assert.rejects(
    prepareAccountBootstrapMutation(
      JSON.stringify(rootWrap(OTHER_ACCOUNT_ID)),
      ACCOUNT_ID,
      FIRST_OPERATION_ID,
      null,
    ),
    /different account/,
  )

  const first = await prepareAccountBootstrapMutation(
    JSON.stringify(rootWrap()),
    ACCOUNT_ID,
    FIRST_OPERATION_ID,
    null,
  )
  await assert.rejects(
    prepareAccountBootstrapMutation(
      JSON.stringify(rootWrap()),
      ACCOUNT_ID,
      SECOND_OPERATION_ID,
      {
        ...first.mutation.object,
        object_id: OTHER_ACCOUNT_ID,
      },
    ),
    SyncClientError,
  )
})

test("downloaded account bootstrap binds metadata, bytes, and envelope account", async () => {
  const prepared = await prepareAccountBootstrapMutation(
    JSON.stringify(rootWrap()),
    ACCOUNT_ID,
    FIRST_OPERATION_ID,
    null,
  )
  const metadata = {
    object: prepared.mutation.object,
    change_seq: 7,
    etag: '"bootstrap-1"',
  }
  const decoded = await decodePulledAccountBootstrap(metadata, prepared.ciphertext)
  assert.deepEqual(decoded.wrappedRoot, rootWrap())
  assert.equal(decoded.wrappedJson, new TextDecoder().decode(prepared.ciphertext))

  const substituted = new TextEncoder().encode(JSON.stringify(rootWrap(OTHER_ACCOUNT_ID)))
  const substitutedDigest = Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", substituted.buffer)),
  )
  await assert.rejects(
    decodePulledAccountBootstrap(
      {
        ...metadata,
        object: {
          ...metadata.object,
          ciphertext_size_bytes: substituted.byteLength,
          ciphertext_sha256: substitutedDigest,
        },
      },
      substituted,
    ),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_response",
  )
})

test("fresh device fetches bootstrap metadata directly before verified ciphertext", async () => {
  const prepared = await prepareAccountBootstrapMutation(
    JSON.stringify(rootWrap()),
    ACCOUNT_ID,
    FIRST_OPERATION_ID,
    null,
  )
  const metadata = {
    object: prepared.mutation.object,
    change_seq: 9,
    etag: '"bootstrap-1"',
  }
  const requests: string[] = []
  const fetcher: typeof fetch = async (input) => {
    const url = new URL(String(input))
    requests.push(url.pathname)
    if (url.pathname.endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    if (url.pathname.endsWith(`/${ACCOUNT_ID}/metadata`)) {
      return Response.json(metadata)
    }
    if (url.pathname.endsWith(`/${ACCOUNT_ID}`)) {
      return new Response(prepared.ciphertext.slice().buffer, {
        headers: { "content-length": String(prepared.ciphertext.byteLength) },
      })
    }
    return new Response(null, { status: 404 })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )

  const fetched = await fetchAccountBootstrap(client)
  assert.equal(fetched.metadata.object.object_id, ACCOUNT_ID)
  assert.deepEqual(requests, [
    "/v1/compatibility",
    `/v1/objects/${ACCOUNT_ID}/metadata`,
    `/v1/objects/${ACCOUNT_ID}`,
  ])
})
