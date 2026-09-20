import assert from "node:assert/strict"
import test from "node:test"

import { CURRENT_SYNC_COMPATIBILITY } from "../src/sync-compatibility"
import {
  SyncClient,
  SyncClientError,
  generateDeviceToken,
  parseOpaqueMutation,
  parseOpaqueObjectHeader,
  parseSyncObjectPage,
  type OpaqueMutationV1,
  type OpaqueObjectHeaderV1,
  type SyncObjectMetadataV1,
} from "../src/sync-client"
import type { HouseholdTopologyV1 } from "../src/sync-domain"
import type { DeviceRegistrationV1 } from "../src/device-keys"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const OBJECT_ID = "22222222-2222-4222-8222-222222222222"
const OPERATION_ID = "33333333-3333-4333-8333-333333333333"
const DEVICE_TOKEN = `sfo_dev_v1_${"a".repeat(64)}`
const CIPHERTEXT = new TextEncoder().encode("opaque ciphertext")
const HOUSEHOLD_ID = "44444444-4444-4444-8444-444444444444"
const MEMBERSHIP_ID = "55555555-5555-4555-8555-555555555555"
const DEVICE_ID = "66666666-6666-4666-8666-666666666666"
const SECOND_DEVICE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
const ENROLLMENT_REQUEST_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
const PENDING_DEVICE_TOKEN = `sfo_dev_v1_${"b".repeat(64)}`
const SPACE_ID = "77777777-7777-4777-8777-777777777777"

function deviceRegistration(deviceId = DEVICE_ID): DeviceRegistrationV1 {
  return {
    format_version: 1,
    device_id: deviceId,
    encryption_public_key_hex: "11".repeat(32),
    signing_public_key_hex: "22".repeat(32),
  }
}

test("device bearer generation uses canonical independent 256-bit material", () => {
  const first = generateDeviceToken()
  const second = generateDeviceToken()
  assert.match(first, /^sfo_dev_v1_[0-9a-f]{64}$/)
  assert.match(second, /^sfo_dev_v1_[0-9a-f]{64}$/)
  assert.notEqual(first, second)
})

function topology(): HouseholdTopologyV1 {
  return {
    format_version: 1,
    accounts: [{
      format_version: 1,
      account_id: ACCOUNT_ID,
      household_ids: [HOUSEHOLD_ID],
      device_ids: [DEVICE_ID],
    }],
    household: {
      format_version: 1,
      household_id: HOUSEHOLD_ID,
      encrypted_profile_object_id: "88888888-8888-4888-8888-888888888888",
      membership_ids: [MEMBERSHIP_ID],
      space_ids: [SPACE_ID],
      revision: 0,
    },
    memberships: [{
      format_version: 1,
      membership_id: MEMBERSHIP_ID,
      account_id: ACCOUNT_ID,
      household_id: HOUSEHOLD_ID,
      role: "owner",
      state: "active",
      revision: 0,
    }],
    spaces: [{
      format_version: 1,
      space_id: SPACE_ID,
      household_id: HOUSEHOLD_ID,
      kind: "private",
      encrypted_manifest_object_id: "99999999-9999-4999-8999-999999999999",
      key_generation: 1,
      revision: 0,
    }],
    space_members: [{
      format_version: 1,
      space_id: SPACE_ID,
      membership_id: MEMBERSHIP_ID,
      access: "manage",
      envelope_object_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      device_id: DEVICE_ID,
      key_generation: 1,
      revision: 0,
    }],
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

test("client bootstrap binds the client-generated ID and both device public keys", async () => {
  const requests: Array<{ url: string; init: RequestInit }> = []
  const fetcher: typeof fetch = async (input, init = {}) => {
    requests.push({ url: String(input), init })
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    return Response.json({
      account_id: ACCOUNT_ID,
      device_id: DEVICE_ID,
      device_token: DEVICE_TOKEN,
    }, { status: 201 })
  }

  const credentials = await SyncClient.createAccount(
    "https://sync.example.test",
    "r".repeat(32),
    deviceRegistration(),
    { fetcher },
  )

  assert.deepEqual(credentials, {
    account_id: ACCOUNT_ID,
    device_id: DEVICE_ID,
    device_token: DEVICE_TOKEN,
  })
  assert.equal(requests[1]?.url, "https://sync.example.test/v1/accounts")
  assert.equal(
    new Headers(requests[1]?.init.headers).get("authorization"),
    `Bearer ${"r".repeat(32)}`,
  )
  assert.deepEqual(JSON.parse(String(requests[1]?.init.body)), {
    device_id: DEVICE_ID,
    encryption_public_key: "11".repeat(32),
    signing_public_key: "22".repeat(32),
  })
})

test("authenticated client creates and revokes a bound device", async () => {
  const methods: string[] = []
  const fetcher: typeof fetch = async (input, init = {}) => {
    const url = String(input)
    if (url.endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    methods.push(`${init.method} ${new URL(url).pathname}`)
    if (init.method === "DELETE") return new Response(null, { status: 204 })
    return Response.json({
      account_id: ACCOUNT_ID,
      device_id: SECOND_DEVICE_ID,
      device_token: `sfo_dev_v1_${"b".repeat(64)}`,
    }, { status: 201 })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )

  const credentials = await client.createDevice(deviceRegistration(SECOND_DEVICE_ID))
  await client.revokeDevice(SECOND_DEVICE_ID)

  assert.equal(credentials.device_id, SECOND_DEVICE_ID)
  assert.deepEqual(methods, [
    "POST /v1/devices",
    `DELETE /v1/devices/${SECOND_DEVICE_ID}`,
  ])
})

test("approved-device enrollment prepares, activates, and cancels through bounded contracts", async () => {
  const requests: Array<{ url: string; init: RequestInit }> = []
  const fetcher: typeof fetch = async (input, init = {}) => {
    const url = String(input)
    if (url.endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    requests.push({ url, init })
    if (init.method === "DELETE") return new Response(null, { status: 204 })
    return Response.json({
      account_id: ACCOUNT_ID,
      request_id: ENROLLMENT_REQUEST_ID,
      device_id: SECOND_DEVICE_ID,
      expires_at_unix_seconds: 2_000_000_000,
      status: url.endsWith("/activate") ? "active" : "pending",
    }, { status: url.endsWith("/activate") ? 200 : 201 })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher, deviceId: DEVICE_ID },
  )

  const pending = await client.prepareDeviceEnrollment(
    ENROLLMENT_REQUEST_ID,
    deviceRegistration(SECOND_DEVICE_ID),
    PENDING_DEVICE_TOKEN,
  )
  const credentials = await SyncClient.activateDeviceEnrollment(
    "https://sync.example.test",
    ENROLLMENT_REQUEST_ID,
    SECOND_DEVICE_ID,
    PENDING_DEVICE_TOKEN,
    { fetcher },
  )
  await client.cancelDeviceEnrollment(ENROLLMENT_REQUEST_ID)

  assert.equal(pending.status, "pending")
  assert.deepEqual(credentials, {
    account_id: ACCOUNT_ID,
    device_id: SECOND_DEVICE_ID,
    device_token: PENDING_DEVICE_TOKEN,
  })
  assert.deepEqual(
    JSON.parse(String(requests[0]?.init.body)),
    {
      request_id: ENROLLMENT_REQUEST_ID,
      device_id: SECOND_DEVICE_ID,
      encryption_public_key: "11".repeat(32),
      signing_public_key: "22".repeat(32),
      device_token: PENDING_DEVICE_TOKEN,
    },
  )
  assert.equal(
    new Headers(requests[1]?.init.headers).get("authorization"),
    `Bearer ${PENDING_DEVICE_TOKEN}`,
  )
  assert.equal(requests[2]?.init.method, "DELETE")
})

test("device enrollment rejects substituted identity and maps terminal state", async () => {
  let unavailable = false
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    if (unavailable) {
      return Response.json({ error: "enrollment_unavailable" }, { status: 410 })
    }
    return Response.json({
      account_id: ACCOUNT_ID,
      request_id: ENROLLMENT_REQUEST_ID,
      device_id: DEVICE_ID,
      expires_at_unix_seconds: 2_000_000_000,
      status: "active",
    })
  }

  await assert.rejects(
    SyncClient.activateDeviceEnrollment(
      "https://sync.example.test",
      ENROLLMENT_REQUEST_ID,
      SECOND_DEVICE_ID,
      PENDING_DEVICE_TOKEN,
      { fetcher },
    ),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_response",
  )
  unavailable = true
  await assert.rejects(
    SyncClient.activateDeviceEnrollment(
      "https://sync.example.test",
      ENROLLMENT_REQUEST_ID,
      SECOND_DEVICE_ID,
      PENDING_DEVICE_TOKEN,
      { fetcher },
    ),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "enrollment_unavailable",
  )
})

test("client validates the bounded active-device inventory", async () => {
  let duplicate = false
  let currentDeviceId = DEVICE_ID
  const entry = {
    device_id: DEVICE_ID,
    encryption_public_key: "11".repeat(32),
    signing_public_key: "22".repeat(32),
  }
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    const currentEntry = { ...entry, device_id: currentDeviceId }
    return Response.json({
      current_device_id: currentDeviceId,
      devices: duplicate ? [currentEntry, currentEntry] : [currentEntry],
    })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher, deviceId: DEVICE_ID },
  )

  assert.deepEqual(await client.listDevices(), {
    current_device_id: DEVICE_ID,
    devices: [entry],
  })
  duplicate = true
  await assert.rejects(
    client.listDevices(),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_response",
  )
  duplicate = false
  currentDeviceId = SECOND_DEVICE_ID
  await assert.rejects(
    client.listDevices(),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_response",
  )
})

test("device enrollment maps the active-device limit", async () => {
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    return new Response(null, { status: 422 })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )

  await assert.rejects(
    client.createDevice(deviceRegistration(SECOND_DEVICE_ID)),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "limit_reached",
  )
})

test("device enrollment reports a client-generated identifier collision", async () => {
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    return Response.json(
      { error: "device_identifier_conflict" },
      { status: 409 },
    )
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )

  await assert.rejects(
    client.createDevice(deviceRegistration(SECOND_DEVICE_ID)),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "identifier_conflict",
  )
})

test("device revocation preserves the final active device", async () => {
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    return Response.json({ error: "last_active_device" }, { status: 409 })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )

  await assert.rejects(
    client.revokeDevice(DEVICE_ID),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "last_active_device",
  )
})

test("device registration rejects substituted server identity", async () => {
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    return Response.json({
      account_id: ACCOUNT_ID,
      device_id: SECOND_DEVICE_ID,
      device_token: DEVICE_TOKEN,
    })
  }

  await assert.rejects(
    SyncClient.createAccount(
      "https://sync.example.test",
      "r".repeat(32),
      deviceRegistration(),
      { fetcher },
    ),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_response",
  )
})

test("client publishes and retrieves canonical household topology", async () => {
  const expected = topology()
  const requests: Array<{ url: string; init: RequestInit }> = []
  const fetcher: typeof fetch = async (input, init = {}) => {
    requests.push({ url: String(input), init })
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    if (init.method === "PUT") return new Response(null, { status: 201 })
    return Response.json(expected)
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )

  await client.putHouseholdTopology(expected)
  assert.deepEqual(await client.getHouseholdTopology(HOUSEHOLD_ID), expected)
  assert.equal(
    requests[1]?.url,
    `https://sync.example.test/v1/households/${HOUSEHOLD_ID}/topology`,
  )
  assert.deepEqual(JSON.parse(String(requests[1]?.init.body)), expected)
})

test("topology client rejects cross-account responses and maps forbidden access", async () => {
  const expected = topology()
  let forbidden = false
  const fetcher: typeof fetch = async (input) => {
    if (String(input).endsWith("/v1/compatibility")) {
      return Response.json(CURRENT_SYNC_COMPATIBILITY)
    }
    if (forbidden) return new Response(null, { status: 403 })
    return Response.json({
      ...expected,
      accounts: [{
        ...expected.accounts[0],
        account_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      }],
      memberships: [{
        ...expected.memberships[0],
        account_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      }],
    })
  }
  const client = await SyncClient.connect(
    "https://sync.example.test",
    ACCOUNT_ID,
    DEVICE_TOKEN,
    { fetcher },
  )

  await assert.rejects(
    client.getHouseholdTopology(HOUSEHOLD_ID),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_contract",
  )
  forbidden = true
  await assert.rejects(
    client.getHouseholdTopology(HOUSEHOLD_ID),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "forbidden",
  )
})
