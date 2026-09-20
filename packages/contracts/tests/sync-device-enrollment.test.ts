import assert from "node:assert/strict"
import test from "node:test"

import type { BrowserDeviceKeyStore } from "../src/device-keys"
import {
  BrowserDeviceEnrollmentCoordinator,
  type DeviceEnrollmentApprovalStorageBackend,
  type StoredDeviceEnrollmentApprovalV1,
  type StoredDeviceEnrollmentJoinRequestV1,
} from "../src/sync-device-enrollment"
import { CURRENT_SYNC_COMPATIBILITY } from "../src/sync-compatibility"
import { SyncClient, SyncClientError } from "../src/sync-client"
import type { BrowserSyncCredentialStore } from "../src/sync-credentials"

const API = "https://sync.example.test"
const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const APPROVER_ID = "22222222-2222-4222-8222-222222222222"
const JOINING_ID = "33333333-3333-4333-8333-333333333333"
const REQUEST_ID = "44444444-4444-4444-8444-444444444444"
const APPROVER_ENCRYPTION = Array(32).fill(51) as number[]
const APPROVER_SIGNING = Array(32).fill(68) as number[]
const JOINING_ENCRYPTION = Array(32).fill(17) as number[]
const JOINING_SIGNING = Array(32).fill(34) as number[]
const TOKEN = `sfo_dev_v1_${"a".repeat(64)}`

function requestJson(): string {
  return JSON.stringify({
    format_version: 1,
    request_id: REQUEST_ID,
    account_id: ACCOUNT_ID,
    device_id: JOINING_ID,
    encryption_public: JOINING_ENCRYPTION,
    signing_public: JOINING_SIGNING,
    challenge: Array(32).fill(85),
    signature: Array(64).fill(102),
  })
}

function grantJson(): string {
  return JSON.stringify({
    format_version: 1,
    algorithm: "x25519-hkdf-sha256+xchacha20poly1305+ed25519",
    request_id: REQUEST_ID,
    account_id: ACCOUNT_ID,
    joining_device_id: JOINING_ID,
    joining_encryption_public: JOINING_ENCRYPTION,
    joining_signing_public: JOINING_SIGNING,
    approver_device_id: APPROVER_ID,
    approver_encryption_public: APPROVER_ENCRYPTION,
    approver_signing_public: APPROVER_SIGNING,
    ephemeral_public: Array(32).fill(119),
    nonce: Array(24).fill(136),
    ciphertext: [1, 2, 3],
    signature: Array(64).fill(153),
  })
}

class MemoryApprovalStorage implements DeviceEnrollmentApprovalStorageBackend {
  readonly records = new Map<string, StoredDeviceEnrollmentApprovalV1>()
  readonly joinRequests = new Map<string, StoredDeviceEnrollmentJoinRequestV1>()
  readonly wrappingKey = crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  ) as Promise<CryptoKey>

  getOrCreateWrappingKey(): Promise<CryptoKey> { return this.wrappingKey }
  async addDraft(record: StoredDeviceEnrollmentApprovalV1): Promise<void> {
    if (this.records.has(record.key)) throw new Error("draft already exists")
    this.records.set(record.key, record)
  }
  async getDraft(key: string): Promise<StoredDeviceEnrollmentApprovalV1 | null> {
    return this.records.get(key) ?? null
  }
  async listDrafts(): Promise<StoredDeviceEnrollmentApprovalV1[]> {
    return [...this.records.values()]
  }
  async deleteDraft(key: string): Promise<void> { this.records.delete(key) }
  async addJoinRequest(record: StoredDeviceEnrollmentJoinRequestV1): Promise<void> {
    if (this.joinRequests.has(record.key)) throw new Error("join request already exists")
    this.joinRequests.set(record.key, record)
  }
  async getJoinRequest(key: string): Promise<StoredDeviceEnrollmentJoinRequestV1 | null> {
    return this.joinRequests.get(key) ?? null
  }
  async listJoinRequests(): Promise<StoredDeviceEnrollmentJoinRequestV1[]> {
    return [...this.joinRequests.values()]
  }
  async deleteJoinRequest(key: string): Promise<void> { this.joinRequests.delete(key) }
}

function fakeDeviceKeys(openedPackage?: Uint8Array): BrowserDeviceKeyStore {
  return {
    async createDeviceEnrollmentRequest(): Promise<string> {
      return requestJson()
    },
    async sealDeviceEnrollmentGrant(
      _approverDeviceId: string,
      _requestJson: string,
      credentialPackage: Uint8Array,
    ): Promise<string> {
      openedPackage = Uint8Array.from(credentialPackage)
      return grantJson()
    },
    async openDeviceEnrollmentGrant(): Promise<Uint8Array> {
      if (openedPackage === undefined) throw new Error("missing package")
      return Uint8Array.from(openedPackage)
    },
  } as unknown as BrowserDeviceKeyStore
}

test("joining-device request is retained durably until a grant is accepted", async () => {
  const storage = new MemoryApprovalStorage()
  const saved: unknown[] = []
  const credentialPackage = new TextEncoder().encode(JSON.stringify({
    format_version: 1,
    account_id: ACCOUNT_ID,
    device_id: JOINING_ID,
    device_token: TOKEN,
  }))
  const coordinator = new BrowserDeviceEnrollmentCoordinator(
    fakeDeviceKeys(credentialPackage), fakeCredentialStore(saved), storage, crypto,
  )

  const request = await coordinator.createJoinRequest(API, ACCOUNT_ID, JOINING_ID)
  assert.deepEqual(request, {
    account_id: ACCOUNT_ID,
    request_id: REQUEST_ID,
    joining_device_id: JOINING_ID,
    request_json: requestJson(),
  })
  assert.deepEqual(await coordinator.listJoinRequests(API, ACCOUNT_ID), [request])

  await assert.rejects(
    coordinator.acceptStoredGrant(API, ACCOUNT_ID, REQUEST_ID, grantJson(), {
      fetcher: async () => { throw new Error("offline") },
    }),
    /compatibility request failed/,
  )
  assert.deepEqual(await coordinator.listJoinRequests(API, ACCOUNT_ID), [request])
  assert.deepEqual(saved, [])

  const fetcher: typeof fetch = async (input) => {
    const path = new URL(String(input)).pathname
    if (path === "/v1/compatibility") return Response.json(CURRENT_SYNC_COMPATIBILITY)
    if (path.endsWith("/activate")) {
      return Response.json({
        account_id: ACCOUNT_ID,
        request_id: REQUEST_ID,
        device_id: JOINING_ID,
        expires_at_unix_seconds: 2_000_000_000,
        status: "active",
      })
    }
    if (path === "/v1/devices") {
      return Response.json({
        current_device_id: JOINING_ID,
        devices: [
          {
            device_id: APPROVER_ID,
            encryption_public_key: "33".repeat(32),
            signing_public_key: "44".repeat(32),
          },
          {
            device_id: JOINING_ID,
            encryption_public_key: "11".repeat(32),
            signing_public_key: "22".repeat(32),
          },
        ],
      })
    }
    throw new Error(`unexpected endpoint ${path}`)
  }
  const accepted = await coordinator.acceptStoredGrant(
    API, ACCOUNT_ID, REQUEST_ID, grantJson(), { fetcher },
  )
  assert.equal(accepted.client.deviceId, JOINING_ID)
  assert.deepEqual(await coordinator.listJoinRequests(API, ACCOUNT_ID), [])
  assert.equal(saved.length, 1)
})

test("joining-device request can be discarded without affecting approval drafts", async () => {
  const storage = new MemoryApprovalStorage()
  const coordinator = new BrowserDeviceEnrollmentCoordinator(
    fakeDeviceKeys(), fakeCredentialStore([]), storage, crypto,
  )
  const request = await coordinator.createJoinRequest(API, ACCOUNT_ID, JOINING_ID)
  await coordinator.discardJoinRequest(API, ACCOUNT_ID, request.request_id)
  assert.deepEqual(await coordinator.listJoinRequests(API, ACCOUNT_ID), [])
  await assert.rejects(
    coordinator.acceptStoredGrant(API, ACCOUNT_ID, request.request_id, grantJson()),
    (error: unknown) => error instanceof SyncClientError && error.code === "not_found",
  )
})

function fakeCredentialStore(saved: Array<unknown>): BrowserSyncCredentialStore {
  return {
    async save(_api: string, credentials: unknown): Promise<void> { saved.push(credentials) },
  } as unknown as BrowserSyncCredentialStore
}

test("approval draft is encrypted durably before the first server mutation and resumes exactly", async () => {
  const storage = new MemoryApprovalStorage()
  const saved: unknown[] = []
  let failPreparation = true
  const enrollmentBodies: string[] = []
  const fetcher: typeof fetch = async (input, init = {}) => {
    const path = new URL(String(input)).pathname
    if (path === "/v1/compatibility") return Response.json(CURRENT_SYNC_COMPATIBILITY)
    if (path === "/v1/device-enrollments") {
      assert.equal(storage.records.size, 1)
      enrollmentBodies.push(String(init.body))
      if (failPreparation) throw new Error("offline")
      return Response.json({
        account_id: ACCOUNT_ID,
        request_id: REQUEST_ID,
        device_id: JOINING_ID,
        expires_at_unix_seconds: 2_000_000_000,
        status: "pending",
      }, { status: 201 })
    }
    throw new Error(`unexpected endpoint ${path}`)
  }
  const client = await SyncClient.connect(API, ACCOUNT_ID, TOKEN, {
    fetcher,
    deviceId: APPROVER_ID,
  })
  const coordinator = new BrowserDeviceEnrollmentCoordinator(
    fakeDeviceKeys(), fakeCredentialStore(saved), storage, crypto,
  )

  await assert.rejects(
    coordinator.prepareApproval(client, APPROVER_ID, requestJson()),
    (error: unknown) => error instanceof SyncClientError && error.code === "request_failed",
  )
  const draft = [...storage.records.values()][0]
  assert.ok(draft)
  assert.equal((await storage.getOrCreateWrappingKey()).extractable, false)
  const firstPayload = JSON.parse(enrollmentBodies[0] ?? "null") as { device_token: string }
  assert.match(firstPayload.device_token, /^sfo_dev_v1_[0-9a-f]{64}$/)
  assert.equal(
    new TextDecoder().decode(draft.ciphertext).includes(firstPayload.device_token),
    false,
  )
  await assert.rejects(
    coordinator.prepareApproval(client, APPROVER_ID, requestJson()),
    /draft already exists/,
  )
  assert.equal(storage.records.values().next().value, draft)

  failPreparation = false
  const resumed = await coordinator.resumeApproval(client, REQUEST_ID)
  const secondPayload = JSON.parse(enrollmentBodies[1] ?? "null") as { device_token: string }
  assert.equal(secondPayload.device_token, firstPayload.device_token)
  assert.equal(resumed.grant_json, draft.grantJson)
  assert.equal(resumed.enrollment.status, "pending")
  assert.deepEqual(await coordinator.listApprovalDrafts(API, ACCOUNT_ID), [{
    account_id: ACCOUNT_ID,
    request_id: REQUEST_ID,
    approver_device_id: APPROVER_ID,
    joining_device_id: JOINING_ID,
    request_json: draft.requestJson,
    grant_json: draft.grantJson,
  }])
})

test("joining device persists credentials only after active approver inventory verification", async () => {
  const saved: unknown[] = []
  const credentialPackage = new TextEncoder().encode(JSON.stringify({
    format_version: 1,
    account_id: ACCOUNT_ID,
    device_id: JOINING_ID,
    device_token: TOKEN,
  }))
  const fetcher: typeof fetch = async (input) => {
    const path = new URL(String(input)).pathname
    if (path === "/v1/compatibility") return Response.json(CURRENT_SYNC_COMPATIBILITY)
    if (path.endsWith("/activate")) {
      return Response.json({
        account_id: ACCOUNT_ID,
        request_id: REQUEST_ID,
        device_id: JOINING_ID,
        expires_at_unix_seconds: 2_000_000_000,
        status: "active",
      })
    }
    if (path === "/v1/devices") {
      return Response.json({
        current_device_id: JOINING_ID,
        devices: [
          {
            device_id: APPROVER_ID,
            encryption_public_key: "33".repeat(32),
            signing_public_key: "44".repeat(32),
          },
          {
            device_id: JOINING_ID,
            encryption_public_key: "11".repeat(32),
            signing_public_key: "22".repeat(32),
          },
        ],
      })
    }
    throw new Error(`unexpected endpoint ${path}`)
  }
  const coordinator = new BrowserDeviceEnrollmentCoordinator(
    fakeDeviceKeys(credentialPackage),
    fakeCredentialStore(saved),
    new MemoryApprovalStorage(),
    crypto,
  )

  const accepted = await coordinator.acceptGrant(
    API, JOINING_ID, requestJson(), grantJson(), { fetcher },
  )
  assert.equal(accepted.client.deviceId, JOINING_ID)
  assert.deepEqual(saved, [{
    account_id: ACCOUNT_ID,
    device_id: JOINING_ID,
    device_token: TOKEN,
  }])
})

test("joining device refuses a substituted approver before saving credentials", async () => {
  const saved: unknown[] = []
  const credentialPackage = new TextEncoder().encode(JSON.stringify({
    format_version: 1,
    account_id: ACCOUNT_ID,
    device_id: JOINING_ID,
    device_token: TOKEN,
  }))
  const fetcher: typeof fetch = async (input) => {
    const path = new URL(String(input)).pathname
    if (path === "/v1/compatibility") return Response.json(CURRENT_SYNC_COMPATIBILITY)
    if (path.endsWith("/activate")) {
      return Response.json({
        account_id: ACCOUNT_ID,
        request_id: REQUEST_ID,
        device_id: JOINING_ID,
        expires_at_unix_seconds: 2_000_000_000,
        status: "active",
      })
    }
    return Response.json({
      current_device_id: JOINING_ID,
      devices: [{
        device_id: JOINING_ID,
        encryption_public_key: "11".repeat(32),
        signing_public_key: "22".repeat(32),
      }],
    })
  }
  const coordinator = new BrowserDeviceEnrollmentCoordinator(
    fakeDeviceKeys(credentialPackage), fakeCredentialStore(saved),
    new MemoryApprovalStorage(), crypto,
  )

  await assert.rejects(
    coordinator.acceptGrant(API, JOINING_ID, requestJson(), grantJson(), { fetcher }),
    (error: unknown) => error instanceof SyncClientError && error.code === "invalid_response",
  )
  assert.deepEqual(saved, [])
})
