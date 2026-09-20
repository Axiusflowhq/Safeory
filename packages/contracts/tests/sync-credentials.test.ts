import assert from "node:assert/strict"
import test from "node:test"

import type { DeviceCredentialsV1 } from "../src/sync-client"
import {
  BrowserSyncCredentialStore,
  type StoredSyncCredentialV1,
  type SyncCredentialStorageBackend,
} from "../src/sync-credentials"
import { SyncClientError } from "../src/sync-error"
import { CURRENT_SYNC_COMPATIBILITY } from "../src/sync-compatibility"

const API_URL = "https://sync.example.test"
const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const DEVICE_ID = "22222222-2222-4222-8222-222222222222"
const TOKEN = `sfo_dev_v1_${"a".repeat(64)}`

function credentials(): DeviceCredentialsV1 {
  return {
    account_id: ACCOUNT_ID,
    device_id: DEVICE_ID,
    device_token: TOKEN,
  }
}

class MemoryCredentialStorage implements SyncCredentialStorageBackend {
  readonly records = new Map<string, StoredSyncCredentialV1>()
  readonly wrappingKeyPromise = crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  ) as Promise<CryptoKey>

  getOrCreateWrappingKey(): Promise<CryptoKey> {
    return this.wrappingKeyPromise
  }

  async putCredential(record: StoredSyncCredentialV1): Promise<void> {
    this.records.set(record.key, record)
  }

  async getCredential(key: string): Promise<StoredSyncCredentialV1 | null> {
    return this.records.get(key) ?? null
  }

  async deleteCredential(key: string): Promise<void> {
    this.records.delete(key)
  }
}

test("device bearer persists only as bound ciphertext under a non-extractable key", async () => {
  const storage = new MemoryCredentialStorage()
  const store = new BrowserSyncCredentialStore(storage, crypto)

  await store.save(API_URL, credentials())

  const wrappingKey = await storage.getOrCreateWrappingKey()
  assert.equal(wrappingKey.extractable, false)
  assert.equal(wrappingKey.algorithm.name, "AES-GCM")
  const saved = [...storage.records.values()][0]
  assert.ok(saved)
  assert.equal(saved.apiBaseUrl, `${API_URL}/`)
  assert.equal(saved.iv.byteLength, 12)
  const plaintext = new TextEncoder().encode(TOKEN)
  assert.notDeepEqual(
    Array.from(new Uint8Array(saved.ciphertext).subarray(0, plaintext.byteLength)),
    Array.from(plaintext),
  )
  assert.deepEqual(await store.load(`${API_URL}/`, ACCOUNT_ID), credentials())
})

test("credential AAD rejects device metadata substitution", async () => {
  const storage = new MemoryCredentialStorage()
  const store = new BrowserSyncCredentialStore(storage, crypto)
  await store.save(API_URL, credentials())
  const saved = [...storage.records.values()][0]
  assert.ok(saved)
  saved.deviceId = "33333333-3333-4333-8333-333333333333"

  await assert.rejects(
    store.load(API_URL, ACCOUNT_ID),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_response",
  )
})

test("malformed persisted credential metadata fails as an invalid response", async () => {
  const storage = new MemoryCredentialStorage()
  const store = new BrowserSyncCredentialStore(storage, crypto)
  await store.save(API_URL, credentials())
  const saved = [...storage.records.values()][0]
  assert.ok(saved)
  saved.accountId = "not-an-account"

  await assert.rejects(
    store.load(API_URL, ACCOUNT_ID),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_response",
  )
})

test("credential lookup is API/account scoped and deletion is durable", async () => {
  const storage = new MemoryCredentialStorage()
  const store = new BrowserSyncCredentialStore(storage, crypto)
  await store.save(API_URL, credentials())

  assert.equal(
    await store.load(API_URL, "44444444-4444-4444-8444-444444444444"),
    null,
  )
  assert.equal(
    await store.load("https://other.example.test", ACCOUNT_ID),
    null,
  )
  await store.delete(API_URL, ACCOUNT_ID)
  assert.equal(await store.load(API_URL, ACCOUNT_ID), null)
})

test("credential store reconnects with the persisted device identity bound", async () => {
  const store = new BrowserSyncCredentialStore(new MemoryCredentialStorage(), crypto)
  await store.save(API_URL, credentials())
  const client = await store.connect(API_URL, ACCOUNT_ID, {
    fetcher: async () => Response.json(CURRENT_SYNC_COMPATIBILITY),
  })

  assert.equal(client?.accountId, ACCOUNT_ID)
  assert.equal(client?.deviceId, DEVICE_ID)
  assert.equal(
    await store.connect(API_URL, "44444444-4444-4444-8444-444444444444"),
    null,
  )
})

test("credential store rejects malformed tokens and insecure remote origins", async () => {
  const store = new BrowserSyncCredentialStore(new MemoryCredentialStorage(), crypto)
  await assert.rejects(
    store.save(API_URL, { ...credentials(), device_token: "not-a-token" }),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_contract",
  )
  await assert.rejects(
    store.save("http://sync.example.test", credentials()),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "invalid_configuration",
  )
})
