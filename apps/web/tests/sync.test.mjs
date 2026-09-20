import assert from "node:assert/strict"
import test from "node:test"

import {
  browserSyncApiBaseUrl,
  clearBrowserSyncConfiguration,
  loadBrowserSyncConfiguration,
  saveBrowserSyncConfiguration,
} from "../lib/vault/sync-configuration.ts"

const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const DEVICE_ID = "22222222-2222-4222-8222-222222222222"

class MemoryStorage {
  values = new Map()

  getItem(key) {
    return this.values.get(key) ?? null
  }

  setItem(key, value) {
    this.values.set(key, String(value))
  }

  removeItem(key) {
    this.values.delete(key)
  }
}

test("sync configuration stores only normalized non-secret routing metadata", () => {
  const storage = new MemoryStorage()
  const saved = saveBrowserSyncConfiguration({
    format: 1,
    apiBaseUrl: "https://vault.example.test/api",
    accountId: ACCOUNT_ID.toUpperCase(),
    deviceId: DEVICE_ID.toUpperCase(),
  }, storage)
  assert.deepEqual(saved, {
    format: 1,
    apiBaseUrl: "https://vault.example.test/api/",
    accountId: ACCOUNT_ID,
    deviceId: DEVICE_ID,
  })
  const encoded = storage.getItem("safeory:sync-connection:v1")
  assert.equal(encoded?.includes("device_token"), false)
  assert.deepEqual(loadBrowserSyncConfiguration(storage), saved)
  clearBrowserSyncConfiguration(storage)
  assert.equal(loadBrowserSyncConfiguration(storage), null)
})

test("sync configuration rejects unknown fields and unsafe endpoints", () => {
  const storage = new MemoryStorage()
  storage.setItem("safeory:sync-connection:v1", JSON.stringify({
    format: 1,
    apiBaseUrl: "https://vault.example.test/api/",
    accountId: ACCOUNT_ID,
    deviceId: DEVICE_ID,
    device_token: "must-not-persist",
  }))
  assert.throws(() => loadBrowserSyncConfiguration(storage), /invalid/)

  assert.throws(
    () => saveBrowserSyncConfiguration({
      format: 1,
      apiBaseUrl: "http://vault.example.test/api",
      accountId: ACCOUNT_ID,
      deviceId: DEVICE_ID,
    }, storage),
    /HTTPS/,
  )
})

test("production sync uses the same-origin API proxy", () => {
  assert.equal(
    browserSyncApiBaseUrl({ origin: "https://vault.example.test" }),
    "https://vault.example.test/api/",
  )
})
