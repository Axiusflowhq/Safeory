import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_EXTENSION_SYNC_API_URL,
  loadExtensionSyncConfiguration,
  normalizeExtensionSyncApiBaseUrl,
  saveExtensionSyncConfiguration,
  type ExtensionStorageArea,
} from "../src/sync-configuration.ts";

const accountId = "11111111-1111-4111-8111-111111111111";
const deviceId = "22222222-2222-4222-8222-222222222222";

class MemoryStorage implements ExtensionStorageArea {
  readonly values: Record<string, unknown> = {};
  async get(key: string): Promise<Record<string, unknown>> {
    return Object.hasOwn(this.values, key) ? { [key]: this.values[key] } : {};
  }
  async set(items: Record<string, unknown>): Promise<void> {
    Object.assign(this.values, items);
  }
  async remove(key: string): Promise<void> {
    delete this.values[key];
  }
}

test("stores only strict non-secret extension routing metadata", async () => {
  const storage = new MemoryStorage();
  const saved = await saveExtensionSyncConfiguration(
    { format: 1, apiBaseUrl: "https://sync.example.test/api", accountId, deviceId },
    storage,
  );
  assert.deepEqual(saved, {
    format: 1,
    apiBaseUrl: "https://sync.example.test/api/",
    accountId,
    deviceId,
  });
  assert.deepEqual(await loadExtensionSyncConfiguration(storage), saved);
  assert.doesNotMatch(JSON.stringify(storage.values), /token|secret|bearer/i);
});

test("rejects unknown fields and unsafe remote HTTP endpoints", async () => {
  const storage = new MemoryStorage();
  storage.values["safeory.sync.connection.v1"] = {
    format: 1,
    apiBaseUrl: "https://sync.example.test/api/",
    accountId,
    deviceId,
    deviceToken: "must-not-be-accepted",
  };
  await assert.rejects(loadExtensionSyncConfiguration(storage), /invalid/);
  assert.throws(
    () => normalizeExtensionSyncApiBaseUrl("http://sync.example.test/api/"),
    /HTTPS/,
  );
});

test("allows the explicit loopback development API", () => {
  assert.equal(
    normalizeExtensionSyncApiBaseUrl(DEFAULT_EXTENSION_SYNC_API_URL),
    DEFAULT_EXTENSION_SYNC_API_URL,
  );
});
