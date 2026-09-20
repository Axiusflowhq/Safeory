import assert from "node:assert/strict";
import test from "node:test";

import {
  BrowserDeviceKeyStore,
  type DeviceIdentityFactory,
  type DeviceKeyStorageBackend,
  type StoredDeviceIdentityV1,
  type WasmDeviceIdentityLike,
} from "../src/device-keys";
import type { PairingChallengeV1, PairingProofV1 } from "../src/session";

const DEVICE_ID = "55555555-5555-4555-8555-555555555555";
const ENCRYPTION_PUBLIC = Array.from({ length: 32 }, () => 0x11);
const SIGNING_PUBLIC = Array.from({ length: 32 }, () => 0x22);
const ENCRYPTION_HEX = "11".repeat(32);
const SIGNING_HEX = "22".repeat(32);

function privateMaterial(): Uint8Array {
  const bytes = new Uint8Array(64);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = index + 1;
  return bytes;
}

function registrationJson(deviceId: string): string {
  return JSON.stringify({
    format_version: 1,
    device_id: deviceId,
    encryption_public_key_hex: ENCRYPTION_HEX,
    signing_public_key_hex: SIGNING_HEX,
  });
}

function fakeIdentity(deviceId: string, expectedPrivate: Uint8Array): WasmDeviceIdentityLike {
  return {
    registrationJson: () => registrationJson(deviceId),
    exportPrivateKeyBytes: () => expectedPrivate.slice(),
    answerPairingChallengeJson: (challengeJson: string) => {
      const challenge = JSON.parse(challengeJson) as PairingChallengeV1;
      const proof: PairingProofV1 = {
        format_version: 1,
        request_id: challenge.request_id,
        principal_id: challenge.principal_id,
        device_id: challenge.device_id,
        signing_public: SIGNING_PUBLIC,
        encryption_public: challenge.encryption_public,
        verifier_ephemeral_public: challenge.verifier_ephemeral_public,
        challenge: Array.from({ length: 32 }, () => 0x44),
        signature: Array.from({ length: 64 }, () => 0x55),
      };
      return JSON.stringify(proof);
    },
  };
}

class FakeFactory implements DeviceIdentityFactory {
  private readonly expected = privateMaterial();

  generate(deviceId: string): WasmDeviceIdentityLike {
    return fakeIdentity(deviceId, this.expected);
  }

  fromPrivateKeyBytes(deviceId: string, privateKeyBytes: Uint8Array): WasmDeviceIdentityLike {
    assert.deepEqual(Array.from(privateKeyBytes), Array.from(this.expected));
    return fakeIdentity(deviceId, this.expected);
  }
}

class MemoryStorage implements DeviceKeyStorageBackend {
  readonly records = new Map<string, StoredDeviceIdentityV1>();
  readonly wrappingKeyPromise = crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  ) as Promise<CryptoKey>;

  getOrCreateWrappingKey(): Promise<CryptoKey> {
    return this.wrappingKeyPromise;
  }

  async addIdentity(record: StoredDeviceIdentityV1): Promise<void> {
    if (this.records.has(record.deviceId)) throw new Error("duplicate device");
    this.records.set(record.deviceId, record);
  }

  async getIdentity(deviceId: string): Promise<StoredDeviceIdentityV1 | null> {
    return this.records.get(deviceId) ?? null;
  }

  async listIdentities(): Promise<StoredDeviceIdentityV1[]> {
    return [...this.records.values()];
  }

  async deleteIdentity(deviceId: string): Promise<void> {
    this.records.delete(deviceId);
  }
}

function challenge(encryptionPublic = ENCRYPTION_PUBLIC): PairingChallengeV1 {
  return {
    format_version: 1,
    request_id: "66666666-6666-4666-8666-666666666666",
    principal_id: "44444444-4444-4444-8444-444444444444",
    device_id: DEVICE_ID,
    encryption_public: encryptionPublic,
    verifier_ephemeral_public: Array.from({ length: 32 }, () => 0x33),
    nonce: Array.from({ length: 24 }, () => 0x44),
    ciphertext: Array.from({ length: 48 }, () => 0x55),
  };
}

test("browser device keys persist only as AES-GCM ciphertext under a non-extractable key", async () => {
  const storage = new MemoryStorage();
  const store = new BrowserDeviceKeyStore(new FakeFactory(), storage, crypto);

  const registration = await store.createIdentity(DEVICE_ID);
  assert.equal(registration.device_id, DEVICE_ID);
  assert.equal(registration.encryption_public_key_hex, ENCRYPTION_HEX);
  assert.equal(registration.signing_public_key_hex, SIGNING_HEX);

  const wrappingKey = await storage.getOrCreateWrappingKey();
  assert.equal(wrappingKey.extractable, false);
  assert.equal(wrappingKey.algorithm.name, "AES-GCM");

  const saved = storage.records.get(DEVICE_ID);
  assert.ok(saved);
  assert.equal(saved.ciphertext.byteLength, 80);
  assert.equal(saved.iv.byteLength, 12);
  assert.notDeepEqual(
    Array.from(new Uint8Array(saved.ciphertext).subarray(0, 64)),
    Array.from(privateMaterial()),
  );

  const listed = await store.listIdentities();
  assert.deepEqual(listed, [registration]);
  const proof = await store.answerPairingChallenge(challenge());
  assert.equal(proof.device_id, DEVICE_ID);
  assert.deepEqual(proof.signing_public, SIGNING_PUBLIC);
});

test("browser device key AAD binds stored public identity metadata", async () => {
  const storage = new MemoryStorage();
  const store = new BrowserDeviceKeyStore(new FakeFactory(), storage, crypto);
  await store.createIdentity(DEVICE_ID);
  const saved = storage.records.get(DEVICE_ID);
  assert.ok(saved);
  saved.signingPublicKeyHex = "33".repeat(32);

  await assert.rejects(
    store.answerPairingChallenge(challenge()),
    /Unable to answer the trusted-device pairing challenge/,
  );
});

test("browser device responder rejects a challenge for a different recipient key", async () => {
  const storage = new MemoryStorage();
  const store = new BrowserDeviceKeyStore(new FakeFactory(), storage, crypto);
  await store.createIdentity(DEVICE_ID);

  await assert.rejects(
    store.answerPairingChallenge(challenge(Array.from({ length: 32 }, () => 0x99))),
    /does not match this browser device identity/,
  );
});

test("browser device identity deletion removes the local responder key", async () => {
  const storage = new MemoryStorage();
  const store = new BrowserDeviceKeyStore(new FakeFactory(), storage, crypto);
  await store.createIdentity(DEVICE_ID);
  await store.deleteIdentity(DEVICE_ID);
  assert.deepEqual(await store.listIdentities(), []);
  await assert.rejects(store.answerPairingChallenge(challenge()), /does not hold the private keys/);
});
