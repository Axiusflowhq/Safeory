import type { PairingChallengeV1, PairingProofV1 } from "./session";

const DEVICE_DB_NAME = "safeory-device-keys";
const DEVICE_DB_VERSION = 1;
const WRAPPING_STORE = "wrapping";
const IDENTITY_STORE = "identities";
const WRAPPING_KEY_ID = "device-key-wrap-v1";
const DEVICE_RECORD_FORMAT = 1;
const PRIVATE_KEY_BYTES = 64;
const AES_GCM_IV_BYTES = 12;
const WRAP_AAD_DOMAIN = "safeory:browser-device-key-wrap:v1";

export interface DeviceRegistrationV1 {
  format_version: 1;
  device_id: string;
  encryption_public_key_hex: string;
  signing_public_key_hex: string;
}

export interface WasmDeviceIdentityLike {
  registrationJson(): string;
  exportPrivateKeyBytes(): Uint8Array;
  answerPairingChallengeJson(challengeJson: string): string;
  createDeviceEnrollmentRequestJson(accountId: string): string;
  sealDeviceEnrollmentGrantJson(requestJson: string, credentialPackage: Uint8Array): string;
  openDeviceEnrollmentGrant(requestJson: string, grantJson: string): Uint8Array;
  free?: () => void;
}

export interface DeviceIdentityFactory {
  generate(deviceId: string): WasmDeviceIdentityLike;
  fromPrivateKeyBytes(deviceId: string, privateKeyBytes: Uint8Array): WasmDeviceIdentityLike;
}

export interface StoredDeviceIdentityV1 {
  format: number;
  deviceId: string;
  encryptionPublicKeyHex: string;
  signingPublicKeyHex: string;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

export interface DeviceKeyStorageBackend {
  getOrCreateWrappingKey(): Promise<CryptoKey>;
  addIdentity(record: StoredDeviceIdentityV1): Promise<void>;
  getIdentity(deviceId: string): Promise<StoredDeviceIdentityV1 | null>;
  listIdentities(): Promise<StoredDeviceIdentityV1[]>;
  deleteIdentity(deviceId: string): Promise<void>;
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function isHexKey(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isUuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
  );
}

function bytesToHex(bytes: readonly number[]): string {
  if (bytes.length !== 32 || bytes.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new Error("pairing challenge public key is invalid");
  }
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function parseRegistration(json: string): DeviceRegistrationV1 {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    throw new Error("device registration is invalid");
  }
  if (typeof value !== "object" || value === null) {
    throw new Error("device registration is invalid");
  }
  const candidate = value as Partial<DeviceRegistrationV1>;
  if (
    candidate.format_version !== 1 ||
    !isUuid(candidate.device_id) ||
    !isHexKey(candidate.encryption_public_key_hex) ||
    !isHexKey(candidate.signing_public_key_hex)
  ) {
    throw new Error("device registration is invalid");
  }
  return candidate as DeviceRegistrationV1;
}

function validateWrappingKey(value: unknown): CryptoKey {
  if (typeof value !== "object" || value === null) {
    throw new Error("browser device wrapping key is missing or invalid");
  }
  const key = value as CryptoKey;
  if (
    key.type !== "secret" ||
    key.extractable !== false ||
    key.algorithm?.name !== "AES-GCM" ||
    !key.usages?.includes("encrypt") ||
    !key.usages?.includes("decrypt")
  ) {
    throw new Error("browser device wrapping key is missing or invalid");
  }
  return key;
}

function validatePersistedIdentity(value: unknown): StoredDeviceIdentityV1 {
  if (typeof value !== "object" || value === null) {
    throw new Error("saved browser device identity is invalid");
  }
  const candidate = value as Partial<StoredDeviceIdentityV1>;
  if (
    candidate.format !== DEVICE_RECORD_FORMAT ||
    !isUuid(candidate.deviceId) ||
    !isHexKey(candidate.encryptionPublicKeyHex) ||
    !isHexKey(candidate.signingPublicKeyHex) ||
    !(candidate.iv instanceof ArrayBuffer) ||
    candidate.iv.byteLength !== AES_GCM_IV_BYTES ||
    !(candidate.ciphertext instanceof ArrayBuffer) ||
    candidate.ciphertext.byteLength <= PRIVATE_KEY_BYTES
  ) {
    throw new Error("saved browser device identity is invalid");
  }
  return candidate as StoredDeviceIdentityV1;
}

function wrapAad(record: Pick<
  StoredDeviceIdentityV1,
  "deviceId" | "encryptionPublicKeyHex" | "signingPublicKeyHex"
>): ArrayBuffer {
  const bytes = new TextEncoder().encode(
    `${WRAP_AAD_DOMAIN}\0${record.deviceId}\0${record.encryptionPublicKeyHex}\0${record.signingPublicKeyHex}`,
  );
  return bytes.slice().buffer as ArrayBuffer;
}

function openDeviceDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DEVICE_DB_NAME, DEVICE_DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(WRAPPING_STORE)) db.createObjectStore(WRAPPING_STORE);
      if (!db.objectStoreNames.contains(IDENTITY_STORE)) db.createObjectStore(IDENTITY_STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("device-key database open failed"));
  });
}

async function generateWrappingKey(): Promise<CryptoKey> {
  const generated = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return validateWrappingKey(generated);
}

async function getOrCreateWrappingKey(): Promise<CryptoKey> {
  // Generate first. IndexedDB may auto-commit while awaiting Web Crypto, so no
  // asynchronous crypto operation occurs inside the conditional-write window.
  const candidate = await generateWrappingKey();
  return openDeviceDb().then(
    (db) =>
      new Promise<CryptoKey>((resolve, reject) => {
        const tx = db.transaction(WRAPPING_STORE, "readwrite");
        const store = tx.objectStore(WRAPPING_STORE);
        let selected: CryptoKey | null = null;
        let settled = false;
        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          db.close();
          reject(asError(error));
        };
        tx.onabort = () => fail(tx.error ?? new Error("device wrapping-key transaction aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("device wrapping-key transaction failed"));
        tx.oncomplete = () => {
          if (settled) return;
          if (selected === null) {
            fail(new Error("device wrapping-key transaction completed without a key"));
            return;
          }
          settled = true;
          db.close();
          resolve(selected);
        };
        const read = store.get(WRAPPING_KEY_ID);
        read.onerror = () => fail(read.error ?? new Error("device wrapping-key read failed"));
        read.onsuccess = () => {
          try {
            if (read.result !== undefined) {
              selected = validateWrappingKey(read.result);
              return;
            }
            selected = candidate;
            const write = store.add(candidate, WRAPPING_KEY_ID);
            write.onerror = () => fail(write.error ?? new Error("device wrapping-key write failed"));
          } catch (error) {
            fail(error);
            try {
              tx.abort();
            } catch {
              // Transaction may already be stopping.
            }
          }
        };
      }),
  );
}

function addIdentity(record: StoredDeviceIdentityV1): Promise<void> {
  const validated = validatePersistedIdentity(record);
  return openDeviceDb().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(IDENTITY_STORE, "readwrite");
        const request = tx.objectStore(IDENTITY_STORE).add(validated, validated.deviceId);
        let settled = false;
        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          db.close();
          reject(asError(error));
        };
        request.onerror = () => fail(request.error ?? new Error("device identity already exists"));
        tx.onabort = () => fail(tx.error ?? new Error("device identity write aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("device identity write failed"));
        tx.oncomplete = () => {
          if (settled) return;
          settled = true;
          db.close();
          resolve();
        };
      }),
  );
}

function getIdentity(deviceId: string): Promise<StoredDeviceIdentityV1 | null> {
  return openDeviceDb().then(
    (db) =>
      new Promise<StoredDeviceIdentityV1 | null>((resolve, reject) => {
        const request = db.transaction(IDENTITY_STORE, "readonly").objectStore(IDENTITY_STORE).get(deviceId);
        request.onerror = () => {
          db.close();
          reject(request.error ?? new Error("device identity read failed"));
        };
        request.onsuccess = () => {
          try {
            const result = request.result === undefined ? null : validatePersistedIdentity(request.result);
            db.close();
            resolve(result);
          } catch (error) {
            db.close();
            reject(asError(error));
          }
        };
      }),
  );
}

function listIdentityRecords(): Promise<StoredDeviceIdentityV1[]> {
  return openDeviceDb().then(
    (db) =>
      new Promise<StoredDeviceIdentityV1[]>((resolve, reject) => {
        const request = db.transaction(IDENTITY_STORE, "readonly").objectStore(IDENTITY_STORE).getAll();
        request.onerror = () => {
          db.close();
          reject(request.error ?? new Error("device identity list failed"));
        };
        request.onsuccess = () => {
          try {
            const result = request.result.map(validatePersistedIdentity);
            db.close();
            resolve(result);
          } catch (error) {
            db.close();
            reject(asError(error));
          }
        };
      }),
  );
}

function deleteIdentityRecord(deviceId: string): Promise<void> {
  return openDeviceDb().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(IDENTITY_STORE, "readwrite");
        const request = tx.objectStore(IDENTITY_STORE).delete(deviceId);
        let settled = false;
        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          db.close();
          reject(asError(error));
        };
        request.onerror = () => fail(request.error ?? new Error("device identity delete failed"));
        tx.onabort = () => fail(tx.error ?? new Error("device identity delete aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("device identity delete failed"));
        tx.oncomplete = () => {
          if (settled) return;
          settled = true;
          db.close();
          resolve();
        };
      }),
  );
}

export class IndexedDbDeviceKeyStorage implements DeviceKeyStorageBackend {
  getOrCreateWrappingKey(): Promise<CryptoKey> {
    return getOrCreateWrappingKey();
  }

  addIdentity(record: StoredDeviceIdentityV1): Promise<void> {
    return addIdentity(record);
  }

  getIdentity(deviceId: string): Promise<StoredDeviceIdentityV1 | null> {
    return getIdentity(deviceId);
  }

  listIdentities(): Promise<StoredDeviceIdentityV1[]> {
    return listIdentityRecords();
  }

  deleteIdentity(deviceId: string): Promise<void> {
    return deleteIdentityRecord(deviceId);
  }
}

export class BrowserDeviceKeyStore {
  constructor(
    private readonly factory: DeviceIdentityFactory,
    private readonly storage: DeviceKeyStorageBackend = new IndexedDbDeviceKeyStorage(),
    private readonly cryptography: Crypto = crypto,
  ) {}

  async createIdentity(deviceId: string): Promise<DeviceRegistrationV1> {
    if (!isUuid(deviceId)) throw new Error("device identifier is invalid");
    const identity = this.factory.generate(deviceId);
    let privateBytes: Uint8Array | null = null;
    let encryptInput: Uint8Array<ArrayBuffer> | null = null;
    try {
      const registration = parseRegistration(identity.registrationJson());
      if (registration.device_id !== deviceId) throw new Error("generated device identity is inconsistent");
      privateBytes = identity.exportPrivateKeyBytes();
      if (privateBytes.byteLength !== PRIVATE_KEY_BYTES) {
        throw new Error("generated device private-key material is invalid");
      }
      encryptInput = new Uint8Array(PRIVATE_KEY_BYTES);
      encryptInput.set(privateBytes);
      const wrappingKey = await this.storage.getOrCreateWrappingKey();
      const iv = this.cryptography.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
      const metadata = {
        deviceId: registration.device_id,
        encryptionPublicKeyHex: registration.encryption_public_key_hex,
        signingPublicKeyHex: registration.signing_public_key_hex,
      };
      const ciphertext = await this.cryptography.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: wrapAad(metadata) },
        wrappingKey,
        encryptInput,
      );
      await this.storage.addIdentity({
        format: DEVICE_RECORD_FORMAT,
        ...metadata,
        iv: iv.slice().buffer,
        ciphertext,
      });
      return registration;
    } finally {
      privateBytes?.fill(0);
      encryptInput?.fill(0);
      identity.free?.();
    }
  }

  async listIdentities(): Promise<DeviceRegistrationV1[]> {
    const records = await this.storage.listIdentities();
    return records.map((record) => ({
      format_version: 1,
      device_id: record.deviceId,
      encryption_public_key_hex: record.encryptionPublicKeyHex,
      signing_public_key_hex: record.signingPublicKeyHex,
    }));
  }

  async deleteIdentity(deviceId: string): Promise<void> {
    if (!isUuid(deviceId)) throw new Error("device identifier is invalid");
    await this.storage.deleteIdentity(deviceId);
  }

  async createDeviceEnrollmentRequest(deviceId: string, accountId: string): Promise<string> {
    return this.withIdentity(deviceId, (identity) =>
      identity.createDeviceEnrollmentRequestJson(accountId),
    );
  }

  async sealDeviceEnrollmentGrant(
    approverDeviceId: string,
    requestJson: string,
    credentialPackage: Uint8Array,
  ): Promise<string> {
    const input = Uint8Array.from(credentialPackage);
    try {
      return await this.withIdentity(approverDeviceId, (identity) =>
        identity.sealDeviceEnrollmentGrantJson(requestJson, input),
      );
    } finally {
      input.fill(0);
    }
  }

  async openDeviceEnrollmentGrant(
    joiningDeviceId: string,
    requestJson: string,
    grantJson: string,
  ): Promise<Uint8Array> {
    return this.withIdentity(joiningDeviceId, (identity) => {
      const plaintext = identity.openDeviceEnrollmentGrant(requestJson, grantJson);
      try {
        return Uint8Array.from(plaintext);
      } finally {
        plaintext.fill(0);
      }
    });
  }

  async answerPairingChallenge(challenge: PairingChallengeV1): Promise<PairingProofV1> {
    if (!isUuid(challenge.device_id)) throw new Error("pairing challenge device identifier is invalid");
    return this.withIdentity(
      challenge.device_id,
      (identity, registration) => {
        if (bytesToHex(challenge.encryption_public) !== registration.encryption_public_key_hex) {
          throw new Error("Pairing challenge does not match this browser device identity.");
        }
        return JSON.parse(
          identity.answerPairingChallengeJson(JSON.stringify(challenge)),
        ) as PairingProofV1;
      },
      "Unable to answer the trusted-device pairing challenge.",
    );
  }

  private async withIdentity<T>(
    deviceId: string,
    operation: (identity: WasmDeviceIdentityLike, registration: DeviceRegistrationV1) => T,
    keyFailureMessage?: string,
  ): Promise<T> {
    if (!isUuid(deviceId)) throw new Error("device identifier is invalid");
    const record = await this.storage.getIdentity(deviceId);
    if (record === null) {
      throw new Error("This browser does not hold the private keys for the requested device.");
    }
    const wrappingKey = await this.storage.getOrCreateWrappingKey();
    let privateBytes: Uint8Array | null = null;
    let identity: WasmDeviceIdentityLike | null = null;
    let identityReady = false;
    try {
      const plaintext = await this.cryptography.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: new Uint8Array(record.iv),
          additionalData: wrapAad(record),
        },
        wrappingKey,
        record.ciphertext,
      );
      privateBytes = new Uint8Array(plaintext);
      if (privateBytes.byteLength !== PRIVATE_KEY_BYTES) {
        throw new Error("saved browser device key material is invalid");
      }
      identity = this.factory.fromPrivateKeyBytes(record.deviceId, privateBytes);
      const registration = parseRegistration(identity.registrationJson());
      if (
        registration.device_id !== record.deviceId ||
        registration.encryption_public_key_hex !== record.encryptionPublicKeyHex ||
        registration.signing_public_key_hex !== record.signingPublicKeyHex
      ) {
        throw new Error("saved browser device identity failed its public-key integrity check");
      }
      identityReady = true;
      return operation(identity, registration);
    } catch (error) {
      if (!identityReady && keyFailureMessage !== undefined) {
        throw new Error(keyFailureMessage, { cause: error });
      }
      throw error;
    } finally {
      privateBytes?.fill(0);
      identity?.free?.();
    }
  }
}
