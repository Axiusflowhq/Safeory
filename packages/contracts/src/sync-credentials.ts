import {
  SyncClient,
  normalizeSyncApiBaseUrl,
  type DeviceCredentialsV1,
} from "./sync-client"
import { SyncClientError } from "./sync-error"

const DB_NAME = "safeory-sync-credentials"
const DB_VERSION = 1
const WRAPPING_STORE = "wrapping"
const CREDENTIAL_STORE = "credentials"
const WRAPPING_KEY_ID = "sync-credential-wrap-v1"
const RECORD_FORMAT = 1
const IV_BYTES = 12
const AAD_DOMAIN = "safeory:browser-sync-credential-wrap:v1"
const DEVICE_TOKEN = /^sfo_dev_v1_[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"
const MAX_CIPHERTEXT_BYTES = 4 * 1024

export interface StoredSyncCredentialV1 {
  key: string
  format: number
  apiBaseUrl: string
  accountId: string
  deviceId: string
  iv: ArrayBuffer
  ciphertext: ArrayBuffer
}

export interface SyncCredentialStorageBackend {
  getOrCreateWrappingKey(): Promise<CryptoKey>
  putCredential(record: StoredSyncCredentialV1): Promise<void>
  getCredential(key: string): Promise<StoredSyncCredentialV1 | null>
  deleteCredential(key: string): Promise<void>
}

export class BrowserSyncCredentialStore {
  constructor(
    private readonly storage: SyncCredentialStorageBackend =
      new IndexedDbSyncCredentialStorage(),
    private readonly cryptography: Crypto = crypto,
  ) {}

  async save(apiBaseUrlValue: string, credentialsValue: DeviceCredentialsV1): Promise<void> {
    const apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    const credentials = validateCredentials(credentialsValue)
    const key = recordKey(apiBaseUrl, credentials.account_id)
    const metadata = {
      apiBaseUrl,
      accountId: credentials.account_id,
      deviceId: credentials.device_id,
    }
    const plaintext = new TextEncoder().encode(credentials.device_token)
    try {
      const wrappingKey = validateWrappingKey(await this.storage.getOrCreateWrappingKey())
      const iv = this.cryptography.getRandomValues(new Uint8Array(IV_BYTES))
      const ciphertext = await this.cryptography.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: wrapAad(metadata) },
        wrappingKey,
        plaintext,
      )
      await this.storage.putCredential({
        key,
        format: RECORD_FORMAT,
        ...metadata,
        iv: iv.slice().buffer,
        ciphertext,
      })
    } finally {
      plaintext.fill(0)
    }
  }

  async load(
    apiBaseUrlValue: string,
    accountIdValue: string,
  ): Promise<DeviceCredentialsV1 | null> {
    const apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    const accountId = requireUuid(accountIdValue, "account ID")
    const key = recordKey(apiBaseUrl, accountId)
    const stored = await this.storage.getCredential(key)
    if (stored === null) return null
    const record = validateStoredCredential(stored)
    if (
      record.key !== key ||
      record.apiBaseUrl !== apiBaseUrl ||
      record.accountId !== accountId
    ) {
      return invalidStoredCredential()
    }

    let plaintext: Uint8Array | null = null
    try {
      const wrappingKey = validateWrappingKey(await this.storage.getOrCreateWrappingKey())
      const decrypted = await this.cryptography.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: new Uint8Array(record.iv),
          additionalData: wrapAad(record),
        },
        wrappingKey,
        record.ciphertext,
      )
      plaintext = new Uint8Array(decrypted)
      const deviceToken = new TextDecoder("utf-8", { fatal: true }).decode(plaintext)
      return validateCredentials({
        account_id: record.accountId,
        device_id: record.deviceId,
        device_token: deviceToken,
      })
    } catch (error) {
      if (error instanceof SyncClientError) throw error
      return invalidStoredCredential()
    } finally {
      plaintext?.fill(0)
    }
  }

  async delete(apiBaseUrlValue: string, accountIdValue: string): Promise<void> {
    const apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    const accountId = requireUuid(accountIdValue, "account ID")
    await this.storage.deleteCredential(recordKey(apiBaseUrl, accountId))
  }

  async connect(
    apiBaseUrlValue: string,
    accountIdValue: string,
    options: { fetcher?: typeof fetch; signal?: AbortSignal } = {},
  ): Promise<SyncClient | null> {
    const credentials = await this.load(apiBaseUrlValue, accountIdValue)
    if (credentials === null) return null
    return SyncClient.connect(
      apiBaseUrlValue,
      credentials.account_id,
      credentials.device_token,
      {
        ...options,
        deviceId: credentials.device_id,
      },
    )
  }
}

export class IndexedDbSyncCredentialStorage implements SyncCredentialStorageBackend {
  getOrCreateWrappingKey(): Promise<CryptoKey> {
    return getOrCreateWrappingKey()
  }

  putCredential(record: StoredSyncCredentialV1): Promise<void> {
    return writeCredential(validateStoredCredential(record))
  }

  getCredential(key: string): Promise<StoredSyncCredentialV1 | null> {
    return readCredential(key)
  }

  deleteCredential(key: string): Promise<void> {
    return deleteCredential(key)
  }
}

function validateCredentials(value: DeviceCredentialsV1): DeviceCredentialsV1 {
  if (typeof value !== "object" || value === null) {
    throw new SyncClientError("invalid_contract", "The device credential is invalid.")
  }
  const accountId = requireUuid(value.account_id, "account ID")
  const deviceId = requireUuid(value.device_id, "device ID")
  if (!DEVICE_TOKEN.test(value.device_token)) {
    throw new SyncClientError(
      "invalid_contract",
      "The device credential has an invalid format.",
    )
  }
  return { account_id: accountId, device_id: deviceId, device_token: value.device_token }
}

function validateStoredCredential(value: unknown): StoredSyncCredentialV1 {
  if (typeof value !== "object" || value === null) return invalidStoredCredential()
  const record = value as Partial<StoredSyncCredentialV1>
  if (
    record.format !== RECORD_FORMAT ||
    typeof record.key !== "string" ||
    typeof record.apiBaseUrl !== "string" ||
    typeof record.accountId !== "string" ||
    typeof record.deviceId !== "string" ||
    !(record.iv instanceof ArrayBuffer) ||
    record.iv.byteLength !== IV_BYTES ||
    !(record.ciphertext instanceof ArrayBuffer) ||
    record.ciphertext.byteLength <= 16 ||
    record.ciphertext.byteLength > MAX_CIPHERTEXT_BYTES
  ) {
    return invalidStoredCredential()
  }
  let apiBaseUrl: string
  try {
    apiBaseUrl = normalizeSyncApiBaseUrl(record.apiBaseUrl)
  } catch {
    return invalidStoredCredential()
  }
  try {
    return {
      key: record.key,
      format: RECORD_FORMAT,
      apiBaseUrl,
      accountId: requireUuid(record.accountId, "stored account ID"),
      deviceId: requireUuid(record.deviceId, "stored device ID"),
      iv: record.iv,
      ciphertext: record.ciphertext,
    }
  } catch {
    return invalidStoredCredential()
  }
}

function validateWrappingKey(value: unknown): CryptoKey {
  if (typeof value !== "object" || value === null) return invalidStoredCredential()
  const key = value as CryptoKey
  if (
    key.type !== "secret" ||
    key.extractable !== false ||
    key.algorithm?.name !== "AES-GCM" ||
    !key.usages?.includes("encrypt") ||
    !key.usages?.includes("decrypt")
  ) {
    return invalidStoredCredential()
  }
  return key
}

function wrapAad(record: {
  apiBaseUrl: string
  accountId: string
  deviceId: string
}): ArrayBuffer {
  return new TextEncoder()
    .encode(
      `${AAD_DOMAIN}\0${record.apiBaseUrl}\0${record.accountId}\0${record.deviceId}`,
    )
    .slice().buffer
}

function recordKey(apiBaseUrl: string, accountId: string): string {
  return `${apiBaseUrl}\0${accountId}`
}

function requireUuid(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    !UUID.test(value) ||
    value.toLowerCase() === NIL_UUID
  ) {
    throw new SyncClientError("invalid_contract", `The ${label} is invalid.`)
  }
  return value.toLowerCase()
}

function invalidStoredCredential(): never {
  throw new SyncClientError(
    "invalid_response",
    "The persisted sync credential is invalid.",
  )
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(WRAPPING_STORE)) db.createObjectStore(WRAPPING_STORE)
      if (!db.objectStoreNames.contains(CREDENTIAL_STORE)) {
        db.createObjectStore(CREDENTIAL_STORE, { keyPath: "key" })
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(asError(request.error, "sync credential database open failed"))
  })
}

async function generateWrappingKey(): Promise<CryptoKey> {
  return validateWrappingKey(await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  ))
}

async function getOrCreateWrappingKey(): Promise<CryptoKey> {
  const candidate = await generateWrappingKey()
  const db = await openDb()
  return new Promise<CryptoKey>((resolve, reject) => {
    let selected: CryptoKey | null = null
    let settled = false
    const tx = db.transaction(WRAPPING_STORE, "readwrite")
    const store = tx.objectStore(WRAPPING_STORE)
    const fail = (error: unknown) => {
      if (settled) return
      settled = true
      db.close()
      reject(asError(error, "sync credential wrapping-key transaction failed"))
    }
    tx.onabort = () => fail(tx.error)
    tx.onerror = () => fail(tx.error)
    tx.oncomplete = () => {
      if (settled) return
      if (selected === null) {
        fail(new Error("sync credential wrapping-key transaction completed without a key"))
        return
      }
      settled = true
      db.close()
      resolve(selected)
    }
    const read = store.get(WRAPPING_KEY_ID)
    read.onerror = () => fail(read.error)
    read.onsuccess = () => {
      try {
        if (read.result !== undefined) {
          selected = validateWrappingKey(read.result)
          return
        }
        selected = candidate
        const write = store.add(candidate, WRAPPING_KEY_ID)
        write.onerror = () => fail(write.error)
      } catch (error) {
        try {
          tx.abort()
        } catch {
          // The transaction may already be stopping.
        }
        fail(error)
      }
    }
  })
}

async function writeCredential(record: StoredSyncCredentialV1): Promise<void> {
  await requestWithTransaction("readwrite", (store) => store.put(record))
}

async function readCredential(key: string): Promise<StoredSyncCredentialV1 | null> {
  const result = await requestWithTransaction<unknown>("readonly", (store) => store.get(key))
  return result === undefined ? null : validateStoredCredential(result)
}

async function deleteCredential(key: string): Promise<void> {
  await requestWithTransaction("readwrite", (store) => store.delete(key))
}

function requestWithTransaction<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        let result: T | undefined
        let succeeded = false
        let settled = false
        const tx = db.transaction(CREDENTIAL_STORE, mode)
        const fail = (error: unknown) => {
          if (settled) return
          settled = true
          db.close()
          reject(asError(error, "sync credential transaction failed"))
        }
        tx.onabort = () => fail(tx.error)
        tx.onerror = () => fail(tx.error)
        tx.oncomplete = () => {
          if (settled) return
          if (!succeeded) {
            fail(new Error("sync credential transaction completed before its request"))
            return
          }
          settled = true
          db.close()
          resolve(result as T)
        }
        let request: IDBRequest<T>
        try {
          request = run(tx.objectStore(CREDENTIAL_STORE))
        } catch (error) {
          fail(error)
          return
        }
        request.onerror = () => fail(request.error)
        request.onsuccess = () => {
          succeeded = true
          result = request.result
        }
      }),
  )
}

function asError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback)
}
