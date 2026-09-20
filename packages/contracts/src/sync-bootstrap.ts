import {
  normalizeSyncApiBaseUrl,
  type ObjectScopeV1,
} from "./sync-client"
import {
  parseSingleOwnerMigration,
  type HouseholdTopologyV1,
  type SingleOwnerMigrationV1,
} from "./sync-domain"
import { SyncClientError } from "./sync-error"

const DB_NAME = "safeory-sync-bootstrap"
const DB_VERSION = 1
const STORE = "single_owner"
const RECORD_FORMAT = 1
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"
const MAX_GENERATION_ATTEMPTS = 32

export type SyncBootstrapPublication = "draft" | "published"

export interface SingleOwnerSyncBootstrapState {
  version: number
  apiBaseUrl: string
  accountId: string
  deviceId: string
  publication: SyncBootstrapPublication
  migration: SingleOwnerMigrationV1
}

export interface SingleOwnerSyncBootstrapStore {
  load(key: string): Promise<SingleOwnerSyncBootstrapState | null>
  create(key: string, state: SingleOwnerSyncBootstrapState): Promise<SingleOwnerSyncBootstrapState>
  markPublished(key: string, expectedVersion: number): Promise<SingleOwnerSyncBootstrapState>
}

export interface HouseholdTopologyPublisher {
  readonly accountId: string
  readonly deviceId: string | null
  putHouseholdTopology(topology: HouseholdTopologyV1): Promise<void>
}

interface StoredBootstrapRecord {
  key: string
  format: number
  version: number
  api_base_url: string
  account_id: string
  device_id: string
  publication: SyncBootstrapPublication
  migration: SingleOwnerMigrationV1
}

export function createSingleOwnerMigration(
  accountIdValue: string,
  deviceIdValue: string,
  existingObjectIdsValue: readonly string[],
  randomUuid: () => string = () => globalThis.crypto.randomUUID(),
): SingleOwnerMigrationV1 {
  const accountId = uuid(accountIdValue, "account ID")
  const deviceId = uuid(deviceIdValue, "device ID")
  const existingObjectIds = existingObjectIdsValue.map((value) => uuid(value, "object ID"))
  if (new Set(existingObjectIds).size !== existingObjectIds.length) {
    throw new SyncClientError("invalid_contract", "The existing vault object IDs contain a duplicate.")
  }
  const used = new Set([accountId, deviceId, ...existingObjectIds])
  const nextId = (): string => {
    for (let attempt = 0; attempt < MAX_GENERATION_ATTEMPTS; attempt += 1) {
      const candidate = uuid(randomUuid(), "generated topology ID")
      if (!used.has(candidate)) {
        used.add(candidate)
        return candidate
      }
    }
    throw new SyncClientError(
      "invalid_configuration",
      "Unable to generate a unique sync topology identifier.",
    )
  }

  const householdId = nextId()
  const membershipId = nextId()
  const spaceId = nextId()
  const profileObjectId = nextId()
  const manifestObjectId = nextId()
  const envelopeObjectId = nextId()
  return parseSingleOwnerMigration({
    format_version: 1,
    topology: {
      format_version: 1,
      accounts: [
        {
          format_version: 1,
          account_id: accountId,
          household_ids: [householdId],
          device_ids: [deviceId],
        },
      ],
      household: {
        format_version: 1,
        household_id: householdId,
        encrypted_profile_object_id: profileObjectId,
        membership_ids: [membershipId],
        space_ids: [spaceId],
        revision: 0,
      },
      memberships: [
        {
          format_version: 1,
          membership_id: membershipId,
          account_id: accountId,
          household_id: householdId,
          role: "owner",
          state: "active",
          revision: 0,
        },
      ],
      spaces: [
        {
          format_version: 1,
          space_id: spaceId,
          household_id: householdId,
          kind: "private",
          encrypted_manifest_object_id: manifestObjectId,
          key_generation: 1,
          revision: 0,
        },
      ],
      space_members: [
        {
          format_version: 1,
          space_id: spaceId,
          membership_id: membershipId,
          access: "manage",
          envelope_object_id: envelopeObjectId,
          device_id: deviceId,
          key_generation: 1,
          revision: 0,
        },
      ],
    },
    private_space_id: spaceId,
    object_assignments: existingObjectIds.map((objectId) => ({
      object_id: objectId,
      space_id: spaceId,
    })),
  })
}

/**
 * Persists random topology identifiers before network publication. Retrying
 * after interruption therefore republishes byte-for-byte identical topology
 * instead of creating a second household or private space.
 */
export class BrowserSingleOwnerSyncBootstrap {
  readonly apiBaseUrl: string
  readonly accountId: string
  readonly deviceId: string
  private readonly key: string

  constructor(
    apiBaseUrlValue: string,
    accountIdValue: string,
    deviceIdValue: string,
    private readonly store: SingleOwnerSyncBootstrapStore =
      new IndexedDbSingleOwnerSyncBootstrapStore(),
  ) {
    this.apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    this.accountId = uuid(accountIdValue, "account ID")
    this.deviceId = uuid(deviceIdValue, "device ID")
    this.key = bootstrapKey(this.apiBaseUrl, this.accountId)
  }

  async prepare(
    existingObjectIds: readonly string[],
    randomUuid?: () => string,
  ): Promise<SingleOwnerSyncBootstrapState> {
    const existing = await this.store.load(this.key)
    if (existing !== null) return this.requireBinding(existing)
    const migration = createSingleOwnerMigration(
      this.accountId,
      this.deviceId,
      existingObjectIds,
      randomUuid,
    )
    const state: SingleOwnerSyncBootstrapState = {
      version: 1,
      apiBaseUrl: this.apiBaseUrl,
      accountId: this.accountId,
      deviceId: this.deviceId,
      publication: "draft",
      migration,
    }
    return this.requireBinding(await this.store.create(this.key, state))
  }

  async publish(
    publisher: HouseholdTopologyPublisher,
    existingObjectIds: readonly string[],
    randomUuid?: () => string,
  ): Promise<SingleOwnerSyncBootstrapState> {
    if (publisher.accountId !== this.accountId || publisher.deviceId !== this.deviceId) {
      throw new SyncClientError(
        "invalid_configuration",
        "The sync topology publisher does not match the bootstrap account and device.",
      )
    }
    const state = await this.prepare(existingObjectIds, randomUuid)
    if (state.publication === "published") return state
    await publisher.putHouseholdTopology(state.migration.topology)
    try {
      return this.requireBinding(await this.store.markPublished(this.key, state.version))
    } catch (error) {
      const latest = await this.store.load(this.key)
      if (latest?.publication === "published") return this.requireBinding(latest)
      throw error
    }
  }

  async load(): Promise<SingleOwnerSyncBootstrapState | null> {
    const state = await this.store.load(this.key)
    return state === null ? null : this.requireBinding(state)
  }

  scope(stateValue: SingleOwnerSyncBootstrapState): ObjectScopeV1 {
    const state = this.requireBinding(stateValue)
    return {
      scope: "space",
      account_id: this.accountId,
      household_id: state.migration.topology.household.household_id,
      space_id: state.migration.private_space_id,
    }
  }

  private requireBinding(stateValue: SingleOwnerSyncBootstrapState): SingleOwnerSyncBootstrapState {
    const state = validateState(stateValue)
    if (
      state.apiBaseUrl !== this.apiBaseUrl ||
      state.accountId !== this.accountId ||
      state.deviceId !== this.deviceId
    ) {
      throw new SyncClientError(
        "invalid_response",
        "The persisted sync bootstrap belongs to a different API, account, or device.",
      )
    }
    return state
  }
}

export class IndexedDbSingleOwnerSyncBootstrapStore implements SingleOwnerSyncBootstrapStore {
  async load(key: string): Promise<SingleOwnerSyncBootstrapState | null> {
    const value = await requestWithTransaction<unknown>("readonly", (store) => store.get(key))
    return value === undefined ? null : decodeRecord(value, key)
  }

  async create(
    key: string,
    stateValue: SingleOwnerSyncBootstrapState,
  ): Promise<SingleOwnerSyncBootstrapState> {
    const state = validateState(stateValue)
    const record = encodeRecord(key, state)
    const db = await openDb()
    return new Promise((resolve, reject) => {
      let settled = false
      let result: SingleOwnerSyncBootstrapState | null = null
      const tx = db.transaction(STORE, "readwrite")
      const store = tx.objectStore(STORE)
      const read = store.get(key)
      const fail = (error: unknown) => {
        if (settled) return
        settled = true
        db.close()
        reject(asError(error, "indexeddb sync bootstrap transaction failed"))
      }
      tx.onabort = () => fail(tx.error)
      tx.onerror = () => fail(tx.error)
      tx.oncomplete = () => {
        if (settled) return
        if (result === null) {
          fail(new Error("indexeddb sync bootstrap completed without a result"))
          return
        }
        settled = true
        db.close()
        resolve(result)
      }
      read.onerror = () => fail(read.error)
      read.onsuccess = () => {
        if (read.result !== undefined) {
          try {
            result = decodeRecord(read.result, key)
          } catch (error) {
            abort(tx, error, fail)
          }
          return
        }
        const write = store.add(record)
        write.onerror = () => fail(write.error)
        write.onsuccess = () => {
          result = state
        }
      }
    })
  }

  async markPublished(
    key: string,
    expectedVersionValue: number,
  ): Promise<SingleOwnerSyncBootstrapState> {
    const expectedVersion = wireInteger(expectedVersionValue, "bootstrap version")
    const db = await openDb()
    return new Promise((resolve, reject) => {
      let settled = false
      let result: SingleOwnerSyncBootstrapState | null = null
      const tx = db.transaction(STORE, "readwrite")
      const store = tx.objectStore(STORE)
      const read = store.get(key)
      const fail = (error: unknown) => {
        if (settled) return
        settled = true
        db.close()
        reject(asError(error, "indexeddb sync bootstrap transaction failed"))
      }
      tx.onabort = () => fail(tx.error)
      tx.onerror = () => fail(tx.error)
      tx.oncomplete = () => {
        if (settled) return
        if (result === null) {
          fail(new Error("indexeddb sync bootstrap completed without publication"))
          return
        }
        settled = true
        db.close()
        resolve(result)
      }
      read.onerror = () => fail(read.error)
      read.onsuccess = () => {
        let current: SingleOwnerSyncBootstrapState
        try {
          if (read.result === undefined) invalidStored()
          current = decodeRecord(read.result, key)
        } catch (error) {
          abort(tx, error, fail)
          return
        }
        if (current.version !== expectedVersion) {
          abort(
            tx,
            new SyncClientError(
              "precondition_failed",
              "The sync bootstrap changed in another browser context.",
            ),
            fail,
          )
          return
        }
        if (current.publication === "published") {
          result = current
          return
        }
        if (current.version === Number.MAX_SAFE_INTEGER) {
          abort(
            tx,
            new SyncClientError("invalid_contract", "The sync bootstrap version is exhausted."),
            fail,
          )
          return
        }
        result = { ...current, version: current.version + 1, publication: "published" }
        const write = store.put(encodeRecord(key, result))
        write.onerror = () => fail(write.error)
      }
    })
  }
}

function validateState(value: SingleOwnerSyncBootstrapState): SingleOwnerSyncBootstrapState {
  if (typeof value !== "object" || value === null) invalidStored()
  const version = wireInteger(value.version, "bootstrap version")
  if (version === 0) invalidStored()
  const apiBaseUrl = normalizeSyncApiBaseUrl(value.apiBaseUrl)
  const accountId = uuid(value.accountId, "bootstrap account ID")
  const deviceId = uuid(value.deviceId, "bootstrap device ID")
  if (value.publication !== "draft" && value.publication !== "published") invalidStored()
  const migration = parseSingleOwnerMigration(value.migration)
  if (
    migration.topology.accounts.length !== 1 ||
    migration.topology.accounts[0]?.account_id !== accountId ||
    !migration.topology.accounts[0]?.device_ids.includes(deviceId)
  ) {
    invalidStored()
  }
  return {
    version,
    apiBaseUrl,
    accountId,
    deviceId,
    publication: value.publication,
    migration,
  }
}

function encodeRecord(key: string, state: SingleOwnerSyncBootstrapState): StoredBootstrapRecord {
  return {
    key,
    format: RECORD_FORMAT,
    version: state.version,
    api_base_url: state.apiBaseUrl,
    account_id: state.accountId,
    device_id: state.deviceId,
    publication: state.publication,
    migration: state.migration,
  }
}

function decodeRecord(value: unknown, key: string): SingleOwnerSyncBootstrapState {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalidStored()
  const record = value as Partial<StoredBootstrapRecord>
  if (
    record.key !== key ||
    record.format !== RECORD_FORMAT ||
    !hasExactKeys(record, [
      "key",
      "format",
      "version",
      "api_base_url",
      "account_id",
      "device_id",
      "publication",
      "migration",
    ])
  ) {
    invalidStored()
  }
  return validateState({
    version: record.version as number,
    apiBaseUrl: record.api_base_url as string,
    accountId: record.account_id as string,
    deviceId: record.device_id as string,
    publication: record.publication as SyncBootstrapPublication,
    migration: record.migration as SingleOwnerMigrationV1,
  })
}

function hasExactKeys(record: object, expected: readonly string[]): boolean {
  const actual = Object.keys(record)
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(record, key))
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: "key" })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(asError(request.error, "indexeddb sync bootstrap open failed"))
  })
}

function requestWithTransaction<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        let settled = false
        let succeeded = false
        let result: T | undefined
        const tx = db.transaction(STORE, mode)
        const fail = (error: unknown) => {
          if (settled) return
          settled = true
          db.close()
          reject(asError(error, "indexeddb sync bootstrap transaction failed"))
        }
        tx.onabort = () => fail(tx.error)
        tx.onerror = () => fail(tx.error)
        tx.oncomplete = () => {
          if (settled) return
          if (!succeeded) {
            fail(new Error("indexeddb sync bootstrap completed before its request"))
            return
          }
          settled = true
          db.close()
          resolve(result as T)
        }
        let request: IDBRequest<T>
        try {
          request = run(tx.objectStore(STORE))
        } catch (error) {
          abort(tx, error, fail)
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

function bootstrapKey(apiBaseUrl: string, accountId: string): string {
  return `${apiBaseUrl}|${accountId}`
}

function uuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    throw new SyncClientError("invalid_contract", `The ${label} is invalid.`)
  }
  return value.toLowerCase()
}

function wireInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new SyncClientError("invalid_contract", `The ${label} is invalid.`)
  }
  return value as number
}

function invalidStored(): never {
  throw new SyncClientError("invalid_response", "The persisted sync bootstrap is invalid.")
}

function abort(
  tx: IDBTransaction,
  error: unknown,
  fail: (error: unknown) => void,
): void {
  try {
    tx.abort()
  } catch {
    // The transaction may already have stopped.
  }
  fail(error)
}

function asError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback)
}
