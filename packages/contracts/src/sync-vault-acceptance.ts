import {
  parseOpaqueObjectHeader,
  verifyOpaqueCiphertext,
  type OpaqueObjectHeaderV1,
} from "./sync-client"
import { SyncClientError } from "./sync-error"
import type { AcceptPulledObject, PulledOpaqueObject } from "./sync-pull"
import {
  decodePulledVaultItem,
  parseEncryptedVaultItem,
  reconcilePulledVaultItem,
  type EncryptedVaultItemV1,
  type VaultItemReconciliation,
} from "./sync-vault-item"

const DB_NAME = "safeory-sync-item-state"
const DB_VERSION = 1
const STORE = "item_state"
const RECORD_FORMAT = 1
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"

export interface VaultItemConflictCandidate {
  remoteHeader: OpaqueObjectHeaderV1
  remoteCiphertext: Uint8Array
}

export interface VaultItemSyncState {
  version: number
  baseline: OpaqueObjectHeaderV1 | null
  conflict: VaultItemConflictCandidate | null
}

export interface VaultItemSyncStateStore {
  load(accountId: string, objectId: string): Promise<VaultItemSyncState>
  commit(
    accountId: string,
    objectId: string,
    expectedVersion: number,
    next: Omit<VaultItemSyncState, "version">,
  ): Promise<number>
}

export interface VaultItemAcceptanceResult {
  reconciliation: VaultItemReconciliation
  stateVersion: number
}

export type LoadLocalEncryptedItem = (objectId: string) => Promise<unknown | null>
export type ApplyRemoteEncryptedItem = (
  item: EncryptedVaultItemV1,
  expectedLocal: EncryptedVaultItemV1 | null,
) => Promise<void>

interface StoredItemSyncState {
  key: string
  format: number
  account_id: string
  object_id: string
  version: number
  baseline: OpaqueObjectHeaderV1 | null
  conflict_header: OpaqueObjectHeaderV1 | null
  conflict_ciphertext: ArrayBuffer | null
}

/**
 * Durable pull-acceptance coordinator for encrypted vault items.
 *
 * Remote application happens before the accepted baseline is advanced. If the
 * browser stops between those steps, replay observes the already-applied local
 * ciphertext and safely repairs the baseline. Concurrent candidates are stored
 * without replacing the local record, after which the pull cursor may advance.
 */
export class DurableVaultItemAcceptor {
  readonly accountId: string

  constructor(
    accountIdValue: string,
    private readonly store: VaultItemSyncStateStore = new IndexedDbVaultItemSyncStateStore(),
  ) {
    this.accountId = uuid(accountIdValue, "account ID")
  }

  async accept(
    pulled: PulledOpaqueObject,
    loadLocal: LoadLocalEncryptedItem,
    applyRemote: ApplyRemoteEncryptedItem,
  ): Promise<VaultItemAcceptanceResult> {
    const decoded = await decodePulledVaultItem(pulled.metadata, pulled.ciphertext)
    const objectId = decoded.metadata.object.object_id
    const state = await this.store.load(this.accountId, objectId)
    const localValue = await loadLocal(objectId)
    const reconciliation = await reconcilePulledVaultItem(
      localValue,
      state.baseline,
      decoded,
    )

    if (reconciliation.action === "apply_remote") {
      const expectedLocal = localValue === null ? null : parseEncryptedVaultItem(localValue)
      await applyRemote(reconciliation.item, expectedLocal)
      const stateVersion = await this.store.commit(
        this.accountId,
        objectId,
        state.version,
        { baseline: reconciliation.baseline, conflict: null },
      )
      return { reconciliation, stateVersion }
    }

    if (reconciliation.action === "unchanged") {
      const stateVersion = await this.store.commit(
        this.accountId,
        objectId,
        state.version,
        { baseline: reconciliation.baseline, conflict: null },
      )
      return { reconciliation, stateVersion }
    }

    if (reconciliation.action === "conflict") {
      const stateVersion = await this.store.commit(
        this.accountId,
        objectId,
        state.version,
        {
          baseline: reconciliation.baseline,
          conflict: {
            remoteHeader: reconciliation.remoteHeader,
            remoteCiphertext: decoded.ciphertext,
          },
        },
      )
      return { reconciliation, stateVersion }
    }

    return { reconciliation, stateVersion: state.version }
  }

  state(objectIdValue: string): Promise<VaultItemSyncState> {
    return this.store.load(this.accountId, uuid(objectIdValue, "object ID"))
  }

  callback(
    loadLocal: LoadLocalEncryptedItem,
    applyRemote: ApplyRemoteEncryptedItem,
  ): AcceptPulledObject {
    return async (pulled) => {
      await this.accept(pulled, loadLocal, applyRemote)
    }
  }
}

export class IndexedDbVaultItemSyncStateStore implements VaultItemSyncStateStore {
  async load(accountIdValue: string, objectIdValue: string): Promise<VaultItemSyncState> {
    const accountId = uuid(accountIdValue, "account ID")
    const objectId = uuid(objectIdValue, "object ID")
    const value = await requestWithTransaction<unknown>("readonly", (store) =>
      store.get(recordKey(accountId, objectId)),
    )
    return decodeState(value, accountId, objectId)
  }

  async commit(
    accountIdValue: string,
    objectIdValue: string,
    expectedVersionValue: number,
    next: Omit<VaultItemSyncState, "version">,
  ): Promise<number> {
    const accountId = uuid(accountIdValue, "account ID")
    const objectId = uuid(objectIdValue, "object ID")
    const expectedVersion = wireInteger(expectedVersionValue, "expected item sync state version")
    const baseline = next.baseline === null ? null : validateItemHeader(next.baseline, objectId)
    const conflict = await validateConflict(next.conflict, objectId)
    validateStateRelationship(baseline, conflict)
    const db = await openDb()

    return new Promise<number>((resolve, reject) => {
      let settled = false
      let nextVersion: number | null = null
      const tx = db.transaction(STORE, "readwrite")
      const store = tx.objectStore(STORE)
      const read = store.get(recordKey(accountId, objectId))
      const fail = (error: unknown) => {
        if (settled) return
        settled = true
        db.close()
        reject(asError(error, "indexeddb vault item sync state transaction failed"))
      }
      tx.onabort = () => fail(tx.error)
      tx.onerror = () => fail(tx.error)
      tx.oncomplete = () => {
        if (settled) return
        if (nextVersion === null) {
          fail(new Error("indexeddb vault item sync state completed without a write"))
          return
        }
        settled = true
        db.close()
        resolve(nextVersion)
      }
      read.onerror = () => fail(read.error)
      read.onsuccess = () => {
        let current: VaultItemSyncState
        try {
          current = decodeStateShape(read.result, accountId, objectId)
        } catch (error) {
          abort(tx, error, fail)
          return
        }
        if (current.version !== expectedVersion) {
          abort(
            tx,
            new SyncClientError(
              "precondition_failed",
              "The durable vault item sync state changed in another browser context.",
            ),
            fail,
          )
          return
        }
        if (expectedVersion === Number.MAX_SAFE_INTEGER) {
          abort(tx, new SyncClientError("invalid_contract", "The item sync state is exhausted."), fail)
          return
        }
        nextVersion = expectedVersion + 1
        const ciphertext = conflict?.remoteCiphertext.slice().buffer ?? null
        const write = store.put({
          key: recordKey(accountId, objectId),
          format: RECORD_FORMAT,
          account_id: accountId,
          object_id: objectId,
          version: nextVersion,
          baseline,
          conflict_header: conflict?.remoteHeader ?? null,
          conflict_ciphertext: ciphertext,
        } satisfies StoredItemSyncState)
        write.onerror = () => fail(write.error)
      }
    })
  }
}

async function decodeState(
  value: unknown,
  accountId: string,
  objectId: string,
): Promise<VaultItemSyncState> {
  const state = decodeStateShape(value, accountId, objectId)
  if (state.conflict !== null) {
    await verifyOpaqueCiphertext(
      state.conflict.remoteHeader,
      state.conflict.remoteCiphertext,
    )
    await decodePulledVaultItem(
      { object: state.conflict.remoteHeader, change_seq: 1, etag: "persisted-conflict" },
      state.conflict.remoteCiphertext,
    )
  }
  return state
}

function decodeStateShape(
  value: unknown,
  accountId: string,
  objectId: string,
): VaultItemSyncState {
  if (value === undefined) return { version: 0, baseline: null, conflict: null }
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalidState()
  const record = value as Partial<StoredItemSyncState>
  if (
    record.key !== recordKey(accountId, objectId) ||
    record.format !== RECORD_FORMAT ||
    record.account_id !== accountId ||
    record.object_id !== objectId
  ) {
    invalidState()
  }
  const version = wireInteger(record.version, "persisted item sync state version")
  const baseline = record.baseline === null
    ? null
    : validateItemHeader(record.baseline, objectId)
  let conflict: VaultItemConflictCandidate | null = null
  if (record.conflict_header === null && record.conflict_ciphertext === null) {
    conflict = null
  } else if (
    record.conflict_header !== null &&
    record.conflict_header !== undefined &&
    record.conflict_ciphertext instanceof ArrayBuffer
  ) {
    conflict = {
      remoteHeader: validateItemHeader(record.conflict_header, objectId),
      remoteCiphertext: new Uint8Array(record.conflict_ciphertext.slice(0)),
    }
  } else {
    invalidState()
  }
  validateStateRelationship(baseline, conflict)
  return { version, baseline, conflict }
}

async function validateConflict(
  value: VaultItemConflictCandidate | null,
  objectId: string,
): Promise<VaultItemConflictCandidate | null> {
  if (value === null) return null
  const remoteHeader = validateItemHeader(value.remoteHeader, objectId)
  const remoteCiphertext = Uint8Array.from(value.remoteCiphertext)
  await decodePulledVaultItem(
    { object: remoteHeader, change_seq: 1, etag: "conflict-candidate" },
    remoteCiphertext,
  )
  return { remoteHeader, remoteCiphertext }
}

function validateItemHeader(value: unknown, objectId: string): OpaqueObjectHeaderV1 {
  const header = parseOpaqueObjectHeader(value)
  if (header.class !== "item" || header.object_id !== objectId) invalidState()
  return header
}

function validateStateRelationship(
  baseline: OpaqueObjectHeaderV1 | null,
  conflict: VaultItemConflictCandidate | null,
): void {
  if (
    baseline !== null &&
    conflict !== null &&
    (JSON.stringify(baseline.scope) !== JSON.stringify(conflict.remoteHeader.scope) ||
      conflict.remoteHeader.revision <= baseline.revision)
  ) {
    invalidState()
  }
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: "key" })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(asError(request.error, "indexeddb vault item sync state open failed"))
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
          reject(asError(error, "indexeddb vault item sync state transaction failed"))
        }
        tx.onabort = () => fail(tx.error)
        tx.onerror = () => fail(tx.error)
        tx.oncomplete = () => {
          if (settled) return
          if (!succeeded) {
            fail(new Error("indexeddb vault item sync state completed before its request"))
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

function recordKey(accountId: string, objectId: string): string {
  return `${accountId}:${objectId}`
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

function invalidState(): never {
  throw new SyncClientError("invalid_response", "The persisted vault item sync state is invalid.")
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
