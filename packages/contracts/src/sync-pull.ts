import {
  SyncClient,
  SyncClientError,
  type SyncObjectMetadataV1,
} from "./sync-client"

const DB_NAME = "safeory-sync-pull"
const DB_VERSION = 1
const CURSOR_STORE = "cursors"
const RECORD_FORMAT = 1
const MAX_PAGE_SIZE = 256
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"

export interface SyncCursorStore {
  load(accountId: string): Promise<number>
  advance(accountId: string, expectedCursor: number, nextCursor: number): Promise<void>
}

export interface PulledOpaqueObject {
  metadata: SyncObjectMetadataV1
  ciphertext: Uint8Array
}

export type AcceptPulledObject = (object: PulledOpaqueObject) => Promise<void>

export interface SyncPullResult {
  accepted: number
  cursor: number
}

interface StoredCursorRecord {
  format: number
  account_id: string
  cursor: number
}

/**
 * Pulls one bounded page and advances its durable cursor only after each
 * ciphertext has been verified by SyncClient and durably accepted by the
 * application callback. The callback must be idempotent because a browser can
 * stop after acceptance but before the cursor transaction commits.
 */
export class DurableSyncPuller {
  readonly accountId: string

  constructor(
    accountId: string,
    private readonly store: SyncCursorStore = new IndexedDbSyncCursorStore(),
  ) {
    this.accountId = requireUuid(accountId, "account ID")
  }

  async pullPage(
    client: SyncClient,
    accept: AcceptPulledObject,
    options: { limit?: number; signal?: AbortSignal } = {},
  ): Promise<SyncPullResult> {
    const limit = options.limit ?? 100
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) {
      throw new SyncClientError(
        "invalid_contract",
        `The sync pull limit must be between 1 and ${MAX_PAGE_SIZE}.`,
      )
    }
    let cursor = requireCursor(await this.store.load(this.accountId), "saved cursor")
    const page = await client.listObjects({
      after: cursor,
      limit,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })

    let accepted = 0
    for (const metadata of page.objects) {
      if (options.signal?.aborted) {
        throw new SyncClientError("request_failed", "The sync pull was cancelled.")
      }
      const ciphertext = await client.getObject(
        metadata.object,
        options.signal === undefined ? {} : { signal: options.signal },
      )
      await accept({ metadata, ciphertext })
      await this.store.advance(this.accountId, cursor, metadata.change_seq)
      cursor = metadata.change_seq
      accepted += 1
    }

    if (cursor !== page.next_change_seq) {
      throw new SyncClientError(
        "invalid_response",
        "The accepted sync cursor does not match the response page.",
      )
    }
    return { accepted, cursor }
  }

  async cursor(): Promise<number> {
    return requireCursor(await this.store.load(this.accountId), "saved cursor")
  }
}

export class IndexedDbSyncCursorStore implements SyncCursorStore {
  async load(accountIdValue: string): Promise<number> {
    const accountId = requireUuid(accountIdValue, "account ID")
    const value = await requestWithTransaction<unknown>("readonly", (store) =>
      store.get(accountId),
    )
    return decodeCursor(value, accountId)
  }

  async advance(
    accountIdValue: string,
    expectedCursorValue: number,
    nextCursorValue: number,
  ): Promise<void> {
    const accountId = requireUuid(accountIdValue, "account ID")
    const expectedCursor = requireCursor(expectedCursorValue, "expected cursor")
    const nextCursor = requireCursor(nextCursorValue, "next cursor")
    if (nextCursor <= expectedCursor) {
      throw new SyncClientError(
        "invalid_contract",
        "The next sync cursor must advance.",
      )
    }

    const db = await openDb()
    return new Promise<void>((resolve, reject) => {
      let written = false
      let settled = false
      const tx = db.transaction(CURSOR_STORE, "readwrite")
      const store = tx.objectStore(CURSOR_STORE)
      const getRequest = store.get(accountId)
      const fail = (error: unknown) => {
        if (settled) return
        settled = true
        db.close()
        reject(asError(error, "indexeddb sync cursor transaction failed"))
      }
      tx.onabort = () => fail(tx.error)
      tx.onerror = () => fail(tx.error)
      tx.oncomplete = () => {
        if (settled) return
        if (!written) {
          fail(new Error("indexeddb sync cursor completed without a write"))
          return
        }
        settled = true
        db.close()
        resolve()
      }
      getRequest.onerror = () => fail(getRequest.error)
      getRequest.onsuccess = () => {
        let current: number
        try {
          current = decodeCursor(getRequest.result, accountId)
        } catch (error) {
          abort(tx, error, fail)
          return
        }
        if (current !== expectedCursor) {
          abort(
            tx,
            new SyncClientError(
              "precondition_failed",
              "The durable sync cursor changed in another browser context.",
            ),
            fail,
          )
          return
        }
        const putRequest = store.put({
          format: RECORD_FORMAT,
          account_id: accountId,
          cursor: nextCursor,
        } satisfies StoredCursorRecord)
        putRequest.onerror = () => fail(putRequest.error)
        putRequest.onsuccess = () => {
          written = true
        }
      }
    })
  }
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(CURSOR_STORE)) {
        db.createObjectStore(CURSOR_STORE, { keyPath: "account_id" })
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(asError(request.error, "indexeddb sync cursor open failed"))
  })
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
        const tx = db.transaction(CURSOR_STORE, mode)
        const fail = (error: unknown) => {
          if (settled) return
          settled = true
          db.close()
          reject(asError(error, "indexeddb sync cursor transaction failed"))
        }
        tx.onabort = () => fail(tx.error)
        tx.onerror = () => fail(tx.error)
        tx.oncomplete = () => {
          if (settled) return
          if (!succeeded) {
            fail(new Error("indexeddb sync cursor completed before its request"))
            return
          }
          settled = true
          db.close()
          resolve(result as T)
        }
        let request: IDBRequest<T>
        try {
          request = run(tx.objectStore(CURSOR_STORE))
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

function decodeCursor(value: unknown, accountId: string): number {
  if (value === undefined) return 0
  if (typeof value !== "object" || value === null) invalidCursor()
  const record = value as Partial<StoredCursorRecord>
  if (
    record.format !== RECORD_FORMAT ||
    record.account_id !== accountId ||
    !Number.isSafeInteger(record.cursor) ||
    (record.cursor ?? -1) < 0
  ) {
    invalidCursor()
  }
  return record.cursor as number
}

function requireCursor(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new SyncClientError(
      "invalid_contract",
      `The ${label} is outside the exact browser integer range.`,
    )
  }
  return value
}

function requireUuid(value: string, label: string): string {
  if (!UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    throw new SyncClientError("invalid_contract", `The ${label} is invalid.`)
  }
  return value.toLowerCase()
}

function abort(
  tx: IDBTransaction,
  error: unknown,
  fail: (error: unknown) => void,
): void {
  try {
    tx.abort()
  } catch {
    // The transaction may already have been stopped by IndexedDB.
  }
  fail(error)
}

function invalidCursor(): never {
  throw new SyncClientError(
    "invalid_response",
    "The persisted sync cursor record is invalid.",
  )
}

function asError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback)
}
