import {
  SyncClient,
  SyncClientError,
  parseOpaqueMutation,
  verifyOpaqueCiphertext,
  type OpaqueMutationV1,
  type SyncObjectMetadataV1,
} from "./sync-client"

const DB_NAME = "safeory-sync"
const DB_VERSION = 1
const OUTBOX_STORE = "outbox"
const ACCOUNT_ORDER_INDEX = "account_order"
const RECORD_FORMAT = 1
const MAX_OUTBOX_ENTRIES = 256
const MAX_OUTBOX_BYTES = 256 * 1024 * 1024
const MAX_FLUSH_ENTRIES = 64
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"

export interface QueuedOpaqueMutation {
  mutation: OpaqueMutationV1
  ciphertext: Uint8Array
  queued_at_ms: number
}

export interface SyncOutboxStore {
  enqueue(accountId: string, entry: QueuedOpaqueMutation): Promise<boolean>
  list(accountId: string, limit: number): Promise<QueuedOpaqueMutation[]>
  acknowledge(accountId: string, operationId: string): Promise<void>
  count(accountId: string): Promise<number>
}

export interface SyncFlushResult {
  uploaded: SyncObjectMetadataV1[]
  remaining: number
}

interface StoredOutboxRecord {
  key: string
  format: number
  account_id: string
  operation_id: string
  queued_at_ms: number
  mutation: OpaqueMutationV1
  ciphertext: ArrayBuffer
  ciphertext_size_bytes: number
}

/**
 * Durable, credential-free push queue shared by browser application surfaces.
 *
 * A successful server write is acknowledged in a separate local transaction.
 * If the browser stops between those operations, the canonical operation ID
 * makes the next flush an idempotent replay.
 */
export class DurableSyncOutbox {
  readonly accountId: string

  constructor(
    accountId: string,
    private readonly store: SyncOutboxStore = new IndexedDbSyncOutboxStore(),
  ) {
    this.accountId = requireUuid(accountId, "account ID")
  }

  async enqueue(
    mutationValue: OpaqueMutationV1,
    ciphertextValue: Uint8Array,
    queuedAtMs = Date.now(),
  ): Promise<boolean> {
    const mutation = parseOpaqueMutation(mutationValue)
    requireAccount(mutation, this.accountId)
    if (!Number.isSafeInteger(queuedAtMs) || queuedAtMs < 0) {
      throw new SyncClientError(
        "invalid_contract",
        "The sync queue timestamp is invalid.",
      )
    }
    const ciphertext = Uint8Array.from(ciphertextValue)
    await verifyOpaqueCiphertext(mutation.object, ciphertext)
    return this.store.enqueue(this.accountId, {
      mutation,
      ciphertext,
      queued_at_ms: queuedAtMs,
    })
  }

  async flush(
    client: SyncClient,
    options: { limit?: number; signal?: AbortSignal } = {},
  ): Promise<SyncFlushResult> {
    const limit = options.limit ?? MAX_FLUSH_ENTRIES
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_FLUSH_ENTRIES) {
      throw new SyncClientError(
        "invalid_contract",
        `The sync flush limit must be between 1 and ${MAX_FLUSH_ENTRIES}.`,
      )
    }

    const entries = await this.store.list(this.accountId, limit)
    const uploaded: SyncObjectMetadataV1[] = []
    for (const entry of entries) {
      if (options.signal?.aborted) {
        throw new SyncClientError("request_failed", "The sync flush was cancelled.")
      }
      const metadata = await client.putObject(
        entry.mutation,
        entry.ciphertext,
        options.signal === undefined ? {} : { signal: options.signal },
      )
      await this.store.acknowledge(
        this.accountId,
        entry.mutation.operation_id,
      )
      uploaded.push(metadata)
    }
    return { uploaded, remaining: await this.store.count(this.accountId) }
  }

  pending(limit = MAX_FLUSH_ENTRIES): Promise<QueuedOpaqueMutation[]> {
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_OUTBOX_ENTRIES) {
      throw new SyncClientError(
        "invalid_contract",
        `The sync queue read limit must be between 1 and ${MAX_OUTBOX_ENTRIES}.`,
      )
    }
    return this.store.list(this.accountId, limit)
  }

  count(): Promise<number> {
    return this.store.count(this.accountId)
  }
}

export class IndexedDbSyncOutboxStore implements SyncOutboxStore {
  async enqueue(accountId: string, entry: QueuedOpaqueMutation): Promise<boolean> {
    const record = encodeRecord(accountId, entry)
    const db = await openDb()
    return new Promise<boolean>((resolve, reject) => {
      let result: boolean | null = null
      let settled = false
      const tx = db.transaction(OUTBOX_STORE, "readwrite")
      const store = tx.objectStore(OUTBOX_STORE)
      const existingRequest = store.get(record.key)

      const fail = (error: unknown) => {
        if (settled) return
        settled = true
        db.close()
        reject(asError(error, "indexeddb sync outbox transaction failed"))
      }
      tx.onabort = () => fail(tx.error)
      tx.onerror = () => fail(tx.error)
      tx.oncomplete = () => {
        if (settled) return
        if (result === null) {
          fail(new Error("indexeddb sync outbox completed without a result"))
          return
        }
        settled = true
        db.close()
        resolve(result)
      }

      existingRequest.onerror = () => fail(existingRequest.error)
      existingRequest.onsuccess = () => {
        if (existingRequest.result !== undefined) {
          try {
            const existing = decodeRecord(existingRequest.result)
            if (!sameEntry(existing, entry)) {
              throw new SyncClientError(
                "operation_conflict",
                "The operation ID is already queued with different input.",
              )
            }
            result = false
          } catch (error) {
            abort(tx, error, fail)
          }
          return
        }

        const range = accountRange(accountId)
        const cursorRequest = store.index(ACCOUNT_ORDER_INDEX).openCursor(range)
        let count = 0
        let bytes = 0
        cursorRequest.onerror = () => fail(cursorRequest.error)
        cursorRequest.onsuccess = () => {
          const cursor = cursorRequest.result
          if (cursor !== null) {
            const current = cursor.value as Partial<StoredOutboxRecord>
            count += 1
            bytes +=
              typeof current.ciphertext_size_bytes === "number"
                ? current.ciphertext_size_bytes
                : MAX_OUTBOX_BYTES + 1
            cursor.continue()
            return
          }
          if (count >= MAX_OUTBOX_ENTRIES) {
            abort(
              tx,
              new SyncClientError("request_failed", "The sync outbox is full."),
              fail,
            )
            return
          }
          if (bytes + entry.ciphertext.byteLength > MAX_OUTBOX_BYTES) {
            abort(
              tx,
              new SyncClientError(
                "request_failed",
                "The sync outbox ciphertext limit was reached.",
              ),
              fail,
            )
            return
          }
          const putRequest = store.add(record)
          putRequest.onerror = () => fail(putRequest.error)
          putRequest.onsuccess = () => {
            result = true
          }
        }
      }
    })
  }

  async list(accountId: string, limit: number): Promise<QueuedOpaqueMutation[]> {
    const records = await requestWithTransaction<StoredOutboxRecord[]>(
      "readonly",
      (store) =>
        store.index(ACCOUNT_ORDER_INDEX).getAll(accountRange(accountId), limit),
    )
    return Promise.all(records.map(decodeRecordAndVerify))
  }

  async acknowledge(accountId: string, operationId: string): Promise<void> {
    const key = recordKey(accountId, requireUuid(operationId, "operation ID"))
    await requestWithTransaction("readwrite", (store) => store.delete(key))
  }

  count(accountId: string): Promise<number> {
    return requestWithTransaction("readonly", (store) =>
      store.index(ACCOUNT_ORDER_INDEX).count(accountRange(accountId)),
    )
  }
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(OUTBOX_STORE)) {
        const store = db.createObjectStore(OUTBOX_STORE, { keyPath: "key" })
        store.createIndex(
          ACCOUNT_ORDER_INDEX,
          ["account_id", "queued_at_ms", "operation_id"],
          { unique: false },
        )
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(asError(request.error, "indexeddb sync open failed"))
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
        const tx = db.transaction(OUTBOX_STORE, mode)
        const fail = (error: unknown) => {
          if (settled) return
          settled = true
          db.close()
          reject(asError(error, "indexeddb sync transaction failed"))
        }
        tx.onabort = () => fail(tx.error)
        tx.onerror = () => fail(tx.error)
        tx.oncomplete = () => {
          if (settled) return
          if (!succeeded) {
            fail(new Error("indexeddb sync transaction completed before its request"))
            return
          }
          settled = true
          db.close()
          resolve(result as T)
        }
        let request: IDBRequest<T>
        try {
          request = run(tx.objectStore(OUTBOX_STORE))
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

function encodeRecord(
  accountId: string,
  entry: QueuedOpaqueMutation,
): StoredOutboxRecord {
  const operationId = entry.mutation.operation_id
  const ciphertext = entry.ciphertext.buffer.slice(
    entry.ciphertext.byteOffset,
    entry.ciphertext.byteOffset + entry.ciphertext.byteLength,
  ) as ArrayBuffer
  return {
    key: recordKey(accountId, operationId),
    format: RECORD_FORMAT,
    account_id: accountId,
    operation_id: operationId,
    queued_at_ms: entry.queued_at_ms,
    mutation: entry.mutation,
    ciphertext,
    ciphertext_size_bytes: entry.ciphertext.byteLength,
  }
}

function decodeRecord(value: unknown): QueuedOpaqueMutation {
  if (typeof value !== "object" || value === null) invalidQueueRecord()
  const record = value as Partial<StoredOutboxRecord>
  if (
    record.format !== RECORD_FORMAT ||
    typeof record.account_id !== "string" ||
    typeof record.operation_id !== "string" ||
    typeof record.key !== "string" ||
    !Number.isSafeInteger(record.queued_at_ms) ||
    (record.queued_at_ms ?? -1) < 0 ||
    !(record.ciphertext instanceof ArrayBuffer) ||
    record.ciphertext_size_bytes !== record.ciphertext.byteLength
  ) {
    invalidQueueRecord()
  }
  const accountId = requireUuid(record.account_id, "queued account ID")
  const operationId = requireUuid(record.operation_id, "queued operation ID")
  const mutation = parseOpaqueMutation(record.mutation)
  if (
    record.key !== recordKey(accountId, operationId) ||
    mutation.operation_id.toLowerCase() !== operationId
  ) {
    invalidQueueRecord()
  }
  requireAccount(mutation, accountId)
  return {
    mutation,
    ciphertext: new Uint8Array(record.ciphertext.slice(0)),
    queued_at_ms: record.queued_at_ms as number,
  }
}

async function decodeRecordAndVerify(value: unknown): Promise<QueuedOpaqueMutation> {
  const entry = decodeRecord(value)
  await verifyOpaqueCiphertext(entry.mutation.object, entry.ciphertext)
  return entry
}

function requireAccount(mutation: OpaqueMutationV1, accountId: string): void {
  if (mutation.object.scope.account_id.toLowerCase() !== accountId.toLowerCase()) {
    throw new SyncClientError(
      "invalid_contract",
      "The queued opaque object does not belong to this account.",
    )
  }
}

function requireUuid(value: string, label: string): string {
  if (!UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    throw new SyncClientError("invalid_contract", `The ${label} is invalid.`)
  }
  return value.toLowerCase()
}

function recordKey(accountId: string, operationId: string): string {
  return `${accountId.toLowerCase()}:${operationId.toLowerCase()}`
}

function accountRange(accountId: string): IDBKeyRange {
  return IDBKeyRange.bound(
    [accountId, 0, ""],
    [accountId, Number.MAX_SAFE_INTEGER, "\uffff"],
  )
}

function sameEntry(left: QueuedOpaqueMutation, right: QueuedOpaqueMutation): boolean {
  return (
    JSON.stringify(left.mutation) === JSON.stringify(right.mutation) &&
    left.ciphertext.byteLength === right.ciphertext.byteLength &&
    left.ciphertext.every((byte, index) => byte === right.ciphertext[index])
  )
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

function invalidQueueRecord(): never {
  throw new SyncClientError(
    "invalid_response",
    "The persisted sync outbox record is invalid.",
  )
}

function asError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback)
}
