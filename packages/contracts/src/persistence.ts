/**
 * Browser persistence for the vault ciphertext snapshot.
 *
 * Only the encrypted `KVSnapshot` (opaque envelopes + minimal metadata) is
 * stored in IndexedDB. No plaintext vault data and no vault keys ever touch
 * this layer — the WASM core (`vault-wasm`) owns decryption in-memory.
 *
 * This is plain TS with no runtime deps so both the web app and the browser
 * extension can share it without bundling conflicts.
 */

const DB_NAME = "safeory";
const DB_VERSION = 1;
const STORE = "vault";
const SNAPSHOT_KEY = "snapshot";
const SNAPSHOT_RECORD_FORMAT = 1;

export interface LoadedSnapshot {
  snapshotJson: string | null;
  version: number;
}

interface SnapshotRecord {
  format: number;
  version: number;
  snapshotJson: string | null;
}

function decodeSnapshotRecord(value: unknown): LoadedSnapshot {
  if (value === undefined) return { snapshotJson: null, version: 0 };
  // Backward compatibility with the original raw-string IndexedDB value.
  if (typeof value === "string") return { snapshotJson: value, version: 0 };
  if (
    typeof value === "object" &&
    value !== null &&
    "format" in value &&
    "version" in value &&
    "snapshotJson" in value
  ) {
    const record = value as Partial<SnapshotRecord>;
    if (
      record.format === SNAPSHOT_RECORD_FORMAT &&
      Number.isSafeInteger(record.version) &&
      (record.version ?? -1) >= 0 &&
      (typeof record.snapshotJson === "string" || record.snapshotJson === null)
    ) {
      return { snapshotJson: record.snapshotJson, version: record.version as number };
    }
  }
  throw new Error("saved browser vault metadata is invalid");
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("indexeddb open failed"));
  });
}

function withStore<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        let tx: IDBTransaction;
        try {
          tx = db.transaction(STORE, mode);
        } catch (error) {
          db.close();
          reject(error instanceof Error ? error : new Error(String(error)));
          return;
        }
        let settled = false;
        let requestSucceeded = false;
        let requestResult: T | undefined;

        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          db.close();
          reject(error instanceof Error ? error : new Error(String(error)));
        };

        tx.oncomplete = () => {
          if (settled) return;
          if (!requestSucceeded) {
            fail(new Error("indexeddb transaction completed before its request"));
            return;
          }
          settled = true;
          db.close();
          resolve(requestResult as T);
        };
        tx.onabort = () => fail(tx.error ?? new Error("indexeddb transaction aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("indexeddb transaction failed"));

        let request: IDBRequest<T>;
        try {
          request = run(tx.objectStore(STORE));
        } catch (error) {
          try {
            tx.abort();
          } catch {
            // The transaction may already have stopped because `run` failed.
          }
          fail(error);
          return;
        }

        request.onsuccess = () => {
          requestSucceeded = true;
          requestResult = request.result;
        };
        request.onerror = () =>
          fail(request.error ?? tx.error ?? new Error("indexeddb request failed"));
      }),
  );
}

function replaceSnapshot(snapshotJson: string | null, expectedVersion: number): Promise<number> {
  return openDb().then(
    (db) =>
      new Promise<number>((resolve, reject) => {
        let settled = false;
        let nextVersion: number | null = null;
        const tx = db.transaction(STORE, "readwrite");
        const store = tx.objectStore(STORE);

        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          db.close();
          reject(error instanceof Error ? error : new Error(String(error)));
        };

        tx.oncomplete = () => {
          if (settled) return;
          if (nextVersion === null) {
            fail(new Error("indexeddb snapshot transaction completed without a write"));
            return;
          }
          settled = true;
          db.close();
          resolve(nextVersion);
        };
        tx.onabort = () => fail(tx.error ?? new Error("indexeddb snapshot transaction aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("indexeddb snapshot transaction failed"));

        const read = store.get(SNAPSHOT_KEY);
        read.onerror = () => fail(read.error ?? new Error("indexeddb snapshot read failed"));
        read.onsuccess = () => {
          let current: LoadedSnapshot;
          try {
            current = decodeSnapshotRecord(read.result);
          } catch (error) {
            fail(error);
            try {
              tx.abort();
            } catch {
              // The transaction may already have stopped after the failed read.
            }
            return;
          }
          if (current.version !== expectedVersion) {
            fail(new Error("The browser vault changed in another tab. Reload before saving again."));
            try {
              tx.abort();
            } catch {
              // The transaction may already have stopped after the conflict.
            }
            return;
          }

          nextVersion = expectedVersion + 1;
          const record: SnapshotRecord = {
            format: SNAPSHOT_RECORD_FORMAT,
            version: nextVersion,
            snapshotJson,
          };
          const write = store.put(record, SNAPSHOT_KEY);
          write.onerror = () => fail(write.error ?? new Error("indexeddb snapshot write failed"));
        };
      }),
  );
}

/** Persist the ciphertext snapshot if no other browser tab has replaced it. */
export function saveSnapshot(snapshotJson: string, expectedVersion: number): Promise<number> {
  return replaceSnapshot(snapshotJson, expectedVersion);
}

/** Load the ciphertext snapshot and its browser-local compare-and-swap version. */
export async function loadSnapshot(): Promise<LoadedSnapshot> {
  const value = await withStore("readonly", (store) => store.get(SNAPSHOT_KEY));
  return decodeSnapshotRecord(value);
}

/** Reset the stored vault while preserving a monotonic version fence. */
export function clearSnapshot(expectedVersion: number): Promise<number> {
  return replaceSnapshot(null, expectedVersion);
}
