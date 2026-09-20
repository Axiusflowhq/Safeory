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
const DB_VERSION = 2;
const STORE = "vault";
const ATTACHMENT_MANIFEST_STORE = "attachment_manifests";
const ATTACHMENT_CHUNK_STORE = "attachment_chunks";
const SNAPSHOT_KEY = "snapshot";
const SNAPSHOT_RECORD_FORMAT = 1;
const ATTACHMENT_RECORD_FORMAT = 1;

export interface LoadedSnapshot {
  snapshotJson: string | null;
  version: number;
}

interface SnapshotRecord {
  format: number;
  version: number;
  snapshotJson: string | null;
}

interface AttachmentManifestRecord {
  format: number;
  revision: number;
  encryptedRecordJson: string;
}

export interface LoadedAttachmentManifest {
  revision: number;
  encryptedRecordJson: string;
}

export interface PersistedAttachmentManifest {
  attachmentId: string;
  revision: number;
  encryptedRecordJson: string;
}

export interface PersistedAttachmentChunk {
  attachmentId: string;
  index: number;
  ciphertext: Uint8Array;
}

export interface PersistedAttachmentState {
  manifests: PersistedAttachmentManifest[];
  chunks: PersistedAttachmentChunk[];
}

export interface PersistedVaultBackupState extends PersistedAttachmentState {
  snapshotJson: string;
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
      if (!db.objectStoreNames.contains(ATTACHMENT_MANIFEST_STORE)) {
        db.createObjectStore(ATTACHMENT_MANIFEST_STORE);
      }
      if (!db.objectStoreNames.contains(ATTACHMENT_CHUNK_STORE)) {
        db.createObjectStore(ATTACHMENT_CHUNK_STORE);
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

function attachmentChunkKey(attachmentId: string, index: number): string {
  return `${attachmentId}:${index}`;
}

function decodeAttachmentManifestRecord(value: unknown): LoadedAttachmentManifest | null {
  if (value === undefined) return null;
  if (
    typeof value === "object" &&
    value !== null &&
    "format" in value &&
    "revision" in value &&
    "encryptedRecordJson" in value
  ) {
    const record = value as Partial<AttachmentManifestRecord>;
    if (
      record.format === ATTACHMENT_RECORD_FORMAT &&
      Number.isSafeInteger(record.revision) &&
      (record.revision ?? 0) >= 1 &&
      typeof record.encryptedRecordJson === "string"
    ) {
      return {
        revision: record.revision as number,
        encryptedRecordJson: record.encryptedRecordJson,
      };
    }
  }
  throw new Error("saved browser attachment metadata is invalid");
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

function attachmentTransaction(
  snapshotJson: string,
  expectedVersion: number,
  runAttachmentWrites: (
    manifestStore: IDBObjectStore,
    chunkStore: IDBObjectStore,
    fail: (error: unknown) => void,
  ) => void,
): Promise<number> {
  return openDb().then(
    (db) =>
      new Promise<number>((resolve, reject) => {
        let settled = false;
        let nextVersion: number | null = null;
        const tx = db.transaction(
          [STORE, ATTACHMENT_MANIFEST_STORE, ATTACHMENT_CHUNK_STORE],
          "readwrite",
        );
        const vaultStore = tx.objectStore(STORE);
        const manifestStore = tx.objectStore(ATTACHMENT_MANIFEST_STORE);
        const chunkStore = tx.objectStore(ATTACHMENT_CHUNK_STORE);

        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          try {
            tx.abort();
          } catch {
            // The transaction may already have been aborted by IndexedDB.
          }
          db.close();
          reject(error instanceof Error ? error : new Error(String(error)));
        };

        tx.oncomplete = () => {
          if (settled) return;
          if (nextVersion === null) {
            fail(new Error("indexeddb attachment transaction completed without a vault write"));
            return;
          }
          settled = true;
          db.close();
          resolve(nextVersion);
        };
        tx.onabort = () => fail(tx.error ?? new Error("indexeddb attachment transaction aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("indexeddb attachment transaction failed"));

        const read = vaultStore.get(SNAPSHOT_KEY);
        read.onerror = () => fail(read.error ?? new Error("indexeddb snapshot read failed"));
        read.onsuccess = () => {
          let current: LoadedSnapshot;
          try {
            current = decodeSnapshotRecord(read.result);
          } catch (error) {
            fail(error);
            return;
          }
          if (current.version !== expectedVersion) {
            fail(new Error("The browser vault changed in another tab. Reload before saving again."));
            return;
          }
          nextVersion = expectedVersion + 1;
          const record: SnapshotRecord = {
            format: SNAPSHOT_RECORD_FORMAT,
            version: nextVersion,
            snapshotJson,
          };
          const write = vaultStore.put(record, SNAPSHOT_KEY);
          write.onerror = () => fail(write.error ?? new Error("indexeddb snapshot write failed"));
          try {
            runAttachmentWrites(manifestStore, chunkStore, fail);
          } catch (error) {
            fail(error);
          }
        };
      }),
  );
}

export function saveAttachmentImport(
  snapshotJson: string,
  expectedVersion: number,
  attachmentId: string,
  attachmentRevision: number,
  encryptedRecordJson: string,
  chunks: readonly Uint8Array[],
): Promise<number> {
  return attachmentTransaction(
    snapshotJson,
    expectedVersion,
    (manifestStore, chunkStore, fail) => {
      const existing = manifestStore.get(attachmentId);
      existing.onerror = () => fail(existing.error ?? new Error("indexeddb attachment read failed"));
      existing.onsuccess = () => {
        if (existing.result !== undefined) {
          fail(new Error("attachment identifier already exists"));
          return;
        }
        const manifest: AttachmentManifestRecord = {
          format: ATTACHMENT_RECORD_FORMAT,
          revision: attachmentRevision,
          encryptedRecordJson,
        };
        const manifestWrite = manifestStore.put(manifest, attachmentId);
        manifestWrite.onerror = () =>
          fail(manifestWrite.error ?? new Error("indexeddb attachment write failed"));
        chunks.forEach((chunk, index) => {
          const copy = chunk.slice();
          const chunkWrite = chunkStore.put(copy.buffer, attachmentChunkKey(attachmentId, index));
          chunkWrite.onerror = () =>
            fail(chunkWrite.error ?? new Error("indexeddb attachment chunk write failed"));
        });
      };
    },
  );
}

export function saveAttachmentDelete(
  snapshotJson: string,
  expectedVersion: number,
  attachmentId: string,
  expectedAttachmentRevision: number,
  nextAttachmentRevision: number,
  tombstoneRecordJson: string,
  chunkCount: number,
): Promise<number> {
  return attachmentTransaction(
    snapshotJson,
    expectedVersion,
    (manifestStore, chunkStore, fail) => {
      const existing = manifestStore.get(attachmentId);
      existing.onerror = () => fail(existing.error ?? new Error("indexeddb attachment read failed"));
      existing.onsuccess = () => {
        let decoded: LoadedAttachmentManifest | null;
        try {
          decoded = decodeAttachmentManifestRecord(existing.result);
        } catch (error) {
          fail(error);
          return;
        }
        if (decoded === null || decoded.revision !== expectedAttachmentRevision) {
          fail(new Error("The attachment changed before it could be deleted."));
          return;
        }
        const manifest: AttachmentManifestRecord = {
          format: ATTACHMENT_RECORD_FORMAT,
          revision: nextAttachmentRevision,
          encryptedRecordJson: tombstoneRecordJson,
        };
        const manifestWrite = manifestStore.put(manifest, attachmentId);
        manifestWrite.onerror = () =>
          fail(manifestWrite.error ?? new Error("indexeddb attachment write failed"));
        for (let index = 0; index < chunkCount; index += 1) {
          const deletion = chunkStore.delete(attachmentChunkKey(attachmentId, index));
          deletion.onerror = () =>
            fail(deletion.error ?? new Error("indexeddb attachment chunk delete failed"));
        }
      };
    },
  );
}

export interface ItemPurgeAttachmentWrite {
  attachmentId: string;
  expectedRevision: number;
  nextRevision: number;
  tombstoneRecordJson: string;
  chunkCount: number;
}

export function saveItemPurge(
  snapshotJson: string,
  expectedVersion: number,
  attachments: readonly ItemPurgeAttachmentWrite[],
): Promise<number> {
  return attachmentTransaction(
    snapshotJson,
    expectedVersion,
    (manifestStore, chunkStore, fail) => {
      for (const attachment of attachments) {
        const existing = manifestStore.get(attachment.attachmentId);
        existing.onerror = () =>
          fail(existing.error ?? new Error("indexeddb attachment read failed"));
        existing.onsuccess = () => {
          let decoded: LoadedAttachmentManifest | null;
          try {
            decoded = decodeAttachmentManifestRecord(existing.result);
          } catch (error) {
            fail(error);
            return;
          }
          if (decoded === null || decoded.revision !== attachment.expectedRevision) {
            fail(new Error("An attachment changed before the item could be permanently deleted."));
            return;
          }
          const manifest: AttachmentManifestRecord = {
            format: ATTACHMENT_RECORD_FORMAT,
            revision: attachment.nextRevision,
            encryptedRecordJson: attachment.tombstoneRecordJson,
          };
          const manifestWrite = manifestStore.put(manifest, attachment.attachmentId);
          manifestWrite.onerror = () =>
            fail(manifestWrite.error ?? new Error("indexeddb attachment purge failed"));
          for (let index = 0; index < attachment.chunkCount; index += 1) {
            const deletion = chunkStore.delete(attachmentChunkKey(attachment.attachmentId, index));
            deletion.onerror = () =>
              fail(deletion.error ?? new Error("indexeddb attachment chunk purge failed"));
          }
        };
      }
    },
  );
}

export async function loadAttachmentManifest(
  attachmentId: string,
): Promise<LoadedAttachmentManifest | null> {
  return openDb().then(
    (db) =>
      new Promise<LoadedAttachmentManifest | null>((resolve, reject) => {
        const tx = db.transaction(ATTACHMENT_MANIFEST_STORE, "readonly");
        const request = tx.objectStore(ATTACHMENT_MANIFEST_STORE).get(attachmentId);
        let value: LoadedAttachmentManifest | null = null;
        request.onsuccess = () => {
          try {
            value = decodeAttachmentManifestRecord(request.result);
          } catch (error) {
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        };
        request.onerror = () =>
          reject(request.error ?? new Error("indexeddb attachment read failed"));
        tx.oncomplete = () => {
          db.close();
          resolve(value);
        };
        tx.onabort = () => {
          db.close();
          reject(tx.error ?? new Error("indexeddb attachment transaction aborted"));
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error ?? new Error("indexeddb attachment transaction failed"));
        };
      }),
  );
}

export function loadAttachmentChunk(
  attachmentId: string,
  index: number,
): Promise<Uint8Array | null> {
  return openDb().then(
    (db) =>
      new Promise<Uint8Array | null>((resolve, reject) => {
        const tx = db.transaction(ATTACHMENT_CHUNK_STORE, "readonly");
        const request = tx.objectStore(ATTACHMENT_CHUNK_STORE).get(attachmentChunkKey(attachmentId, index));
        let value: Uint8Array | null = null;
        request.onsuccess = () => {
          if (request.result === undefined) {
            value = null;
            return;
          }
          if (!(request.result instanceof ArrayBuffer)) {
            reject(new Error("saved browser attachment chunk is invalid"));
            return;
          }
          value = new Uint8Array(request.result);
        };
        request.onerror = () => reject(request.error ?? new Error("indexeddb attachment chunk read failed"));
        tx.oncomplete = () => {
          db.close();
          resolve(value);
        };
        tx.onabort = () => {
          db.close();
          reject(tx.error ?? new Error("indexeddb attachment transaction aborted"));
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error ?? new Error("indexeddb attachment transaction failed"));
        };
      }),
  );
}

export function loadAllAttachmentState(): Promise<PersistedAttachmentState> {
  return openDb().then(
    (db) =>
      new Promise<PersistedAttachmentState>((resolve, reject) => {
        const tx = db.transaction(
          [ATTACHMENT_MANIFEST_STORE, ATTACHMENT_CHUNK_STORE],
          "readonly",
        );
        const manifestStore = tx.objectStore(ATTACHMENT_MANIFEST_STORE);
        const chunkStore = tx.objectStore(ATTACHMENT_CHUNK_STORE);
        const manifestKeys = manifestStore.getAllKeys();
        const manifestValues = manifestStore.getAll();
        const chunkKeys = chunkStore.getAllKeys();
        const chunkValues = chunkStore.getAll();
        let settled = false;

        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          db.close();
          reject(error instanceof Error ? error : new Error(String(error)));
        };
        for (const request of [manifestKeys, manifestValues, chunkKeys, chunkValues]) {
          request.onerror = () => fail(request.error ?? new Error("indexeddb attachment export failed"));
        }
        tx.onabort = () => fail(tx.error ?? new Error("indexeddb attachment export aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("indexeddb attachment export failed"));
        tx.oncomplete = () => {
          if (settled) return;
          try {
            if (manifestKeys.result.length !== manifestValues.result.length) {
              throw new Error("saved browser attachment manifest index is inconsistent");
            }
            if (chunkKeys.result.length !== chunkValues.result.length) {
              throw new Error("saved browser attachment chunk index is inconsistent");
            }
            const manifests = manifestKeys.result.map((key, index) => {
              if (typeof key !== "string") {
                throw new Error("saved browser attachment key is invalid");
              }
              const decoded = decodeAttachmentManifestRecord(manifestValues.result[index]);
              if (decoded === null) {
                throw new Error("saved browser attachment manifest is missing");
              }
              return {
                attachmentId: key,
                revision: decoded.revision,
                encryptedRecordJson: decoded.encryptedRecordJson,
              };
            });
            const chunks = chunkKeys.result.map((key, index) => {
              if (typeof key !== "string") {
                throw new Error("saved browser attachment chunk key is invalid");
              }
              const separator = key.lastIndexOf(":");
              if (separator <= 0) {
                throw new Error("saved browser attachment chunk key is invalid");
              }
              const attachmentId = key.slice(0, separator);
              const chunkIndex = Number(key.slice(separator + 1));
              if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0) {
                throw new Error("saved browser attachment chunk index is invalid");
              }
              const value = chunkValues.result[index];
              if (!(value instanceof ArrayBuffer)) {
                throw new Error("saved browser attachment chunk is invalid");
              }
              return {
                attachmentId,
                index: chunkIndex,
                ciphertext: new Uint8Array(value),
              };
            });
            settled = true;
            db.close();
            resolve({ manifests, chunks });
          } catch (error) {
            fail(error);
          }
        };
      }),
  );
}

export function loadVaultBackupState(expectedVersion: number): Promise<PersistedVaultBackupState> {
  return openDb().then(
    (db) =>
      new Promise<PersistedVaultBackupState>((resolve, reject) => {
        const tx = db.transaction(
          [STORE, ATTACHMENT_MANIFEST_STORE, ATTACHMENT_CHUNK_STORE],
          "readonly",
        );
        const vaultRequest = tx.objectStore(STORE).get(SNAPSHOT_KEY);
        const manifestStore = tx.objectStore(ATTACHMENT_MANIFEST_STORE);
        const chunkStore = tx.objectStore(ATTACHMENT_CHUNK_STORE);
        const manifestKeys = manifestStore.getAllKeys();
        const manifestValues = manifestStore.getAll();
        const chunkKeys = chunkStore.getAllKeys();
        const chunkValues = chunkStore.getAll();
        let settled = false;

        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          db.close();
          reject(error instanceof Error ? error : new Error(String(error)));
        };
        for (const request of [
          vaultRequest,
          manifestKeys,
          manifestValues,
          chunkKeys,
          chunkValues,
        ]) {
          request.onerror = () => fail(request.error ?? new Error("indexeddb backup read failed"));
        }
        tx.onabort = () => fail(tx.error ?? new Error("indexeddb backup read aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("indexeddb backup read failed"));
        tx.oncomplete = () => {
          if (settled) return;
          try {
            const loaded = decodeSnapshotRecord(vaultRequest.result);
            if (loaded.version !== expectedVersion) {
              throw new Error("The browser vault changed in another tab. Reload before exporting.");
            }
            if (loaded.snapshotJson === null) {
              throw new Error("The browser vault is not initialized.");
            }
            if (manifestKeys.result.length !== manifestValues.result.length) {
              throw new Error("saved browser attachment manifest index is inconsistent");
            }
            if (chunkKeys.result.length !== chunkValues.result.length) {
              throw new Error("saved browser attachment chunk index is inconsistent");
            }
            const manifests = manifestKeys.result.map((key, index) => {
              if (typeof key !== "string") {
                throw new Error("saved browser attachment key is invalid");
              }
              const decoded = decodeAttachmentManifestRecord(manifestValues.result[index]);
              if (decoded === null) {
                throw new Error("saved browser attachment manifest is missing");
              }
              return {
                attachmentId: key,
                revision: decoded.revision,
                encryptedRecordJson: decoded.encryptedRecordJson,
              };
            });
            const chunks = chunkKeys.result.map((key, index) => {
              if (typeof key !== "string") {
                throw new Error("saved browser attachment chunk key is invalid");
              }
              const separator = key.lastIndexOf(":");
              if (separator <= 0) {
                throw new Error("saved browser attachment chunk key is invalid");
              }
              const attachmentId = key.slice(0, separator);
              const chunkIndex = Number(key.slice(separator + 1));
              if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0) {
                throw new Error("saved browser attachment chunk index is invalid");
              }
              const value = chunkValues.result[index];
              if (!(value instanceof ArrayBuffer)) {
                throw new Error("saved browser attachment chunk is invalid");
              }
              return {
                attachmentId,
                index: chunkIndex,
                ciphertext: new Uint8Array(value),
              };
            });
            settled = true;
            db.close();
            resolve({ snapshotJson: loaded.snapshotJson, manifests, chunks });
          } catch (error) {
            fail(error);
          }
        };
      }),
  );
}

export function replaceVaultFromBackup(
  snapshotJson: string,
  expectedVersion: number,
  attachmentState: PersistedAttachmentState,
): Promise<number> {
  const manifestIds = new Set<string>();
  for (const manifest of attachmentState.manifests) {
    if (
      manifestIds.has(manifest.attachmentId) ||
      !Number.isSafeInteger(manifest.revision) ||
      manifest.revision < 1 ||
      manifest.encryptedRecordJson.length > 128 * 1024
    ) {
      return Promise.reject(new Error("encrypted backup attachment metadata is invalid"));
    }
    manifestIds.add(manifest.attachmentId);
  }
  const chunkKeys = new Set<string>();
  for (const chunk of attachmentState.chunks) {
    const key = attachmentChunkKey(chunk.attachmentId, chunk.index);
    if (
      chunkKeys.has(key) ||
      !manifestIds.has(chunk.attachmentId) ||
      !Number.isSafeInteger(chunk.index) ||
      chunk.index < 0 ||
      chunk.ciphertext.byteLength > 1024 * 1024 + 16
    ) {
      return Promise.reject(new Error("encrypted backup attachment chunks are invalid"));
    }
    chunkKeys.add(key);
  }

  return openDb().then(
    (db) =>
      new Promise<number>((resolve, reject) => {
        let settled = false;
        let nextVersion: number | null = null;
        const tx = db.transaction(
          [STORE, ATTACHMENT_MANIFEST_STORE, ATTACHMENT_CHUNK_STORE],
          "readwrite",
        );
        const vaultStore = tx.objectStore(STORE);
        const manifestStore = tx.objectStore(ATTACHMENT_MANIFEST_STORE);
        const chunkStore = tx.objectStore(ATTACHMENT_CHUNK_STORE);
        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          try {
            tx.abort();
          } catch {
            // The transaction may already be aborted.
          }
          db.close();
          reject(error instanceof Error ? error : new Error(String(error)));
        };
        tx.oncomplete = () => {
          if (settled) return;
          if (nextVersion === null) {
            fail(new Error("indexeddb backup restore completed without a vault write"));
            return;
          }
          settled = true;
          db.close();
          resolve(nextVersion);
        };
        tx.onabort = () => fail(tx.error ?? new Error("indexeddb backup restore aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("indexeddb backup restore failed"));

        const read = vaultStore.get(SNAPSHOT_KEY);
        read.onerror = () => fail(read.error ?? new Error("indexeddb snapshot read failed"));
        read.onsuccess = () => {
          let current: LoadedSnapshot;
          try {
            current = decodeSnapshotRecord(read.result);
          } catch (error) {
            fail(error);
            return;
          }
          if (current.version !== expectedVersion) {
            fail(new Error("The browser vault changed in another tab. Reload before restoring."));
            return;
          }
          nextVersion = expectedVersion + 1;
          const clearManifests = manifestStore.clear();
          clearManifests.onerror = () =>
            fail(clearManifests.error ?? new Error("indexeddb attachment clear failed"));
          const clearChunks = chunkStore.clear();
          clearChunks.onerror = () =>
            fail(clearChunks.error ?? new Error("indexeddb attachment clear failed"));
          const record: SnapshotRecord = {
            format: SNAPSHOT_RECORD_FORMAT,
            version: nextVersion,
            snapshotJson,
          };
          const snapshotWrite = vaultStore.put(record, SNAPSHOT_KEY);
          snapshotWrite.onerror = () =>
            fail(snapshotWrite.error ?? new Error("indexeddb snapshot write failed"));
          for (const manifest of attachmentState.manifests) {
            const stored: AttachmentManifestRecord = {
              format: ATTACHMENT_RECORD_FORMAT,
              revision: manifest.revision,
              encryptedRecordJson: manifest.encryptedRecordJson,
            };
            const write = manifestStore.put(stored, manifest.attachmentId);
            write.onerror = () =>
              fail(write.error ?? new Error("indexeddb attachment restore failed"));
          }
          for (const chunk of attachmentState.chunks) {
            const copy = chunk.ciphertext.slice();
            const write = chunkStore.put(
              copy.buffer,
              attachmentChunkKey(chunk.attachmentId, chunk.index),
            );
            write.onerror = () =>
              fail(write.error ?? new Error("indexeddb attachment chunk restore failed"));
          }
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
  return openDb().then(
    (db) =>
      new Promise<number>((resolve, reject) => {
        let settled = false;
        let nextVersion: number | null = null;
        const tx = db.transaction(
          [STORE, ATTACHMENT_MANIFEST_STORE, ATTACHMENT_CHUNK_STORE],
          "readwrite",
        );
        const vaultStore = tx.objectStore(STORE);
        const manifestStore = tx.objectStore(ATTACHMENT_MANIFEST_STORE);
        const chunkStore = tx.objectStore(ATTACHMENT_CHUNK_STORE);
        const fail = (error: unknown) => {
          if (settled) return;
          settled = true;
          try {
            tx.abort();
          } catch {
            // The transaction may already be aborted.
          }
          db.close();
          reject(error instanceof Error ? error : new Error(String(error)));
        };
        tx.oncomplete = () => {
          if (settled) return;
          if (nextVersion === null) {
            fail(new Error("indexeddb reset completed without a vault write"));
            return;
          }
          settled = true;
          db.close();
          resolve(nextVersion);
        };
        tx.onabort = () => fail(tx.error ?? new Error("indexeddb reset aborted"));
        tx.onerror = () => fail(tx.error ?? new Error("indexeddb reset failed"));
        const read = vaultStore.get(SNAPSHOT_KEY);
        read.onerror = () => fail(read.error ?? new Error("indexeddb snapshot read failed"));
        read.onsuccess = () => {
          let current: LoadedSnapshot;
          try {
            current = decodeSnapshotRecord(read.result);
          } catch (error) {
            fail(error);
            return;
          }
          if (current.version !== expectedVersion) {
            fail(new Error("The browser vault changed in another tab. Reload before resetting."));
            return;
          }
          nextVersion = expectedVersion + 1;
          const write = vaultStore.put(
            { format: SNAPSHOT_RECORD_FORMAT, version: nextVersion, snapshotJson: null },
            SNAPSHOT_KEY,
          );
          write.onerror = () => fail(write.error ?? new Error("indexeddb reset write failed"));
          const manifestClear = manifestStore.clear();
          manifestClear.onerror = () =>
            fail(manifestClear.error ?? new Error("indexeddb attachment reset failed"));
          const chunkClear = chunkStore.clear();
          chunkClear.onerror = () =>
            fail(chunkClear.error ?? new Error("indexeddb attachment reset failed"));
        };
      }),
  );
}
