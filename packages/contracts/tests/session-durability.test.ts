import assert from "node:assert/strict";
import test from "node:test";

import {
  VaultDurabilityError,
  VaultSession,
  type VaultFactory,
  type WasmVaultLike,
} from "../src/session";
import type { EncryptedVaultItemV1 } from "../src/sync-vault-item";

class FakeVault implements WasmVaultLike {
  unlocked: boolean;
  recoveryInstalled: boolean;
  initialized: boolean;
  putCount = 0;
  sessionResumeCount = 0;
  passphraseChangeCount = 0;
  snapshotCount = 0;
  deadlineJson = "[]";
  encryptedSyncItemJson: string | null = null;
  failMutation = false;
  trashedAttachmentIds: string[] = [];
  purgeCommitJson = JSON.stringify({ item_revision: 3, attachments: [] });
  private readonly onPut: (() => void) | undefined;
  private readonly expectedResumePayload: string | null;
  private readonly expectedPassphrase: string | null;
  private readonly snapshotOverride: string | null;
  private readonly attachmentOwnerId: string | null;
  private readonly attachmentIds: string[];

  constructor(
    unlocked = true,
    recoveryInstalled = false,
    onPut?: () => void,
    expectedResumePayload: string | null = null,
    initialized = true,
    expectedPassphrase: string | null = null,
    snapshotOverride: string | null = null,
    attachmentOwnerId: string | null = null,
    attachmentIds: string[] = [],
  ) {
    this.unlocked = unlocked;
    this.recoveryInstalled = recoveryInstalled;
    this.initialized = initialized;
    this.onPut = onPut;
    this.expectedResumePayload = expectedResumePayload;
    this.expectedPassphrase = expectedPassphrase;
    this.snapshotOverride = snapshotOverride;
    this.attachmentOwnerId = attachmentOwnerId;
    this.attachmentIds = attachmentIds;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  isUnlocked(): boolean {
    return this.unlocked;
  }

  create(): void {
    this.initialized = true;
    this.unlocked = true;
  }

  unlock(passphrase: string): void {
    if (this.expectedPassphrase !== null && passphrase !== this.expectedPassphrase) {
      throw new Error("wrong passphrase");
    }
    this.unlocked = true;
  }

  changePassphrase(): void {
    this.passphraseChangeCount += 1;
  }

  lock(): void {
    this.unlocked = false;
  }

  createSessionResumeJson(): string {
    this.sessionResumeCount += 1;
    return JSON.stringify({ secret: `resume-${this.sessionResumeCount}`, wrapped: {} });
  }

  unlockWithSessionResumeJson(payloadJson: string): void {
    if (this.expectedResumePayload !== null && payloadJson !== this.expectedResumePayload) {
      throw new Error("stale resume payload");
    }
    this.unlocked = true;
  }

  snapshotJson(): string {
    this.snapshotCount += 1;
    return this.snapshotOverride ?? JSON.stringify({ recoveryInstalled: this.recoveryInstalled });
  }

  putItemJson(): void {
    if (this.failMutation) throw new Error("validation failed");
    this.putCount += 1;
    this.onPut?.();
  }

  getItemJson(id: string): string {
    if (this.attachmentOwnerId !== null && id === this.attachmentOwnerId) {
      return JSON.stringify({ attachments: this.attachmentIds });
    }
    return "{}";
  }

  getEncryptedItemJson(): string | null {
    return this.encryptedSyncItemJson;
  }

  listEncryptedItemIdsJson(): string {
    if (this.encryptedSyncItemJson === null) return "[]";
    return JSON.stringify([
      (JSON.parse(this.encryptedSyncItemJson) as { object_id: string }).object_id,
    ]);
  }

  encryptedItemIsTombstone(): boolean {
    return false;
  }

  applyEncryptedItemJson(nextJson: string, expectedJson?: string): void {
    if (expectedJson === undefined) {
      if (this.encryptedSyncItemJson !== null) throw new Error("encrypted sync precondition failed");
    } else if (this.encryptedSyncItemJson !== expectedJson) {
      throw new Error("encrypted sync precondition failed");
    }
    this.encryptedSyncItemJson = nextJson;
  }

  listItemsJson(): string {
    if (this.attachmentOwnerId !== null) {
      return JSON.stringify([
        {
          item: { id: this.attachmentOwnerId, title: "Attachment owner", kind: "secure_note" },
          revision: 2,
        },
      ]);
    }
    return "[]";
  }

  exportReadableJson(): string {
    return JSON.stringify({
      format: "safeory-readable-export",
      format_version: 1,
      items: [],
      emergency_card: null,
    });
  }

  listDeadlinesJson(): string {
    return this.deadlineJson;
  }

  updateItemJson(): bigint {
    return 1n;
  }

  trashItem(): bigint {
    return 1n;
  }

  listTrashedItemsJson(): string {
    return "[]";
  }

  restoreItem(): bigint {
    return 2n;
  }

  trashedAttachmentIdsJson(): string {
    return JSON.stringify(this.trashedAttachmentIds);
  }

  purgeItemJson(): string {
    return this.purgeCommitJson;
  }

  beginAttachmentImportJson(
    _ownerItemId: string,
    _expectedItemRevision: number | bigint,
    filename: string,
    plaintextSize: number | bigint,
  ): string {
    return JSON.stringify({
      id: "00000000-0000-4000-8000-0000000000aa",
      revision: 1,
      filename,
      plaintext_size: Number(plaintextSize),
      chunk_count: Number(plaintextSize) === 0 ? 0 : 1,
    });
  }

  encryptAttachmentImportChunk(
    _attachmentId: string,
    _index: number,
    plaintext: Uint8Array,
  ): Uint8Array {
    return plaintext.slice();
  }

  cancelAttachmentImport(): void {}

  commitAttachmentImportJson(): string {
    return JSON.stringify({
      summary: {
        id: "00000000-0000-4000-8000-0000000000aa",
        revision: 1,
        filename: "attachment.bin",
        plaintext_size: 1,
        chunk_count: 1,
      },
      item_revision: 2,
      encrypted_record_json: "{}",
    });
  }

  describeAttachmentJson(): string {
    return JSON.stringify({
      id: "00000000-0000-4000-8000-0000000000aa",
      revision: 1,
      filename: "attachment.bin",
      plaintext_size: 1,
      chunk_count: 1,
    });
  }

  decryptAttachmentChunk(
    _ownerItemId: string,
    _attachmentId: string,
    _encryptedRecordJson: string,
    _index: number,
    ciphertext: Uint8Array,
  ): Uint8Array {
    return ciphertext.slice();
  }

  deleteAttachmentJson(): string {
    return JSON.stringify({
      item_revision: 3,
      attachment_revision: 2,
      encrypted_record_json: "{}",
    });
  }

  getEmergencyCardJson(): string | null {
    return null;
  }

  setEmergencyCardJson(): bigint {
    return 1n;
  }

  createTrustedDevicePairingChallengeJson(principalId: string, deviceId: string): string {
    return JSON.stringify({
      format_version: 1,
      request_id: "00000000-0000-4000-8000-000000000001",
      principal_id: principalId,
      device_id: deviceId,
      encryption_public: Array(32).fill(1),
      verifier_ephemeral_public: Array(32).fill(2),
      nonce: Array(24).fill(3),
      ciphertext: Array(48).fill(4),
    });
  }

  completeTrustedDevicePairingJson(): bigint {
    return 2n;
  }

  installRecoveryKit(): void {
    this.recoveryInstalled = true;
  }

  hasRecoveryKit(): boolean {
    return this.recoveryInstalled;
  }

  verifyRecoveryKit(): boolean {
    return this.recoveryInstalled;
  }

  unlockWithRecoveryKit(): void {
    this.unlocked = true;
  }
}

type SessionConstructor = new (
  factory: VaultFactory,
  vault: WasmVaultLike,
  persistenceVersion: number,
) => VaultSession;

function newSession(factory: VaultFactory, vault: WasmVaultLike, persistenceVersion = 0): VaultSession {
  return new (VaultSession as unknown as SessionConstructor)(factory, vault, persistenceVersion);
}

function installFailingIndexedDb(): void {
  const db = {
    close() {},
    transaction() {
      const tx: Record<string, unknown> = { error: null };
      const store = {
        get() {
          const request: Record<string, unknown> = {
            error: null,
            result: { format: 1, version: 0, snapshotJson: null },
          };
          queueMicrotask(() => (request.onsuccess as (() => void) | undefined)?.());
          return request;
        },
        put() {
          const request: Record<string, unknown> = { error: new Error("disk full") };
          queueMicrotask(() => (request.onerror as (() => void) | undefined)?.());
          return request;
        },
      };
      tx.objectStore = () => store;
      return tx;
    },
  };

  globalThis.indexedDB = {
    open() {
      const request: Record<string, unknown> = { error: null, result: db };
      queueMicrotask(() => (request.onsuccess as (() => void) | undefined)?.());
      return request;
    },
  } as unknown as IDBFactory;
}

function installSnapshotIndexedDb(record: {
  format: number;
  version: number;
  snapshotJson: string | null;
}): void {
  const db = {
    close() {},
    transaction() {
      const tx: Record<string, unknown> = { error: null };
      const store = {
        get() {
          const request: Record<string, unknown> = { error: null, result: undefined };
          queueMicrotask(() => {
            request.result = record;
            (request.onsuccess as (() => void) | undefined)?.();
            queueMicrotask(() => (tx.oncomplete as (() => void) | undefined)?.());
          });
          return request;
        },
      };
      tx.objectStore = () => store;
      return tx;
    },
  };

  globalThis.indexedDB = {
    open() {
      const request: Record<string, unknown> = { error: null, result: db };
      queueMicrotask(() => (request.onsuccess as (() => void) | undefined)?.());
      return request;
    },
  } as unknown as IDBFactory;
}

function installWritableIndexedDb(initial: {
  format: number;
  version: number;
  snapshotJson: string | null;
}, options: { failWrites?: boolean } = {}): {
  getVaultRecord: () => { format: number; version: number; snapshotJson: string | null };
  getManifest: (id: string) => unknown;
  getChunk: (key: string) => unknown;
} {
  const stores = new Map<string, Map<string, unknown>>([
    ["vault", new Map([["snapshot", structuredClone(initial)]])],
    ["attachment_manifests", new Map()],
    ["attachment_chunks", new Map()],
  ]);
  const db = {
    close() {},
    transaction() {
      let pending = 0;
      let completionScheduled = false;
      let aborted = false;
      const tx: Record<string, unknown> = { error: null };

      const maybeComplete = () => {
        if (aborted || pending !== 0 || completionScheduled) return;
        completionScheduled = true;
        queueMicrotask(() => {
          completionScheduled = false;
          if (!aborted && pending === 0) {
            (tx.oncomplete as (() => void) | undefined)?.();
          }
        });
      };

      const request = <T>(operation: () => T) => {
        pending += 1;
        const result: Record<string, unknown> = { error: null, result: undefined };
        queueMicrotask(() => {
          if (aborted) return;
          try {
            result.result = operation();
            (result.onsuccess as (() => void) | undefined)?.();
          } catch (error) {
            result.error = error;
            tx.error = error;
            (result.onerror as (() => void) | undefined)?.();
            aborted = true;
            (tx.onabort as (() => void) | undefined)?.();
          } finally {
            pending -= 1;
            maybeComplete();
          }
        });
        return result;
      };

      tx.abort = () => {
        if (aborted) return;
        aborted = true;
        queueMicrotask(() => (tx.onabort as (() => void) | undefined)?.());
      };
      tx.objectStore = (name: string) => {
        const data = stores.get(name);
        if (!data) throw new Error(`unknown object store ${name}`);
        return {
          get(key: IDBValidKey) {
            return request(() => structuredClone(data.get(String(key))));
          },
          put(value: unknown, key: IDBValidKey) {
            return request(() => {
              if (options.failWrites) throw new Error("disk full");
              data.set(String(key), structuredClone(value));
              return key;
            });
          },
          delete(key: IDBValidKey) {
            return request(() => {
              if (options.failWrites) throw new Error("disk full");
              data.delete(String(key));
              return undefined;
            });
          },
          clear() {
            return request(() => {
              if (options.failWrites) throw new Error("disk full");
              data.clear();
              return undefined;
            });
          },
          getAllKeys() {
            return request(() => Array.from(data.keys()));
          },
          getAll() {
            return request(() => Array.from(data.values(), (value) => structuredClone(value)));
          },
        };
      };
      return tx;
    },
  };

  globalThis.indexedDB = {
    open() {
      const request: Record<string, unknown> = { error: null, result: db };
      queueMicrotask(() => (request.onsuccess as (() => void) | undefined)?.());
      return request;
    },
  } as unknown as IDBFactory;
  return {
    getVaultRecord: () =>
      structuredClone(stores.get("vault")?.get("snapshot")) as {
        format: number;
        version: number;
        snapshotJson: string | null;
      },
    getManifest: (id) => structuredClone(stores.get("attachment_manifests")?.get(id)),
    getChunk: (key) => structuredClone(stores.get("attachment_chunks")?.get(key)),
  };
}

test("durability failure poisons recovery installation and fences queued mutations", async () => {
  installFailingIndexedDb();
  let totalPutCount = 0;
  const countPut = () => {
    totalPutCount += 1;
  };
  const liveVault = new FakeVault(true, false, countPut);
  let rollbackSnapshot: string | null = null;
  const factory: VaultFactory = (snapshot) => {
    rollbackSnapshot = snapshot;
    const parsed = JSON.parse(snapshot ?? "{}") as { recoveryInstalled?: boolean };
    return new FakeVault(false, parsed.recoveryInstalled ?? false, countPut);
  };
  const session = newSession(factory, liveVault);

  const recoveryInstall = session.installRecoveryKit("secret");
  const queuedPut = session.putItem("{}");

  await assert.rejects(recoveryInstall, VaultDurabilityError);
  await assert.rejects(queuedPut, VaultDurabilityError);
  assert.equal(totalPutCount, 0, "queued mutation must not run after poison");
  assert.equal(session.isUnlocked(), false);
  assert.equal(rollbackSnapshot, JSON.stringify({ recoveryInstalled: false }));
  assert.throws(() => session.listItems(), VaultDurabilityError);
});

test("WASM mutation errors remain recoverable and do not poison the session", async () => {
  const liveVault = new FakeVault(true, false);
  liveVault.failMutation = true;
  const session = newSession(() => new FakeVault(false, false), liveVault);

  await assert.rejects(session.putItem("{}"), /validation failed/);
  assert.equal(session.isUnlocked(), true);
  assert.deepEqual(session.listItems(), []);
});

test("master passphrase change persists through the normal durability fence", async () => {
  const snapshot = JSON.stringify({ recoveryInstalled: false });
  const indexedDb = installWritableIndexedDb({ format: 1, version: 0, snapshotJson: snapshot });
  const liveVault = new FakeVault(true, false, undefined, null, true, null, snapshot);
  const session = newSession(() => new FakeVault(false, false), liveVault);

  await session.changePassphrase("current passphrase", "replacement passphrase");

  assert.equal(liveVault.passphraseChangeCount, 1);
  assert.deepEqual(indexedDb.getVaultRecord(), {
    format: 1,
    version: 1,
    snapshotJson: snapshot,
  });
});

test("portable exports require unlock and encrypted backup reads the durable fenced state", async () => {
  const liveVault = new FakeVault(true, false);
  const session = newSession(() => new FakeVault(false, false), liveVault);
  const durableSnapshot = JSON.stringify({ recoveryInstalled: false });
  installWritableIndexedDb({ format: 1, version: 0, snapshotJson: durableSnapshot });

  const readable = JSON.parse(session.exportReadableVault()) as { format: string };
  assert.equal(readable.format, "safeory-readable-export");
  const encrypted = JSON.parse(await session.exportEncryptedSnapshot()) as {
    format: string;
    snapshot_json: string;
    attachment_manifests: unknown[];
    attachment_chunks: unknown[];
  };
  assert.equal(encrypted.format, "safeory-encrypted-browser-backup");
  assert.equal(encrypted.snapshot_json, durableSnapshot);
  assert.deepEqual(encrypted.attachment_manifests, []);
  assert.deepEqual(encrypted.attachment_chunks, []);
  assert.equal(liveVault.snapshotCount, 0);

  session.lock();
  assert.throws(() => session.exportReadableVault(), /Vault is locked/);
  await assert.rejects(session.exportEncryptedSnapshot(), /Vault is locked/);
});

test("attachment persistence survives download, encrypted backup restore, delete, and reset", async () => {
  const attachmentId = "00000000-0000-4000-8000-0000000000aa";
  const ownerId = "00000000-0000-4000-8000-000000000001";
  const indexedDb = installWritableIndexedDb({
    format: 1,
    version: 0,
    snapshotJson: JSON.stringify({ recoveryInstalled: false }),
  });
  const liveVault = new FakeVault(true, false);
  const session = newSession(() => new FakeVault(false, false), liveVault);
  const fileBytes = Uint8Array.of(7);
  const file = {
    name: "attachment.bin",
    size: fileBytes.byteLength,
    slice(start?: number, end?: number) {
      return new Blob([fileBytes.slice(start ?? 0, end ?? fileBytes.length)]);
    },
  } as File;

  const added = await session.addAttachment(ownerId, 1, file);
  assert.equal(added.summary.id, attachmentId);
  assert.equal(added.itemRevision, 2);
  assert.deepEqual(indexedDb.getManifest(attachmentId), {
    format: 1,
    revision: 1,
    encryptedRecordJson: "{}",
  });
  assert.deepEqual(
    new Uint8Array(indexedDb.getChunk(`${attachmentId}:0`) as ArrayBuffer),
    fileBytes,
  );

  const downloaded = await session.downloadAttachment(ownerId, attachmentId);
  assert.equal(downloaded.summary.filename, "attachment.bin");
  assert.deepEqual(new Uint8Array(await downloaded.blob.arrayBuffer()), fileBytes);

  const backupJson = await session.exportEncryptedSnapshot();
  const backup = JSON.parse(backupJson) as {
    attachment_manifests: unknown[];
    attachment_chunks: Array<{ ciphertext_base64: string }>;
  };
  assert.equal(backup.attachment_manifests.length, 1);
  assert.equal(backup.attachment_chunks.length, 1);
  assert.equal(backup.attachment_chunks[0]?.ciphertext_base64, "Bw==");

  const restoredIndexedDb = installWritableIndexedDb({
    format: 1,
    version: 0,
    snapshotJson: null,
  });
  const fresh = new FakeVault(false, false, undefined, null, false);
  const restored = newSession(
    () =>
      new FakeVault(
        false,
        false,
        undefined,
        null,
        true,
        "backup-passphrase",
        null,
        ownerId,
        [attachmentId],
      ),
    fresh,
  );
  await restored.importEncryptedSnapshot(backupJson, "backup-passphrase");
  assert.deepEqual(restoredIndexedDb.getManifest(attachmentId), {
    format: 1,
    revision: 1,
    encryptedRecordJson: "{}",
  });
  assert.deepEqual(
    new Uint8Array(restoredIndexedDb.getChunk(`${attachmentId}:0`) as ArrayBuffer),
    fileBytes,
  );

  const summaries = await restored.listAttachments(ownerId, [attachmentId]);
  assert.equal(summaries.length, 1);
  await restored.deleteAttachment(ownerId, 2, summaries[0]!, 42);
  assert.deepEqual(restoredIndexedDb.getManifest(attachmentId), {
    format: 1,
    revision: 2,
    encryptedRecordJson: "{}",
  });
  assert.equal(restoredIndexedDb.getChunk(`${attachmentId}:0`), undefined);

  await restored.reset();
  assert.equal(restoredIndexedDb.getManifest(attachmentId), undefined);
  assert.equal(restoredIndexedDb.getChunk(`${attachmentId}:0`), undefined);
  assert.deepEqual(restoredIndexedDb.getVaultRecord(), {
    format: 1,
    version: 3,
    snapshotJson: null,
  });
});

test("permanent item purge atomically tombstones linked attachments and removes chunks", async () => {
  const attachmentId = "00000000-0000-4000-8000-0000000000aa";
  const ownerId = "00000000-0000-4000-8000-000000000001";
  const indexedDb = installWritableIndexedDb({
    format: 1,
    version: 0,
    snapshotJson: JSON.stringify({ recoveryInstalled: false }),
  });
  const liveVault = new FakeVault(true, false);
  const session = newSession(() => new FakeVault(false, false), liveVault);
  const file = {
    name: "attachment.bin",
    size: 1,
    slice() {
      return new Blob([Uint8Array.of(9)]);
    },
  } as File;
  await session.addAttachment(ownerId, 1, file);
  assert.notEqual(indexedDb.getChunk(`${attachmentId}:0`), undefined);

  liveVault.trashedAttachmentIds = [attachmentId];
  liveVault.purgeCommitJson = JSON.stringify({
    item_revision: 4,
    attachments: [
      {
        id: attachmentId,
        expected_revision: 1,
        attachment_revision: 2,
        chunk_count: 1,
        encrypted_record_json: JSON.stringify({ state: "tombstone" }),
      },
    ],
  });
  const purgedRevision = await session.purgeItem(ownerId, 3);

  assert.equal(purgedRevision, 4);
  assert.deepEqual(indexedDb.getManifest(attachmentId), {
    format: 1,
    revision: 2,
    encryptedRecordJson: JSON.stringify({ state: "tombstone" }),
  });
  assert.equal(indexedDb.getChunk(`${attachmentId}:0`), undefined);
  assert.equal(indexedDb.getVaultRecord().version, 2);
});

test("encrypted backup restore authenticates before replacing or persisting a fresh vault", async () => {
  const indexedDb = installWritableIndexedDb({ format: 1, version: 0, snapshotJson: null });
  const backup = JSON.stringify({ backup: "ciphertext" });
  const fresh = new FakeVault(false, false, undefined, null, false);
  let factorySnapshot: string | null = null;
  const factory: VaultFactory = (snapshot) => {
    factorySnapshot = snapshot;
    return new FakeVault(false, false, undefined, null, true, "backup-passphrase", backup);
  };
  const session = newSession(factory, fresh);

  await session.importEncryptedSnapshot(backup, "backup-passphrase");

  assert.equal(factorySnapshot, backup);
  assert.equal(session.isInitialized(), true);
  assert.equal(session.isUnlocked(), true);
  assert.deepEqual(indexedDb.getVaultRecord(), {
    format: 1,
    version: 1,
    snapshotJson: backup,
  });
});

test("encrypted backup restore rejects wrong authentication without changing the fresh vault", async () => {
  const backup = JSON.stringify({ backup: "ciphertext" });
  const fresh = new FakeVault(false, false, undefined, null, false);
  const factory: VaultFactory = () =>
    new FakeVault(false, false, undefined, null, true, "correct-passphrase", backup);
  const session = newSession(factory, fresh);

  await assert.rejects(
    session.importEncryptedSnapshot(backup, "wrong-passphrase"),
    /wrong passphrase/,
  );
  assert.equal(session.isInitialized(), false);
  assert.equal(session.isUnlocked(), false);
  assert.equal(fresh.snapshotCount, 0, "failed authentication must not snapshot or mutate the fresh vault");
});

test("encrypted backup restore cannot overwrite an initialized browser vault", async () => {
  const liveVault = new FakeVault(true, false);
  let factoryCalls = 0;
  const session = newSession(
    () => {
      factoryCalls += 1;
      return new FakeVault(false, false);
    },
    liveVault,
  );

  await assert.rejects(
    session.importEncryptedSnapshot("{}", "passphrase"),
    /available only before this browser vault is created/,
  );
  assert.equal(factoryCalls, 0);
  assert.equal(session.isUnlocked(), true);
});

test("encrypted backup restore persistence failure leaves the fresh vault healthy and retryable", async () => {
  installWritableIndexedDb(
    { format: 1, version: 0, snapshotJson: null },
    { failWrites: true },
  );
  const backup = JSON.stringify({ backup: "ciphertext" });
  const fresh = new FakeVault(false, false, undefined, null, false);
  const factory: VaultFactory = (snapshot) => {
    if (snapshot === backup) {
      return new FakeVault(false, false, undefined, null, true, "backup-passphrase", backup);
    }
    return new FakeVault(false, false, undefined, null, false);
  };
  const session = newSession(factory, fresh);

  await assert.rejects(
    session.importEncryptedSnapshot(backup, "backup-passphrase"),
    /disk full/,
  );
  assert.equal(session.isInitialized(), false);
  assert.equal(session.isUnlocked(), false);
  assert.deepEqual(session.listItems(), []);
});

test("session resume rotation is returned only after durable persistence succeeds", async () => {
  installFailingIndexedDb();
  const liveVault = new FakeVault(true, false);
  const session = newSession(() => new FakeVault(false, false), liveVault);

  await assert.rejects(session.createSessionResume(), VaultDurabilityError);
  assert.equal(liveVault.sessionResumeCount, 1);
  assert.equal(session.isUnlocked(), false);
  await assert.rejects(session.createSessionResume(), VaultDurabilityError);
  assert.equal(
    liveVault.sessionResumeCount,
    1,
    "a poisoned session must not issue another credential",
  );
});

test("session resume reloads newer durable state before accepting a cross-tab payload", async () => {
  const latestSnapshot = JSON.stringify({ generation: 2 });
  installSnapshotIndexedDb({
    format: 1,
    version: 2,
    snapshotJson: latestSnapshot,
  });
  let factorySnapshot: string | null = null;
  const staleVault = new FakeVault(false, false, undefined, "stale");
  const factory: VaultFactory = (snapshot) => {
    factorySnapshot = snapshot;
    return new FakeVault(false, false, undefined, "fresh");
  };
  const session = newSession(factory, staleVault, 1);

  await assert.rejects(session.unlockWithSessionResume("stale"), /stale resume payload/);
  assert.equal(factorySnapshot, latestSnapshot);
  assert.equal(session.isUnlocked(), false);

  await session.unlockWithSessionResume("fresh");
  assert.equal(session.isUnlocked(), true);
});

test("deadline reads are parsed without persistence or mutation", () => {
  const liveVault = new FakeVault(true, false);
  liveVault.deadlineJson = JSON.stringify([
    {
      itemId: "00000000-0000-0000-0000-000000000001",
      kind: "document",
      title: "Passport",
      label: "Document expiry",
      date: "2026-09-20",
      daysUntil: 1,
      revision: 3,
    },
  ]);
  const session = newSession(() => new FakeVault(false, false), liveVault);

  assert.deepEqual(session.listDeadlines("2026-09-19"), [
    {
      itemId: "00000000-0000-0000-0000-000000000001",
      kind: "document",
      title: "Passport",
      label: "Document expiry",
      date: "2026-09-20",
      daysUntil: 1,
      revision: 3,
    },
  ]);
  assert.equal(liveVault.snapshotCount, 0);
  assert.equal(liveVault.putCount, 0);
});

test("encrypted sync acceptance compare-and-swaps through the session durability fence", async () => {
  const indexedDb = installWritableIndexedDb({
    format: 1,
    version: 0,
    snapshotJson: JSON.stringify({ encrypted: true }),
  });
  const liveVault = new FakeVault(true, false);
  const local: EncryptedVaultItemV1 = {
    format_version: 1,
    payload_schema_version: 8,
    algorithm: "xchacha20poly1305",
    object_id: "00000000-0000-4000-8000-0000000000cc",
    key_id: "00000000-0000-4000-8000-0000000000dd",
    revision: 1,
    key_nonce: Array(24).fill(1),
    wrapped_item_key: [2, 3, 4],
    payload_nonce: Array(24).fill(5),
    ciphertext: [6, 7, 8],
  };
  const remote = { ...local, revision: 2, ciphertext: [9, 10, 11] };
  liveVault.encryptedSyncItemJson = JSON.stringify(local);
  const session = newSession(() => new FakeVault(false, false), liveVault);

  assert.deepEqual(await session.loadEncryptedItemForSync(local.object_id), local);
  assert.deepEqual(await session.listEncryptedItemIdsForSync(), [local.object_id]);
  assert.equal(await session.encryptedItemIsTombstoneForSync(local.object_id), false);
  await session.applyRemoteEncryptedItemForSync(remote, local);

  assert.deepEqual(await session.loadEncryptedItemForSync(local.object_id), remote);
  assert.equal(session.isUnlocked(), true, "opaque sync must preserve the in-WASM root key");
  assert.equal(indexedDb.getVaultRecord().version, 1);

  await assert.rejects(
    session.applyRemoteEncryptedItemForSync({ ...remote, revision: 3 }, local),
    /encrypted sync precondition failed/,
  );
  assert.equal(session.isUnlocked(), true, "a stale sync precondition is recoverable");
  assert.equal(indexedDb.getVaultRecord().version, 1);
});
