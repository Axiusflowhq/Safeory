/**
 * Browser vault session controller used by the web app.
 *
 * Owns the `WasmVault` instance and persists the ciphertext snapshot to
 * IndexedDB after every mutation. The extension currently owns a separate
 * chrome.storage.local persistence path; it does not use this IndexedDB
 * controller. The root key lives only inside the WASM
 * module and is dropped on `lock()`.
 */

import {
  clearSnapshot,
  loadAttachmentChunk,
  loadAttachmentManifest,
  loadSnapshot,
  loadVaultBackupState,
  replaceVaultFromBackup,
  saveAttachmentDelete,
  saveAttachmentImport,
  saveItemPurge,
  saveSnapshot,
  type PersistedAttachmentState,
} from "./persistence";
import type { EncryptedVaultItemV1 } from "./sync-vault-item";

const ATTACHMENT_CHUNK_SIZE = 1024 * 1024;
const ATTACHMENT_MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024;
const ENCRYPTED_BROWSER_BACKUP_FORMAT = "safeory-encrypted-browser-backup";
const ENCRYPTED_BROWSER_BACKUP_VERSION = 1;

interface EncryptedBrowserBackupV1 {
  format: typeof ENCRYPTED_BROWSER_BACKUP_FORMAT;
  format_version: typeof ENCRYPTED_BROWSER_BACKUP_VERSION;
  snapshot_json: string;
  attachment_manifests: Array<{
    attachment_id: string;
    revision: number;
    encrypted_record_json: string;
  }>;
  attachment_chunks: Array<{
    attachment_id: string;
    index: number;
    ciphertext_base64: string;
  }>;
}

interface EncodedAttachmentState {
  manifests: PersistedAttachmentState["manifests"];
  chunks: Array<{
    attachmentId: string;
    index: number;
    ciphertextBase64: string;
  }>;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const blockSize = 32 * 1024;
  for (let offset = 0; offset < bytes.length; offset += blockSize) {
    const block = bytes.subarray(offset, Math.min(offset + blockSize, bytes.length));
    binary += String.fromCharCode(...block);
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  if (value.length > 2 * 1024 * 1024) {
    throw new Error("encrypted backup attachment chunk is oversized");
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new Error("encrypted backup attachment chunk is invalid");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function decodeEncryptedBrowserBackup(backupJson: string): {
  snapshotJson: string;
  encodedAttachmentState: EncodedAttachmentState;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(backupJson);
  } catch {
    throw new Error("Encrypted backup is not valid JSON.");
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !("format" in parsed) ||
    (parsed as { format?: unknown }).format !== ENCRYPTED_BROWSER_BACKUP_FORMAT
  ) {
    return {
      snapshotJson: backupJson,
      encodedAttachmentState: { manifests: [], chunks: [] },
    };
  }
  const candidate = parsed as Partial<EncryptedBrowserBackupV1>;
  if (
    candidate.format_version !== ENCRYPTED_BROWSER_BACKUP_VERSION ||
    typeof candidate.snapshot_json !== "string" ||
    !Array.isArray(candidate.attachment_manifests) ||
    !Array.isArray(candidate.attachment_chunks)
  ) {
    throw new Error("Encrypted backup format is unsupported or invalid.");
  }
  if (candidate.attachment_manifests.length > 16 * 1024) {
    throw new Error("Encrypted backup contains too many attachments.");
  }
  const manifests = candidate.attachment_manifests.map((manifest) => {
    if (
      typeof manifest !== "object" ||
      manifest === null ||
      typeof manifest.attachment_id !== "string" ||
      !Number.isSafeInteger(manifest.revision) ||
      manifest.revision < 1 ||
      typeof manifest.encrypted_record_json !== "string"
    ) {
      throw new Error("Encrypted backup attachment metadata is invalid.");
    }
    return {
      attachmentId: manifest.attachment_id,
      revision: manifest.revision,
      encryptedRecordJson: manifest.encrypted_record_json,
    };
  });
  const chunks = candidate.attachment_chunks.map((chunk) => {
    if (
      typeof chunk !== "object" ||
      chunk === null ||
      typeof chunk.attachment_id !== "string" ||
      !Number.isSafeInteger(chunk.index) ||
      chunk.index < 0 ||
      typeof chunk.ciphertext_base64 !== "string" ||
      chunk.ciphertext_base64.length > 2 * 1024 * 1024
    ) {
      throw new Error("Encrypted backup attachment chunk metadata is invalid.");
    }
    return {
      attachmentId: chunk.attachment_id,
      index: chunk.index,
      ciphertextBase64: chunk.ciphertext_base64,
    };
  });
  return {
    snapshotJson: candidate.snapshot_json,
    encodedAttachmentState: { manifests, chunks },
  };
}

function materializeAttachmentState(encoded: EncodedAttachmentState): PersistedAttachmentState {
  return {
    manifests: encoded.manifests,
    chunks: encoded.chunks.map((chunk) => ({
      attachmentId: chunk.attachmentId,
      index: chunk.index,
      ciphertext: base64ToBytes(chunk.ciphertextBase64),
    })),
  };
}

function validateRestoredAttachmentState(
  vault: WasmVaultLike,
  state: PersistedAttachmentState,
): void {
  const manifests = new Map(state.manifests.map((manifest) => [manifest.attachmentId, manifest]));
  const chunks = new Map<string, PersistedAttachmentState["chunks"][number]>(
    state.chunks.map((chunk) => [`${chunk.attachmentId}:${chunk.index}`, chunk] as const),
  );
  if (manifests.size !== state.manifests.length || chunks.size !== state.chunks.length) {
    throw new Error("Encrypted backup contains duplicate attachment records.");
  }
  const referencedAttachments = new Set<string>();
  const usedChunks = new Set<string>();
  const listed = JSON.parse(vault.listItemsJson()) as ListedItem[];
  for (const entry of listed) {
    const item = JSON.parse(vault.getItemJson(entry.item.id)) as { attachments?: unknown };
    if (!Array.isArray(item.attachments) || !item.attachments.every((id) => typeof id === "string")) {
      throw new Error("Encrypted backup item attachment references are invalid.");
    }
    for (const attachmentId of item.attachments as string[]) {
      if (referencedAttachments.has(attachmentId)) {
        throw new Error("Encrypted backup attachment is referenced more than once.");
      }
      referencedAttachments.add(attachmentId);
      const stored = manifests.get(attachmentId);
      if (stored === undefined) {
        throw new Error("Encrypted backup is missing an attachment manifest.");
      }
      const summary = JSON.parse(
        vault.describeAttachmentJson(entry.item.id, attachmentId, stored.encryptedRecordJson),
      ) as AttachmentSummary;
      if (
        summary.revision !== stored.revision ||
        !Number.isSafeInteger(summary.chunk_count) ||
        summary.chunk_count < 0 ||
        summary.chunk_count > 64
      ) {
        throw new Error("Encrypted backup attachment manifest is inconsistent.");
      }
      let plaintextBytes = 0;
      for (let index = 0; index < summary.chunk_count; index += 1) {
        const key = `${attachmentId}:${index}`;
        const chunk = chunks.get(key);
        if (chunk === undefined) {
          throw new Error("Encrypted backup is missing attachment ciphertext.");
        }
        const plaintext = vault.decryptAttachmentChunk(
          entry.item.id,
          attachmentId,
          stored.encryptedRecordJson,
          index,
          chunk.ciphertext,
        );
        plaintextBytes += plaintext.byteLength;
        usedChunks.add(key);
      }
      if (plaintextBytes !== summary.plaintext_size) {
        throw new Error("Encrypted backup attachment plaintext size is inconsistent.");
      }
    }
  }
  if (state.chunks.some((chunk) => !usedChunks.has(`${chunk.attachmentId}:${chunk.index}`))) {
    throw new Error("Encrypted backup contains orphaned attachment ciphertext.");
  }
}

/** The minimal surface of `vault-wasm` this controller relies on. Declared
 * structurally so the package does not need a build-time dependency on the
 * generated WASM bindings (which are produced by `wasm-pack`). */
export interface WasmVaultLike {
  isInitialized(): boolean;
  isUnlocked(): boolean;
  create(passphrase: string): void;
  unlock(passphrase: string): void;
  changePassphrase(currentPassphrase: string, newPassphrase: string): void;
  lock(): void;
  createSessionResumeJson(): string;
  unlockWithSessionResumeJson(payloadJson: string): void;
  snapshotJson(): string;
  putItemJson(itemJson: string): void;
  getItemJson(id: string): string;
  getEncryptedItemJson(id: string): string | null;
  listEncryptedItemIdsJson(): string;
  applyEncryptedItemJson(nextJson: string, expectedJson?: string): void;
  listItemsJson(): string;
  exportReadableJson(): string;
  listDeadlinesJson(todayYmd: string): string;
  updateItemJson(itemJson: string, expectedRevision: number | bigint): bigint;
  trashItem(id: string, expectedRevision: number | bigint, deletedAtMs: number | bigint): bigint;
  beginAttachmentImportJson(
    ownerItemId: string,
    expectedItemRevision: number | bigint,
    filename: string,
    plaintextSize: number | bigint,
  ): string;
  encryptAttachmentImportChunk(
    attachmentId: string,
    index: number,
    plaintext: Uint8Array,
  ): Uint8Array;
  cancelAttachmentImport(attachmentId: string): void;
  commitAttachmentImportJson(attachmentId: string): string;
  describeAttachmentJson(
    ownerItemId: string,
    attachmentId: string,
    encryptedRecordJson: string,
  ): string;
  decryptAttachmentChunk(
    ownerItemId: string,
    attachmentId: string,
    encryptedRecordJson: string,
    index: number,
    ciphertext: Uint8Array,
  ): Uint8Array;
  deleteAttachmentJson(
    ownerItemId: string,
    attachmentId: string,
    expectedItemRevision: number | bigint,
    expectedAttachmentRevision: number | bigint,
    encryptedRecordJson: string,
    deletedAtMs: number | bigint,
  ): string;
  listTrashedItemsJson(): string;
  restoreItem(id: string, expectedRevision: number | bigint): bigint;
  trashedAttachmentIdsJson(id: string, expectedRevision: number | bigint): string;
  purgeItemJson(
    id: string,
    expectedRevision: number | bigint,
    attachmentRecordsJson: string,
  ): string;
  getEmergencyCardJson(): string | null;
  setEmergencyCardJson(cardJson: string): bigint;
  createTrustedDevicePairingChallengeJson(principalId: string, deviceId: string): string;
  completeTrustedDevicePairingJson(proofJson: string): bigint;
  installRecoveryKit(secretHex: string): void;
  hasRecoveryKit(): boolean;
  verifyRecoveryKit(secretHex: string): boolean;
  unlockWithRecoveryKit(secretHex: string): void;
}

/** Static (constructor-level) bindings on the WASM module. */
export interface WasmStatics {
  generateRecoverySecret(): string;
  generatePassword(length: number): string;
}

/** Construct a `WasmVault` from a snapshot, or a fresh one when `null`. */
export type VaultFactory = (snapshotJson: string | null) => WasmVaultLike;

export interface ListedItem {
  item: { id: string; title: string; kind: string };
  revision: number;
}

export interface DeadlineSummary {
  itemId: string;
  kind: string;
  title: string;
  label: string;
  date: string;
  daysUntil: number;
  revision: number;
}

export interface AttachmentSummary {
  id: string;
  revision: number;
  filename: string;
  plaintext_size: number;
  chunk_count: number;
}

export interface TrashedItemSummary {
  id: string;
  title: string;
  kind: string;
  revision: number;
  deleted_at_ms: number;
}

interface AttachmentImportCommitPayload {
  summary: AttachmentSummary;
  item_revision: number;
  encrypted_record_json: string;
}

interface AttachmentDeleteCommitPayload {
  item_revision: number;
  attachment_revision: number;
  encrypted_record_json: string;
}

interface ItemPurgeCommitPayload {
  item_revision: number;
  attachments: Array<{
    id: string;
    expected_revision: number;
    attachment_revision: number;
    chunk_count: number;
    encrypted_record_json: string;
  }>;
}

export interface EmergencyContact {
  name: string;
  relation: string;
  phone: string;
  email: string;
  notes: string;
}

export interface TrustedDevice {
  id: string;
  label: string;
  /** X25519 recipient-encryption key; not sender authentication by itself. */
  encryption_public_key_hex: string;
  /** Ed25519 verification key installed only after the dedicated dual-key pairing proof. */
  signing_public_key_hex: string | null;
}

export interface TrustedPrincipal {
  id: string;
  name: string;
  relation: string;
  devices: TrustedDevice[];
}

export interface PairingChallengeV1 {
  format_version: 1;
  request_id: string;
  principal_id: string;
  device_id: string;
  encryption_public: number[];
  verifier_ephemeral_public: number[];
  nonce: number[];
  ciphertext: number[];
}

export interface PairingProofV1 {
  format_version: 1;
  request_id: string;
  principal_id: string;
  device_id: string;
  signing_public: number[];
  encryption_public: number[];
  verifier_ephemeral_public: number[];
  challenge: number[];
  signature: number[];
}

export interface EmergencyCard {
  selected_item_ids: string[];
  contacts: EmergencyContact[];
  principals: TrustedPrincipal[];
  retired_principal_ids: string[];
  retired_device_ids: string[];
  retired_signing_public_key_hexes: string[];
  instructions: string;
}

/**
 * A mutation changed the in-memory encrypted vault, but its replacement
 * snapshot could not be durably committed. The session is poisoned and must
 * be reloaded from IndexedDB before it can be used again.
 */
export class VaultDurabilityError extends Error {
  constructor(cause?: unknown) {
    super("Saving the encrypted vault failed. Reload before continuing.", { cause });
    this.name = "VaultDurabilityError";
  }
}

export class VaultSession {
  private vault: WasmVaultLike;
  private readonly factory: VaultFactory;
  private mutationTail: Promise<void> = Promise.resolve();
  private persistenceVersion: number;
  private durabilityError: VaultDurabilityError | null = null;

  private constructor(factory: VaultFactory, vault: WasmVaultLike, persistenceVersion: number) {
    this.factory = factory;
    this.vault = vault;
    this.persistenceVersion = persistenceVersion;
  }

  /** Load the vault from IndexedDB, or start a fresh (uninitialized) one. */
  static async load(factory: VaultFactory): Promise<VaultSession> {
    const snapshot = await loadSnapshot();
    return new VaultSession(factory, factory(snapshot.snapshotJson), snapshot.version);
  }

  isInitialized(): boolean {
    return this.durabilityError === null && this.vault.isInitialized();
  }

  isUnlocked(): boolean {
    return this.durabilityError === null && this.vault.isUnlocked();
  }

  /** Create a brand-new vault and persist it. */
  async create(passphrase: string): Promise<void> {
    await this.mutateAndPersist(() => this.vault.create(passphrase));
  }

  async changePassphrase(currentPassphrase: string, newPassphrase: string): Promise<void> {
    await this.mutateAndPersist(() =>
      this.vault.changePassphrase(currentPassphrase, newPassphrase),
    );
  }

  /**
   * Restore an encrypted browser backup into a fresh local vault. The candidate
   * snapshot is parsed and authenticated with its existing master passphrase
   * before it replaces the in-memory vault or is written to IndexedDB.
   */
  async importEncryptedSnapshot(snapshotJson: string, passphrase: string): Promise<void> {
    await this.enqueueMutation(async () => {
      this.assertHealthy();
      if (this.vault.isInitialized()) {
        throw new Error("Encrypted backup restore is available only before this browser vault is created.");
      }
      const decoded = decodeEncryptedBrowserBackup(snapshotJson);
      const candidate = this.factory(decoded.snapshotJson);
      if (!candidate.isInitialized()) {
        throw new Error("Encrypted backup does not contain an initialized Safeory vault.");
      }
      candidate.unlock(passphrase);
      const attachmentState = materializeAttachmentState(decoded.encodedAttachmentState);
      validateRestoredAttachmentState(candidate, attachmentState);
      const nextVersion = await replaceVaultFromBackup(
        decoded.snapshotJson,
        this.persistenceVersion,
        attachmentState,
      );
      this.vault.lock();
      this.vault = candidate;
      this.persistenceVersion = nextVersion;
    });
  }

  /** Unlock the loaded vault. */
  unlock(passphrase: string): void {
    this.assertHealthy();
    this.vault.unlock(passphrase);
  }

  /** Lock (zeroize the in-memory key) without clearing persistence. */
  lock(): void {
    this.vault.lock();
  }

  /**
   * Rotate and durably persist the generation-bound browser reload credential.
   * The credential is returned only after the snapshot CAS succeeds, so a
   * concurrent tab cannot successfully issue a resume credential from stale
   * persisted state.
   */
  createSessionResume(): Promise<string> {
    return this.mutateAndPersist(() => this.vault.createSessionResumeJson());
  }

  /**
   * Resume from the latest durable snapshot. Re-reading IndexedDB before
   * authentication prevents a tab that loaded an older snapshot from replaying
   * a credential invalidated by another tab's successful rotation.
   */
  unlockWithSessionResume(payloadJson: string): Promise<void> {
    return this.enqueueMutation(async () => {
      this.assertHealthy();
      const latest = await loadSnapshot();
      this.assertHealthy();
      if (latest.version !== this.persistenceVersion) {
        const refreshed = this.factory(latest.snapshotJson);
        refreshed.lock();
        this.vault = refreshed;
        this.persistenceVersion = latest.version;
      }
      this.vault.unlockWithSessionResumeJson(payloadJson);
    });
  }

  /** Add a new item; persists the updated ciphertext snapshot. */
  async putItem(itemJson: string): Promise<void> {
    await this.mutateAndPersist(() => this.vault.putItemJson(itemJson));
  }

  getItem(id: string): string {
    this.assertHealthy();
    return this.vault.getItemJson(id);
  }

  /** Read one opaque encrypted record after earlier local mutations settle. */
  loadEncryptedItemForSync(id: string): Promise<EncryptedVaultItemV1 | null> {
    return this.mutationTail.then(() => {
      this.assertHealthy();
      const encoded = this.vault.getEncryptedItemJson(id);
      return encoded === null ? null : JSON.parse(encoded) as EncryptedVaultItemV1;
    });
  }

  /** List all sync-eligible ciphertext object IDs after local writes settle. */
  listEncryptedItemIdsForSync(): Promise<string[]> {
    return this.mutationTail.then(() => {
      this.assertHealthy();
      return JSON.parse(this.vault.listEncryptedItemIdsJson()) as string[];
    });
  }

  /**
   * Durably compare-and-swap a pulled encrypted item while preserving any
   * unlocked root key inside WASM. The exact expected ciphertext protects the
   * reconciliation decision from intervening local edits.
   */
  async applyRemoteEncryptedItemForSync(
    next: EncryptedVaultItemV1,
    expectedLocal: EncryptedVaultItemV1 | null,
  ): Promise<void> {
    await this.mutateAndPersist(() =>
      this.vault.applyEncryptedItemJson(
        JSON.stringify(next),
        expectedLocal === null ? undefined : JSON.stringify(expectedLocal),
      ),
    );
  }

  listItems(): ListedItem[] {
    this.assertHealthy();
    return JSON.parse(this.vault.listItemsJson()) as ListedItem[];
  }

  /**
   * Return a complete plaintext portable export. This is intentionally a
   * separate explicit disclosure path from list/get projections and is only
   * available while the vault is unlocked and the durability state is healthy.
   */
  exportReadableVault(): string {
    this.assertHealthy();
    this.assertUnlocked();
    return this.vault.exportReadableJson();
  }

  /**
   * Return the already-encrypted browser snapshot for a user-initiated backup.
   * The snapshot contains ciphertext and wrapped key material, never the
   * master passphrase, raw root key, or recovery secret.
   */
  async exportEncryptedSnapshot(): Promise<string> {
    this.assertHealthy();
    this.assertUnlocked();
    const state = await loadVaultBackupState(this.persistenceVersion);
    const backup: EncryptedBrowserBackupV1 = {
      format: ENCRYPTED_BROWSER_BACKUP_FORMAT,
      format_version: ENCRYPTED_BROWSER_BACKUP_VERSION,
      snapshot_json: state.snapshotJson,
      attachment_manifests: state.manifests.map((manifest) => ({
        attachment_id: manifest.attachmentId,
        revision: manifest.revision,
        encrypted_record_json: manifest.encryptedRecordJson,
      })),
      attachment_chunks: state.chunks.map((chunk) => ({
        attachment_id: chunk.attachmentId,
        index: chunk.index,
        ciphertext_base64: bytesToBase64(chunk.ciphertext),
      })),
    };
    return JSON.stringify(backup);
  }

  /**
   * Derive redacted deadline summaries for the caller's local calendar date.
   * This is a read-only WASM projection and never touches persistence.
   */
  listDeadlines(todayYmd: string): DeadlineSummary[] {
    this.assertHealthy();
    return JSON.parse(this.vault.listDeadlinesJson(todayYmd)) as DeadlineSummary[];
  }

  async updateItem(itemJson: string, expectedRevision: number): Promise<bigint> {
    return this.mutateAndPersist(() =>
      this.vault.updateItemJson(itemJson, BigInt(expectedRevision)),
    );
  }

  async trashItem(id: string, expectedRevision: number, deletedAtMs: number): Promise<bigint> {
    return this.mutateAndPersist(() =>
      this.vault.trashItem(id, BigInt(expectedRevision), BigInt(deletedAtMs)),
    );
  }

  listTrashedItems(): TrashedItemSummary[] {
    this.assertHealthy();
    this.assertUnlocked();
    return JSON.parse(this.vault.listTrashedItemsJson()) as TrashedItemSummary[];
  }

  async restoreItem(id: string, expectedRevision: number): Promise<number> {
    const revision = await this.mutateAndPersist(() =>
      this.vault.restoreItem(id, BigInt(expectedRevision)),
    );
    return Number(revision);
  }

  async purgeItem(id: string, expectedRevision: number): Promise<number> {
    return this.enqueueMutation(async () => {
      this.assertHealthy();
      this.assertUnlocked();
      const beforeSnapshot = this.vault.snapshotJson();
      const attachmentIds = JSON.parse(
        this.vault.trashedAttachmentIdsJson(id, BigInt(expectedRevision)),
      ) as string[];
      const attachmentRecords: unknown[] = [];
      for (const attachmentId of attachmentIds) {
        const stored = await loadAttachmentManifest(attachmentId);
        if (stored === null) {
          throw new Error("A linked attachment is missing, so this item cannot be permanently deleted.");
        }
        attachmentRecords.push(JSON.parse(stored.encryptedRecordJson) as unknown);
      }
      const committed = JSON.parse(
        this.vault.purgeItemJson(
          id,
          BigInt(expectedRevision),
          JSON.stringify(attachmentRecords),
        ),
      ) as ItemPurgeCommitPayload;
      try {
        const snapshotJson = this.vault.snapshotJson();
        this.persistenceVersion = await saveItemPurge(
          snapshotJson,
          this.persistenceVersion,
          committed.attachments.map((attachment) => ({
            attachmentId: attachment.id,
            expectedRevision: attachment.expected_revision,
            nextRevision: attachment.attachment_revision,
            tombstoneRecordJson: attachment.encrypted_record_json,
            chunkCount: attachment.chunk_count,
          })),
        );
        return committed.item_revision;
      } catch (error) {
        throw this.poisonAfterDurabilityFailure(beforeSnapshot, error);
      }
    });
  }

  async addAttachment(
    ownerItemId: string,
    expectedItemRevision: number,
    file: File,
  ): Promise<{ summary: AttachmentSummary; itemRevision: number }> {
    if (!Number.isSafeInteger(file.size) || file.size > ATTACHMENT_MAX_PLAINTEXT_BYTES) {
      throw new Error("Attachment exceeds the 64 MiB browser limit.");
    }
    return this.enqueueMutation(async () => {
      this.assertHealthy();
      this.assertUnlocked();
      const beforeSnapshot = this.vault.snapshotJson();
      const summary = JSON.parse(
        this.vault.beginAttachmentImportJson(
          ownerItemId,
          BigInt(expectedItemRevision),
          file.name,
          BigInt(file.size),
        ),
      ) as AttachmentSummary;
      const chunks: Uint8Array[] = [];
      try {
        for (let index = 0; index < summary.chunk_count; index += 1) {
          const start = index * ATTACHMENT_CHUNK_SIZE;
          const end = Math.min(start + ATTACHMENT_CHUNK_SIZE, file.size);
          const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
          chunks.push(this.vault.encryptAttachmentImportChunk(summary.id, index, plaintext));
        }
      } catch (error) {
        this.vault.cancelAttachmentImport(summary.id);
        throw error;
      }

      let committed: AttachmentImportCommitPayload;
      try {
        committed = JSON.parse(
          this.vault.commitAttachmentImportJson(summary.id),
        ) as AttachmentImportCommitPayload;
      } catch (error) {
        this.vault.cancelAttachmentImport(summary.id);
        throw error;
      }

      try {
        const snapshotJson = this.vault.snapshotJson();
        this.persistenceVersion = await saveAttachmentImport(
          snapshotJson,
          this.persistenceVersion,
          committed.summary.id,
          committed.summary.revision,
          committed.encrypted_record_json,
          chunks,
        );
        return { summary: committed.summary, itemRevision: committed.item_revision };
      } catch (error) {
        throw this.poisonAfterDurabilityFailure(beforeSnapshot, error);
      }
    });
  }

  async listAttachments(
    ownerItemId: string,
    attachmentIds: readonly string[],
  ): Promise<AttachmentSummary[]> {
    this.assertHealthy();
    this.assertUnlocked();
    const summaries: AttachmentSummary[] = [];
    for (const attachmentId of attachmentIds) {
      const stored = await loadAttachmentManifest(attachmentId);
      if (stored === null) throw new Error("An attachment referenced by this item is missing.");
      const summary = JSON.parse(
        this.vault.describeAttachmentJson(
          ownerItemId,
          attachmentId,
          stored.encryptedRecordJson,
        ),
      ) as AttachmentSummary;
      if (summary.revision !== stored.revision) {
        throw new Error("Stored attachment revision is inconsistent.");
      }
      summaries.push(summary);
    }
    return summaries;
  }

  async downloadAttachment(ownerItemId: string, attachmentId: string): Promise<{
    summary: AttachmentSummary;
    blob: Blob;
  }> {
    this.assertHealthy();
    this.assertUnlocked();
    const stored = await loadAttachmentManifest(attachmentId);
    if (stored === null) throw new Error("Attachment was not found.");
    const summary = JSON.parse(
      this.vault.describeAttachmentJson(
        ownerItemId,
        attachmentId,
        stored.encryptedRecordJson,
      ),
    ) as AttachmentSummary;
    const plaintextChunks: BlobPart[] = [];
    let plaintextBytes = 0;
    for (let index = 0; index < summary.chunk_count; index += 1) {
      const ciphertext = await loadAttachmentChunk(attachmentId, index);
      if (ciphertext === null) throw new Error("Attachment ciphertext is incomplete.");
      const plaintext = this.vault.decryptAttachmentChunk(
        ownerItemId,
        attachmentId,
        stored.encryptedRecordJson,
        index,
        ciphertext,
      );
      plaintextBytes += plaintext.byteLength;
      plaintextChunks.push(plaintext.slice().buffer);
    }
    if (plaintextBytes !== summary.plaintext_size) {
      throw new Error("Attachment plaintext size is inconsistent.");
    }
    return { summary, blob: new Blob(plaintextChunks) };
  }

  async deleteAttachment(
    ownerItemId: string,
    expectedItemRevision: number,
    summary: AttachmentSummary,
    deletedAtMs: number,
  ): Promise<number> {
    return this.enqueueMutation(async () => {
      this.assertHealthy();
      this.assertUnlocked();
      const stored = await loadAttachmentManifest(summary.id);
      if (stored === null) throw new Error("Attachment was not found.");
      if (stored.revision !== summary.revision) {
        throw new Error("The attachment changed before it could be deleted.");
      }
      const beforeSnapshot = this.vault.snapshotJson();
      const committed = JSON.parse(
        this.vault.deleteAttachmentJson(
          ownerItemId,
          summary.id,
          BigInt(expectedItemRevision),
          BigInt(summary.revision),
          stored.encryptedRecordJson,
          BigInt(deletedAtMs),
        ),
      ) as AttachmentDeleteCommitPayload;
      try {
        const snapshotJson = this.vault.snapshotJson();
        this.persistenceVersion = await saveAttachmentDelete(
          snapshotJson,
          this.persistenceVersion,
          summary.id,
          summary.revision,
          committed.attachment_revision,
          committed.encrypted_record_json,
          summary.chunk_count,
        );
        return committed.item_revision;
      } catch (error) {
        throw this.poisonAfterDurabilityFailure(beforeSnapshot, error);
      }
    });
  }

  /** Wipe local persistence and reset to a fresh vault. */
  async reset(): Promise<void> {
    await this.enqueueMutation(async () => {
      this.assertHealthy();
      this.persistenceVersion = await clearSnapshot(this.persistenceVersion);
      this.vault.lock();
      this.vault = this.factory(null);
    });
  }

  /** Fetch the Emergency Card, or null if not set. */
  getEmergencyCard(): { card: EmergencyCard; revision: number } | null {
    this.assertHealthy();
    const raw = this.vault.getEmergencyCardJson();
    if (raw === null) return null;
    return JSON.parse(raw) as { card: EmergencyCard; revision: number };
  }

  /** Set the Emergency Card; persists and returns the new revision. */
  async setEmergencyCard(card: EmergencyCard): Promise<bigint> {
    return this.mutateAndPersist(() => this.vault.setEmergencyCardJson(JSON.stringify(card)));
  }

  /** Create a one-shot owner-side pairing challenge. Pending verifier state is
   * session-local and is lost on lock/reload. This does not mutate ciphertext. */
  createTrustedDevicePairingChallenge(
    principalId: string,
    deviceId: string
  ): PairingChallengeV1 {
    this.assertHealthy();
    return JSON.parse(
      this.vault.createTrustedDevicePairingChallengeJson(principalId, deviceId)
    ) as PairingChallengeV1;
  }

  /** Verify a recipient response and persist the resulting signing-key binding. */
  async completeTrustedDevicePairing(proof: PairingProofV1): Promise<bigint> {
    return this.mutateAndPersist(() =>
      this.vault.completeTrustedDevicePairingJson(JSON.stringify(proof))
    );
  }

  /** Install a recovery kit from a hex secret; persists the new wrap. */
  async installRecoveryKit(secretHex: string): Promise<void> {
    await this.mutateAndPersist(() => this.vault.installRecoveryKit(secretHex));
  }

  hasRecoveryKit(): boolean {
    this.assertHealthy();
    return this.vault.hasRecoveryKit();
  }

  verifyRecoveryKit(secretHex: string): boolean {
    this.assertHealthy();
    return this.vault.verifyRecoveryKit(secretHex);
  }

  /** Unlock with a recovery kit secret instead of the master passphrase. */
  unlockWithRecoveryKit(secretHex: string): void {
    this.assertHealthy();
    this.vault.unlockWithRecoveryKit(secretHex);
  }

  private mutateAndPersist<T>(mutate: () => T): Promise<T> {
    return this.enqueueMutation(async () => {
      this.assertHealthy();

      // A pre-mutation encrypted snapshot lets us discard the changed WASM
      // store if the durable CAS fails, without exporting or reimplementing
      // any key material. It is never used to continue the session unlocked.
      const beforeSnapshot = this.vault.snapshotJson();

      // WASM validation/auth/revision failures are expected to be atomic and
      // remain recoverable. Because they throw before this call returns, they
      // bypass the durability-failure handler below and do not poison the session.
      const result = mutate();

      try {
        const snapshotJson = this.vault.snapshotJson();
        this.persistenceVersion = await saveSnapshot(snapshotJson, this.persistenceVersion);
        return result;
      } catch (error) {
        throw this.poisonAfterDurabilityFailure(beforeSnapshot, error);
      }
    });
  }

  private assertHealthy(): void {
    if (this.durabilityError !== null) throw this.durabilityError;
  }

  private assertUnlocked(): void {
    if (!this.vault.isUnlocked()) throw new Error("Vault is locked.");
  }

  private poisonAfterDurabilityFailure(
    beforeSnapshot: string,
    cause: unknown,
  ): VaultDurabilityError {
    const durabilityError = new VaultDurabilityError(cause);
    this.durabilityError = durabilityError;

    // Drop the active root key first. Best-effort restoration replaces the
    // mutated in-memory ciphertext with the pre-mutation snapshot, but the
    // session remains poisoned because a CAS conflict can mean even that
    // snapshot is stale relative to another tab.
    try {
      this.vault.lock();
    } catch {
      // Poisoning is authoritative even if a defensive lock call fails.
    }
    try {
      const restored = this.factory(beforeSnapshot);
      restored.lock();
      this.vault = restored;
    } catch {
      // The locked, poisoned instance remains inaccessible through this API.
    }

    return durabilityError;
  }

  private enqueueMutation<T>(operation: () => Promise<T>): Promise<T> {
    const queued = this.mutationTail.then(operation, operation);
    this.mutationTail = queued.then(
      () => undefined,
      () => undefined,
    );
    return queued;
  }
}
