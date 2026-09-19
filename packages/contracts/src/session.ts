/**
 * Browser vault session controller used by the web app.
 *
 * Owns the `WasmVault` instance and persists the ciphertext snapshot to
 * IndexedDB after every mutation. The extension currently owns a separate
 * chrome.storage.local persistence path; it does not use this IndexedDB
 * controller. The root key lives only inside the WASM
 * module and is dropped on `lock()`.
 */

import { clearSnapshot, loadSnapshot, saveSnapshot } from "./persistence";

/** The minimal surface of `vault-wasm` this controller relies on. Declared
 * structurally so the package does not need a build-time dependency on the
 * generated WASM bindings (which are produced by `wasm-pack`). */
export interface WasmVaultLike {
  isInitialized(): boolean;
  isUnlocked(): boolean;
  create(passphrase: string): void;
  unlock(passphrase: string): void;
  lock(): void;
  snapshotJson(): string;
  putItemJson(itemJson: string): void;
  getItemJson(id: string): string;
  listItemsJson(): string;
  listDeadlinesJson(todayYmd: string): string;
  updateItemJson(itemJson: string, expectedRevision: number | bigint): bigint;
  trashItem(id: string, expectedRevision: number | bigint, deletedAtMs: number | bigint): bigint;
  getEmergencyCardJson(): string | null;
  setEmergencyCardJson(cardJson: string): bigint;
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

export interface EmergencyContact {
  name: string;
  relation: string;
  phone: string;
  email: string;
  notes: string;
}

export interface EmergencyCard {
  selected_item_ids: string[];
  contacts: EmergencyContact[];
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

  /** Unlock the loaded vault. */
  unlock(passphrase: string): void {
    this.assertHealthy();
    this.vault.unlock(passphrase);
  }

  /** Lock (zeroize the in-memory key) without clearing persistence. */
  lock(): void {
    this.vault.lock();
  }

  /** Add a new item; persists the updated ciphertext snapshot. */
  async putItem(itemJson: string): Promise<void> {
    await this.mutateAndPersist(() => this.vault.putItemJson(itemJson));
  }

  getItem(id: string): string {
    this.assertHealthy();
    return this.vault.getItemJson(id);
  }

  listItems(): ListedItem[] {
    this.assertHealthy();
    return JSON.parse(this.vault.listItemsJson()) as ListedItem[];
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
    return this.mutateAndPersist(() => this.vault.updateItemJson(itemJson, expectedRevision));
  }

  async trashItem(id: string, expectedRevision: number, deletedAtMs: number): Promise<bigint> {
    return this.mutateAndPersist(() => this.vault.trashItem(id, expectedRevision, deletedAtMs));
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
