/**
 * Vault session controller shared by the web app and the browser extension.
 *
 * Owns the `WasmVault` instance and persists the ciphertext snapshot to
 * IndexedDB after every mutation. The root key lives only inside the WASM
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

export class VaultSession {
  private vault: WasmVaultLike;
  private readonly factory: VaultFactory;
  private persistenceTail: Promise<void> = Promise.resolve();
  private persistenceVersion: number;

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
    return this.vault.isInitialized();
  }

  isUnlocked(): boolean {
    return this.vault.isUnlocked();
  }

  /** Create a brand-new vault and persist it. */
  async create(passphrase: string): Promise<void> {
    this.vault.create(passphrase);
    await this.persist();
  }

  /** Unlock the loaded vault. */
  unlock(passphrase: string): void {
    this.vault.unlock(passphrase);
  }

  /** Lock (zeroize the in-memory key) without clearing persistence. */
  lock(): void {
    this.vault.lock();
  }

  /** Add a new item; persists the updated ciphertext snapshot. */
  async putItem(itemJson: string): Promise<void> {
    this.vault.putItemJson(itemJson);
    await this.persist();
  }

  getItem(id: string): string {
    return this.vault.getItemJson(id);
  }

  listItems(): ListedItem[] {
    return JSON.parse(this.vault.listItemsJson()) as ListedItem[];
  }

  async updateItem(itemJson: string, expectedRevision: number): Promise<bigint> {
    const rev = this.vault.updateItemJson(itemJson, expectedRevision);
    await this.persist();
    return rev;
  }

  async trashItem(id: string, expectedRevision: number, deletedAtMs: number): Promise<bigint> {
    const rev = this.vault.trashItem(id, expectedRevision, deletedAtMs);
    await this.persist();
    return rev;
  }

  /** Wipe local persistence and reset to a fresh vault. */
  async reset(): Promise<void> {
    await this.enqueuePersistence(async () => {
      this.persistenceVersion = await clearSnapshot(this.persistenceVersion);
    });
    this.vault = this.factory(null);
  }

  /** Fetch the Emergency Card, or null if not set. */
  getEmergencyCard(): { card: EmergencyCard; revision: number } | null {
    const raw = this.vault.getEmergencyCardJson();
    if (raw === null) return null;
    return JSON.parse(raw) as { card: EmergencyCard; revision: number };
  }

  /** Set the Emergency Card; persists and returns the new revision. */
  async setEmergencyCard(card: EmergencyCard): Promise<bigint> {
    const rev = this.vault.setEmergencyCardJson(JSON.stringify(card));
    await this.persist();
    return rev;
  }

  /** Install a recovery kit from a hex secret; persists the new wrap. */
  async installRecoveryKit(secretHex: string): Promise<void> {
    this.vault.installRecoveryKit(secretHex);
    await this.persist();
  }

  hasRecoveryKit(): boolean {
    return this.vault.hasRecoveryKit();
  }

  verifyRecoveryKit(secretHex: string): boolean {
    return this.vault.verifyRecoveryKit(secretHex);
  }

  /** Unlock with a recovery kit secret instead of the master passphrase. */
  unlockWithRecoveryKit(secretHex: string): void {
    this.vault.unlockWithRecoveryKit(secretHex);
  }

  private persist(): Promise<void> {
    // Capture the post-mutation state now. Later mutations may run before this
    // write reaches IndexedDB, but they cannot change the immutable snapshot
    // queued here or overtake it on disk.
    const snapshotJson = this.vault.snapshotJson();
    return this.enqueuePersistence(async () => {
      this.persistenceVersion = await saveSnapshot(snapshotJson, this.persistenceVersion);
    });
  }

  private enqueuePersistence(operation: () => Promise<void>): Promise<void> {
    const queued = this.persistenceTail.then(operation, operation);
    this.persistenceTail = queued.catch(() => undefined);
    return queued;
  }
}
