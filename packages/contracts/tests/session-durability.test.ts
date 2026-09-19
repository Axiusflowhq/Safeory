import assert from "node:assert/strict";
import test from "node:test";

import {
  VaultDurabilityError,
  VaultSession,
  type VaultFactory,
  type WasmVaultLike,
} from "../src/session";

class FakeVault implements WasmVaultLike {
  unlocked: boolean;
  recoveryInstalled: boolean;
  putCount = 0;
  sessionResumeCount = 0;
  snapshotCount = 0;
  deadlineJson = "[]";
  failMutation = false;
  private readonly onPut: (() => void) | undefined;
  private readonly expectedResumePayload: string | null;

  constructor(
    unlocked = true,
    recoveryInstalled = false,
    onPut?: () => void,
    expectedResumePayload: string | null = null,
  ) {
    this.unlocked = unlocked;
    this.recoveryInstalled = recoveryInstalled;
    this.onPut = onPut;
    this.expectedResumePayload = expectedResumePayload;
  }

  isInitialized(): boolean {
    return true;
  }

  isUnlocked(): boolean {
    return this.unlocked;
  }

  create(): void {}

  unlock(): void {
    this.unlocked = true;
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
    return JSON.stringify({ recoveryInstalled: this.recoveryInstalled });
  }

  putItemJson(): void {
    if (this.failMutation) throw new Error("validation failed");
    this.putCount += 1;
    this.onPut?.();
  }

  getItemJson(): string {
    return "{}";
  }

  listItemsJson(): string {
    return "[]";
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
