/**
 * Background service worker: the only component that holds the unlocked WASM
 * vault. It enforces the origin-matching rule (a credential is released only
 * to a page whose exact origin matches the credential's stored website)
 * and never hands the item list or keys to content scripts.
 */

import init, { WasmVault } from "vault-wasm";
import type { ConnectedSingleOwnerVaultSync } from "@safeory/contracts";
import { createSerializedMutationRunner } from "./mutation";
import { saveCapturedCredential } from "./credential-capture";
import { loadSnapshot, saveSnapshot } from "./storage";
import {
  clearExtensionSyncConfiguration,
  loadExtensionSyncConfiguration,
} from "./sync-configuration";
import { enrollExtensionVaultSync, resumeExtensionVaultSync } from "./sync";
import { createSyncRequestRunner } from "./sync-request";
import { createExtensionVaultSyncSession } from "./sync-session";
import type {
  ContentRequest,
  ContentResponse,
  CredentialSummary,
  ExtensionSyncStatus,
  PopupRequest,
  PopupResponse,
} from "./messages";

type ExtensionWasmVault = WasmVault & {
  listCredentialsJson(): string;
  updateItemJson(itemJson: string, expectedRevision: bigint): bigint;
};

// --- Vault lifecycle (single in-memory instance per worker) ---

let vault: ExtensionWasmVault | null = null;
let initPromise: Promise<void> | null = null;
let vaultLoadPromise: Promise<ExtensionWasmVault> | null = null;

const CONTENT_FIND_COOLDOWN_MS = 1_000;
const CONTENT_FILL_AUTH_TTL_MS = 30_000;
const CONTENT_REQUEST_STATE_MAX_ENTRIES = 128;

interface ContentSenderContext {
  tabId: number;
  origin: string;
}

interface ContentRequestState {
  lastFindAt: number;
  lastTouchedAt: number;
  authorization?: {
    token: string;
    expiresAt: number;
  };
}

const contentRequestState = new Map<string, ContentRequestState>();
const SYNC_ALARM_NAME = "safeory.encrypted-sync";
const INITIAL_SYNC_STATUS: ExtensionSyncStatus = {
  phase: "not_configured",
  accountId: null,
  lastSyncedAt: null,
  pendingUploads: 0,
  blockedItems: 0,
  error: null,
};

let syncConnection: ConnectedSingleOwnerVaultSync | null = null;
let syncGeneration = 0;
let syncStatus: ExtensionSyncStatus = { ...INITIAL_SYNC_STATUS };
let syncAbortController: AbortController | null = null;

function ensureInit(): Promise<void> {
  initPromise ??= init({
    module_or_path: chrome.runtime.getURL("vault_wasm_bg.wasm"),
  }).then(() => undefined);
  return initPromise;
}

async function getVault(): Promise<ExtensionWasmVault> {
  await ensureInit();
  if (vault) return vault;
  vaultLoadPromise ??= loadSnapshot()
    .then((snapshot) => {
      const loaded = (
        snapshot === null
          ? new WasmVault()
          : WasmVault.fromSnapshotJson(snapshot)
      ) as ExtensionWasmVault;
      vault = loaded;
      return loaded;
    })
    .finally(() => {
      vaultLoadPromise = null;
    });
  return vaultLoadPromise;
}

/**
 * Serialize persistent mutations and fail closed if chrome.storage cannot
 * durably save the resulting ciphertext snapshot. Dropping the mutated WASM
 * instance guarantees a later request reloads the last durable snapshot and
 * starts locked instead of accidentally persisting a previously failed change.
 */
const mutateAndPersist = createSerializedMutationRunner<ExtensionWasmVault>({
  acquire: getVault,
  persist: async (current) => {
    try {
      await saveSnapshot(current.snapshotJson());
    } catch {
      throw new Error(
        "Saving the encrypted vault failed. Reload before continuing.",
      );
    }
  },
  discard: (current) => {
    stopSync();
    if (vault === current) vault = null;
    try {
      current.lock();
    } catch {
      // Dropping the shared reference is authoritative even if lock fails.
    }
  },
});

const syncSession = createExtensionVaultSyncSession(mutateAndPersist);

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const syncRequests = createSyncRequestRunner(async () => {
  const connection = syncConnection;
  if (connection === null) return false;
  const unlocked = await mutateAndPersist.access((current) =>
    current.isUnlocked(),
  );
  if (!unlocked) return false;
  const generation = syncGeneration;
  syncStatus = { ...syncStatus, phase: "syncing", error: null };
  try {
    const signal = syncAbortController?.signal;
    const result = await connection.runtime.syncOnce(
      signal === undefined ? {} : { signal },
    );
    if (generation !== syncGeneration || syncConnection !== connection)
      return false;
    syncStatus = {
      phase: "ready",
      accountId: connection.client.accountId,
      lastSyncedAt: Date.now(),
      pendingUploads: result.push.remaining,
      blockedItems: result.harvest.blockedObjectIds.length,
      error: null,
    };
    return true;
  } catch (error) {
    if (generation === syncGeneration && syncConnection === connection) {
      syncStatus = {
        ...syncStatus,
        phase: "error",
        accountId: connection.client.accountId,
        error: errorMessage(error),
      };
    }
    return false;
  }
});

function stopSync(): void {
  syncAbortController?.abort();
  syncAbortController = null;
  syncGeneration += 1;
  syncConnection = null;
  syncRequests.invalidate();
  void chrome.alarms.clear(SYNC_ALARM_NAME);
}

function scheduleSync(): void {
  chrome.alarms.create(SYNC_ALARM_NAME, { periodInMinutes: 1 });
}

async function startSync(): Promise<void> {
  syncAbortController?.abort();
  const abortController = new AbortController();
  syncAbortController = abortController;
  const generation = syncGeneration + 1;
  syncGeneration = generation;
  syncConnection = null;
  syncRequests.invalidate();
  syncStatus = { ...syncStatus, phase: "connecting", error: null };
  let accountId: string | null = null;
  try {
    const configuration = await loadExtensionSyncConfiguration();
    accountId = configuration?.accountId ?? null;
    if (configuration === null) {
      syncStatus = { ...INITIAL_SYNC_STATUS };
      return;
    }
    syncStatus = { ...syncStatus, phase: "connecting", accountId, error: null };
    const connected = await resumeExtensionVaultSync(
      syncSession,
      abortController.signal,
    );
    const unlocked = await mutateAndPersist.access((current) =>
      current.isUnlocked(),
    );
    if (generation !== syncGeneration || !unlocked || connected === null)
      return;
    syncConnection = connected;
    syncStatus = {
      ...syncStatus,
      phase: "ready",
      accountId: connected.client.accountId,
      error: null,
    };
    scheduleSync();
    await syncRequests.request();
  } catch (error) {
    if (generation !== syncGeneration) return;
    syncStatus = {
      ...syncStatus,
      phase: "error",
      accountId,
      error: errorMessage(error),
    };
  }
}

async function enrollSync(
  apiBaseUrl: string,
  registrationToken: string,
  masterPassphrase: string,
  accountSecretCode: string,
): Promise<void> {
  const unlocked = await mutateAndPersist.access((current) =>
    current.isUnlocked(),
  );
  if (!unlocked) throw new Error("locked");
  syncAbortController?.abort();
  const abortController = new AbortController();
  syncAbortController = abortController;
  const generation = syncGeneration + 1;
  syncGeneration = generation;
  syncConnection = null;
  syncRequests.invalidate();
  syncStatus = { ...syncStatus, phase: "connecting", error: null };
  try {
    const connected = await enrollExtensionVaultSync(
      syncSession,
      { registrationToken, masterPassphrase, accountSecretCode },
      apiBaseUrl,
      abortController.signal,
    );
    if (generation !== syncGeneration) return;
    syncConnection = connected;
    syncStatus = {
      ...syncStatus,
      phase: "ready",
      accountId: connected.client.accountId,
      error: null,
    };
    scheduleSync();
    await syncRequests.request();
  } catch (error) {
    if (generation === syncGeneration) {
      const configuration = await loadExtensionSyncConfiguration().catch(
        () => null,
      );
      syncStatus = {
        ...syncStatus,
        phase: configuration === null ? "not_configured" : "error",
        accountId: configuration?.accountId ?? null,
        error: errorMessage(error),
      };
    }
    throw error;
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== SYNC_ALARM_NAME) return;
  if (syncConnection === null) {
    void chrome.alarms.clear(SYNC_ALARM_NAME);
    return;
  }
  void syncRequests.request();
});

self.addEventListener("online", () => void syncRequests.request());

// --- Credential extraction from the generic item model ---

interface ItemJson {
  id: string;
  kind: string;
  title: string;
  fields: Record<string, string>;
}

function listCredentials(v: ExtensionWasmVault): CredentialSummary[] {
  return JSON.parse(v.listCredentialsJson()) as CredentialSummary[];
}

async function addCredential(
  title: string,
  username: string,
  password: string,
  website: string,
): Promise<PopupResponse> {
  const normalizedTitle = title.trim();
  if (normalizedTitle.length === 0)
    return { type: "error", error: "title is required" };
  const normalizedWebsite = website.trim();
  const websiteOrigin =
    normalizedWebsite.length === 0 ? "" : credentialOrigin(normalizedWebsite);
  if (websiteOrigin === null) {
    return { type: "error", error: "website must be a valid HTTP(S) address" };
  }
  const item: ItemJson & {
    links: string[];
    attachments: string[];
    legacy_disposition: string;
    account_closure_plan: { disposition: string; instructions: string };
    notes: null;
  } = {
    id: crypto.randomUUID(),
    kind: "password",
    title: normalizedTitle,
    links: [],
    attachments: [],
    legacy_disposition: "unspecified",
    account_closure_plan: { disposition: "unspecified", instructions: "" },
    fields: { username, password, website: websiteOrigin },
    notes: null,
  };
  await mutateAndPersist((current) => {
    if (!current.isUnlocked()) throw new Error("locked");
    current.putItemJson(JSON.stringify(item));
  });
  void syncRequests.request();
  return { type: "ok" };
}

/** Normalize a stored credential website to an HTTP(S) origin. */
function credentialOrigin(value: string): string | null {
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value)
      ? value
      : `https://${value}`;
    const url = new URL(withScheme);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** Normalize a browser page URL to an HTTP(S) origin. */
function pageOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** Exact scheme + host + effective-port match. */
function originMatches(credentialWebsite: string, pageOrigin: string): boolean {
  const credential = credentialOrigin(credentialWebsite);
  return credential !== null && credential === pageOrigin;
}

/** Accept only messages sent by this extension's top-frame content script. */
function contentContextFromSender(
  sender: chrome.runtime.MessageSender,
): ContentSenderContext | null {
  if (
    sender.id !== chrome.runtime.id ||
    sender.tab?.id === undefined ||
    sender.frameId !== 0
  ) {
    return null;
  }
  const senderUrl = sender.url ?? sender.tab.url;
  const origin = senderUrl ? pageOrigin(senderUrl) : null;
  return origin === null ? null : { tabId: sender.tab.id, origin };
}

/** Popup-privileged requests must come from one of this extension's own pages. */
function isExtensionPageSender(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id !== chrome.runtime.id || !sender.url) return false;
  return sender.url.startsWith(chrome.runtime.getURL(""));
}

function contentRequestKey(context: ContentSenderContext): string {
  return `${context.tabId}\n${context.origin}`;
}

function pruneContentRequestState(now: number): void {
  for (const [key, state] of contentRequestState) {
    const authorizationExpired =
      state.authorization === undefined || state.authorization.expiresAt <= now;
    if (
      authorizationExpired &&
      now - state.lastTouchedAt > CONTENT_FILL_AUTH_TTL_MS
    ) {
      contentRequestState.delete(key);
    }
  }

  while (contentRequestState.size >= CONTENT_REQUEST_STATE_MAX_ENTRIES) {
    let oldestKey: string | null = null;
    let oldestTouchedAt = Number.POSITIVE_INFINITY;
    for (const [key, state] of contentRequestState) {
      if (state.lastTouchedAt < oldestTouchedAt) {
        oldestKey = key;
        oldestTouchedAt = state.lastTouchedAt;
      }
    }
    if (oldestKey === null) break;
    contentRequestState.delete(oldestKey);
  }
}

function authorizeCredentialLookup(
  context: ContentSenderContext,
): { ok: true; authorization: string } | { ok: false } {
  const now = Date.now();
  const key = contentRequestKey(context);
  const current = contentRequestState.get(key);
  // Capture the current entry before pruning so capacity eviction cannot be
  // used to bypass this origin's cooldown.
  pruneContentRequestState(now);
  if (current && now - current.lastFindAt < CONTENT_FIND_COOLDOWN_MS) {
    current.lastTouchedAt = now;
    return { ok: false };
  }

  const authorization = crypto.randomUUID();
  contentRequestState.set(key, {
    lastFindAt: now,
    lastTouchedAt: now,
    authorization: {
      token: authorization,
      expiresAt: now + CONTENT_FILL_AUTH_TTL_MS,
    },
  });
  return { ok: true, authorization };
}

function consumeContentAuthorization(
  context: ContentSenderContext,
  authorization: string,
): boolean {
  const now = Date.now();
  const key = contentRequestKey(context);
  const state = contentRequestState.get(key);
  if (
    !state?.authorization ||
    state.authorization.expiresAt <= now ||
    state.authorization.token !== authorization
  ) {
    return false;
  }

  // Consume before decrypting so replayed or concurrent fill attempts fail closed.
  delete state.authorization;
  state.lastTouchedAt = now;
  return true;
}

/** SHA-256 hex of a string; used as a clipboard clear-token (compare-and-clear). */
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Popup-initiated password copy: requires unlock; returns the password plus a
 * clear token so the popup can conditionally clear the clipboard after 30s. */
async function copyPassword(v: WasmVault, id: string): Promise<PopupResponse> {
  if (!v.isUnlocked()) return { type: "error", error: "locked" };
  let item: ItemJson;
  try {
    item = JSON.parse(v.getItemJson(id)) as ItemJson;
  } catch {
    return { type: "error", error: "not found" };
  }
  if (item.kind !== "password")
    return { type: "error", error: "not a credential" };
  const password = item.fields["password"] ?? "";
  return {
    type: "copiedPassword",
    password,
    clearToken: await sha256Hex(password),
  };
}

// --- Fill: decrypt only the requested credential, only for a matching origin ---

function fillCredential(
  v: WasmVault,
  id: string,
  origin: string,
): ContentResponse {
  if (!v.isUnlocked()) return { type: "fill", ok: false, error: "locked" };
  let item: ItemJson;
  try {
    item = JSON.parse(v.getItemJson(id)) as ItemJson;
  } catch {
    return { type: "fill", ok: false, error: "not found" };
  }
  if (item.kind !== "password")
    return { type: "fill", ok: false, error: "not a credential" };
  if (!originMatches(item.fields["website"] ?? "", origin)) {
    return { type: "fill", ok: false, error: "origin mismatch" };
  }
  return {
    type: "fill",
    ok: true,
    payload: {
      username: item.fields["username"] ?? "",
      password: item.fields["password"] ?? "",
    },
  };
}

function findCredentials(
  v: WasmVault,
  origin: string,
  authorization: string,
): ContentResponse {
  if (!v.isUnlocked()) return { type: "credentials", locked: true, items: [] };
  const matches = listCredentials(v).filter((c) =>
    originMatches(c.website, origin),
  );
  return { type: "credentials", locked: false, items: matches, authorization };
}

// --- Message routing ---

chrome.runtime.onMessage.addListener((raw: unknown, sender, sendResponse) => {
  void (async () => {
    const msg = raw as ContentRequest | PopupRequest;

    switch (msg.type) {
      // Content-script surface (untrusted page context).
      case "findCredentials": {
        const context = contentContextFromSender(sender);
        if (context === null) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies ContentResponse;
        }
        const lookup = authorizeCredentialLookup(context);
        if (!lookup.ok) {
          return {
            type: "error",
            error: "request throttled",
          } satisfies ContentResponse;
        }
        return mutateAndPersist.access((v) =>
          findCredentials(v, context.origin, lookup.authorization),
        );
      }
      case "fillCredential": {
        const context = contentContextFromSender(sender);
        if (context === null) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies ContentResponse;
        }
        return mutateAndPersist.access((v) => {
          if (!consumeContentAuthorization(context, msg.authorization)) {
            return {
              type: "fill",
              ok: false,
              error: "authorization required",
            } satisfies ContentResponse;
          }
          return fillCredential(v, msg.id, context.origin);
        });
      }
      case "captureCredential": {
        const context = contentContextFromSender(sender);
        if (context === null) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies ContentResponse;
        }
        if (!consumeContentAuthorization(context, msg.authorization)) {
          return {
            type: "capture",
            ok: false,
            error: "authorization required",
          } satisfies ContentResponse;
        }
        const result = await mutateAndPersist((v) =>
          saveCapturedCredential(v, context.origin, msg),
        );
        if (result.ok) void syncRequests.request();
        return result;
      }

      // Popup surface (trusted extension page).
      case "getState": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        return mutateAndPersist.access(
          (v) =>
            ({
              type: "state",
              initialized: v.isInitialized(),
              unlocked: v.isUnlocked(),
              credentialCount: v.isUnlocked() ? listCredentials(v).length : 0,
              sync: { ...syncStatus },
            }) satisfies PopupResponse,
        );
      }
      case "create": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        await mutateAndPersist((v) => v.create(msg.passphrase));
        void startSync();
        return { type: "ok" } satisfies PopupResponse;
      }
      case "unlock": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        await mutateAndPersist.access((v) => v.unlock(msg.passphrase));
        void startSync();
        return { type: "ok" } satisfies PopupResponse;
      }
      case "unlockWithRecoveryKit": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        await mutateAndPersist.access((v) =>
          v.unlockWithRecoveryKit(msg.secretHex),
        );
        void startSync();
        return { type: "ok" } satisfies PopupResponse;
      }
      case "lock": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        stopSync();
        await mutateAndPersist.access((v) => v.lock());
        syncStatus = { ...INITIAL_SYNC_STATUS };
        return { type: "ok" } satisfies PopupResponse;
      }
      case "listCredentials": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        return mutateAndPersist.access(
          (v) =>
            ({
              type: "credentials",
              items: listCredentials(v),
            }) satisfies PopupResponse,
        );
      }
      case "addCredential": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        return await addCredential(
          msg.title,
          msg.username,
          msg.password,
          msg.website,
        );
      }
      case "copyPassword": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        return mutateAndPersist.access((v) => copyPassword(v, msg.id));
      }
      case "generatePassword":
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        return {
          type: "password",
          password: WasmVault.generatePassword(msg.length),
        } satisfies PopupResponse;
      case "generateAccountSecret":
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        return {
          type: "accountSecret",
          accountSecret: WasmVault.generateAccountSecret(),
        } satisfies PopupResponse;
      case "enrollSync": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        await enrollSync(
          msg.apiBaseUrl,
          msg.registrationToken,
          msg.masterPassphrase,
          msg.accountSecretCode,
        );
        return { type: "ok" } satisfies PopupResponse;
      }
      case "syncNow": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        if (syncConnection === null)
          throw new Error("Encrypted sync is not connected.");
        await syncRequests.request();
        return { type: "ok" } satisfies PopupResponse;
      }
      case "retrySync": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        await startSync();
        return { type: "ok" } satisfies PopupResponse;
      }
      case "resetSyncConfiguration": {
        if (!isExtensionPageSender(sender)) {
          return {
            type: "error",
            error: "unauthorized sender",
          } satisfies PopupResponse;
        }
        stopSync();
        await clearExtensionSyncConfiguration();
        syncStatus = { ...INITIAL_SYNC_STATUS };
        return { type: "ok" } satisfies PopupResponse;
      }
      default:
        return {
          type: "error",
          error: "unknown message",
        } satisfies PopupResponse;
    }
  })()
    .then((res: ContentResponse | PopupResponse) => sendResponse(res))
    .catch((e: unknown) =>
      sendResponse({
        type: "error",
        error: e instanceof Error ? e.message : String(e),
      }),
    );
  return true; // keep the message channel open for the async response
});
