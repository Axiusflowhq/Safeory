/**
 * Background service worker: the only component that holds the unlocked WASM
 * vault. It enforces the origin-matching rule (a credential is released only
 * to a page whose exact origin matches the credential's stored website)
 * and never hands the item list or keys to content scripts.
 */

import init, { WasmVault } from "vault-wasm";
import { loadSnapshot, saveSnapshot } from "./storage";
import type {
  ContentRequest,
  ContentResponse,
  CredentialSummary,
  PopupRequest,
  PopupResponse,
} from "./messages";

type ExtensionWasmVault = WasmVault & {
  listCredentialsJson(): string;
};

// --- Vault lifecycle (single in-memory instance per worker) ---

let vault: ExtensionWasmVault | null = null;
let initPromise: Promise<void> | null = null;

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

function ensureInit(): Promise<void> {
  initPromise ??= (init as unknown as (a?: unknown) => Promise<unknown>)().then(() => undefined);
  return initPromise;
}

async function getVault(): Promise<ExtensionWasmVault> {
  await ensureInit();
  if (vault) return vault;
  const snapshot = await loadSnapshot();
  vault = (snapshot === null ? new WasmVault() : WasmVault.fromSnapshotJson(snapshot)) as ExtensionWasmVault;
  return vault;
}

async function persist(): Promise<void> {
  if (vault) await saveSnapshot(vault.snapshotJson());
}

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
  v: WasmVault,
  title: string,
  username: string,
  password: string,
  website: string,
): Promise<PopupResponse> {
  if (!v.isUnlocked()) return { type: "error", error: "locked" };
  const normalizedTitle = title.trim();
  if (normalizedTitle.length === 0) return { type: "error", error: "title is required" };
  const normalizedWebsite = website.trim();
  const websiteOrigin = normalizedWebsite.length === 0 ? "" : credentialOrigin(normalizedWebsite);
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
  v.putItemJson(JSON.stringify(item));
  await persist();
  return { type: "ok" };
}

/** Normalize a stored credential website to an HTTP(S) origin. */
function credentialOrigin(value: string): string | null {
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`;
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
function contentContextFromSender(sender: chrome.runtime.MessageSender): ContentSenderContext | null {
  if (sender.id !== chrome.runtime.id || sender.tab?.id === undefined || sender.frameId !== 0) {
    return null;
  }
  const senderUrl = sender.url ?? sender.tab.url;
  const origin = senderUrl ? pageOrigin(senderUrl) : null;
  return origin === null ? null : { tabId: sender.tab.id, origin };
}

/** Popup-privileged requests must come from one of this extension's own pages. */
function isExtensionPageSender(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id !== chrome.runtime.id || sender.tab !== undefined || !sender.url) return false;
  return sender.url.startsWith(chrome.runtime.getURL(""));
}

function contentRequestKey(context: ContentSenderContext): string {
  return `${context.tabId}\n${context.origin}`;
}

function pruneContentRequestState(now: number): void {
  for (const [key, state] of contentRequestState) {
    const authorizationExpired =
      state.authorization === undefined || state.authorization.expiresAt <= now;
    if (authorizationExpired && now - state.lastTouchedAt > CONTENT_FILL_AUTH_TTL_MS) {
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

function consumeFillAuthorization(
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
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
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
  if (item.kind !== "password") return { type: "error", error: "not a credential" };
  const password = item.fields["password"] ?? "";
  return { type: "copiedPassword", password, clearToken: await sha256Hex(password) };
}

// --- Fill: decrypt only the requested credential, only for a matching origin ---

function fillCredential(v: WasmVault, id: string, origin: string): ContentResponse {
  if (!v.isUnlocked()) return { type: "fill", ok: false, error: "locked" };
  let item: ItemJson;
  try {
    item = JSON.parse(v.getItemJson(id)) as ItemJson;
  } catch {
    return { type: "fill", ok: false, error: "not found" };
  }
  if (item.kind !== "password") return { type: "fill", ok: false, error: "not a credential" };
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

function findCredentials(v: WasmVault, origin: string, authorization: string): ContentResponse {
  if (!v.isUnlocked()) return { type: "credentials", locked: true, items: [] };
  const matches = listCredentials(v).filter((c) => originMatches(c.website, origin));
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
          return { type: "error", error: "unauthorized sender" } satisfies ContentResponse;
        }
        const lookup = authorizeCredentialLookup(context);
        if (!lookup.ok) {
          return { type: "error", error: "request throttled" } satisfies ContentResponse;
        }
        return findCredentials(await getVault(), context.origin, lookup.authorization);
      }
      case "fillCredential": {
        const context = contentContextFromSender(sender);
        if (context === null) {
          return { type: "error", error: "unauthorized sender" } satisfies ContentResponse;
        }
        if (!consumeFillAuthorization(context, msg.authorization)) {
          return { type: "fill", ok: false, error: "authorization required" } satisfies ContentResponse;
        }
        return fillCredential(await getVault(), msg.id, context.origin);
      }

      // Popup surface (trusted extension page).
      case "getState": {
        if (!isExtensionPageSender(sender)) {
          return { type: "error", error: "unauthorized sender" } satisfies PopupResponse;
        }
        const v = await getVault();
        return {
          type: "state",
          initialized: v.isInitialized(),
          unlocked: v.isUnlocked(),
          credentialCount: v.isUnlocked() ? listCredentials(v).length : 0,
        } satisfies PopupResponse;
      }
      case "create": {
        if (!isExtensionPageSender(sender)) {
          return { type: "error", error: "unauthorized sender" } satisfies PopupResponse;
        }
        const v = await getVault();
        v.create(msg.passphrase);
        await persist();
        return { type: "ok" } satisfies PopupResponse;
      }
      case "unlock": {
        if (!isExtensionPageSender(sender)) {
          return { type: "error", error: "unauthorized sender" } satisfies PopupResponse;
        }
        const v = await getVault();
        v.unlock(msg.passphrase);
        return { type: "ok" } satisfies PopupResponse;
      }
      case "unlockWithRecoveryKit": {
        if (!isExtensionPageSender(sender)) {
          return { type: "error", error: "unauthorized sender" } satisfies PopupResponse;
        }
        const v = await getVault();
        v.unlockWithRecoveryKit(msg.secretHex);
        return { type: "ok" } satisfies PopupResponse;
      }
      case "lock": {
        if (!isExtensionPageSender(sender)) {
          return { type: "error", error: "unauthorized sender" } satisfies PopupResponse;
        }
        const v = await getVault();
        v.lock();
        return { type: "ok" } satisfies PopupResponse;
      }
      case "listCredentials": {
        if (!isExtensionPageSender(sender)) {
          return { type: "error", error: "unauthorized sender" } satisfies PopupResponse;
        }
        return { type: "credentials", items: listCredentials(await getVault()) } satisfies PopupResponse;
      }
      case "addCredential": {
        if (!isExtensionPageSender(sender)) {
          return { type: "error", error: "unauthorized sender" } satisfies PopupResponse;
        }
        return await addCredential(
          await getVault(),
          msg.title,
          msg.username,
          msg.password,
          msg.website,
        );
      }
      case "copyPassword": {
        if (!isExtensionPageSender(sender)) {
          return { type: "error", error: "unauthorized sender" } satisfies PopupResponse;
        }
        return await copyPassword(await getVault(), msg.id);
      }
      case "generatePassword":
        if (!isExtensionPageSender(sender)) {
          return { type: "error", error: "unauthorized sender" } satisfies PopupResponse;
        }
        return { type: "password", password: WasmVault.generatePassword(msg.length) } satisfies PopupResponse;
      default:
        return { type: "error", error: "unknown message" } satisfies PopupResponse;
    }
  })()
    .then((res: ContentResponse | PopupResponse) => sendResponse(res))
    .catch((e: unknown) =>
      sendResponse({ type: "error", error: e instanceof Error ? e.message : String(e) }),
    );
  return true; // keep the message channel open for the async response
});
