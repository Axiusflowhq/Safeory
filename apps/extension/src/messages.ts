/**
 * Message protocol between content scripts, the background service worker,
 * and the popup. This is the extension's security boundary:
 *
 * - Content scripts run in untrusted pages and NEVER hold vault keys or
 *   decrypted item lists at rest. Exact-origin credential summaries are
 *   requested only after a trusted user gesture. A subsequent fill must carry
 *   the background-issued one-shot authorization from that lookup.
 * - The background service worker derives the page origin from MessageSender
 *   and only releases a credential to the exact stored origin.
 * - The popup is a trusted extension page and may list/edit after unlock.
 */

export interface CredentialSummary {
  id: string;
  title: string;
  username: string;
  website: string;
  revision: number;
}

export interface FillPayload {
  username: string;
  password: string;
}

export type ExtensionSyncPhase =
  | "not_configured"
  | "connecting"
  | "ready"
  | "syncing"
  | "error";

export interface ExtensionSyncStatus {
  phase: ExtensionSyncPhase;
  accountId: string | null;
  lastSyncedAt: number | null;
  pendingUploads: number;
  blockedItems: number;
  error: string | null;
}

export type ContentRequest =
  | { type: "findCredentials" }
  | { type: "fillCredential"; id: string; authorization: string };

export type ContentResponse =
  | {
      type: "credentials";
      locked: boolean;
      items: CredentialSummary[];
      authorization?: string;
    }
  | { type: "fill"; ok: boolean; payload?: FillPayload; error?: string }
  | { type: "error"; error: string };

export type PopupRequest =
  | { type: "getState" }
  | { type: "unlock"; passphrase: string }
  | { type: "unlockWithRecoveryKit"; secretHex: string }
  | { type: "create"; passphrase: string }
  | { type: "lock" }
  | { type: "listCredentials" }
  | {
      type: "addCredential";
      title: string;
      username: string;
      password: string;
      website: string;
    }
  | { type: "copyPassword"; id: string }
  | { type: "generatePassword"; length: number }
  | { type: "enrollSync"; apiBaseUrl: string; registrationToken: string }
  | { type: "syncNow" }
  | { type: "retrySync" }
  | { type: "resetSyncConfiguration" };

export type PopupResponse =
  | {
      type: "state";
      initialized: boolean;
      unlocked: boolean;
      credentialCount: number;
      sync: ExtensionSyncStatus;
    }
  | { type: "credentials"; items: CredentialSummary[] }
  | { type: "password"; password: string }
  | { type: "copiedPassword"; password: string; clearToken: string }
  | { type: "ok" }
  | { type: "error"; error: string };
