import { useCallback, useEffect, useRef, useState } from "react";
import type {
  CredentialSummary,
  ExtensionSyncStatus,
  PopupRequest,
  PopupResponse,
} from "../messages";
import { DEFAULT_EXTENSION_SYNC_API_URL } from "../sync-configuration";

type State =
  | { phase: "loading" }
  | { phase: "setup" }
  | { phase: "unlock" }
  | { phase: "open"; credentials: CredentialSummary[] };

function send<T extends PopupResponse>(req: PopupRequest): Promise<T> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(req, (res: T) => resolve(res));
  });
}

export function Popup() {
  const [state, setState] = useState<State>({ phase: "loading" });
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newWebsite, setNewWebsite] = useState("");
  const [syncStatus, setSyncStatus] = useState<ExtensionSyncStatus>({
    phase: "not_configured",
    accountId: null,
    lastSyncedAt: null,
    pendingUploads: 0,
    blockedItems: 0,
    error: null,
  });
  const [syncApiBaseUrl, setSyncApiBaseUrl] = useState(DEFAULT_EXTENSION_SYNC_API_URL);
  const [registrationToken, setRegistrationToken] = useState("");
  const passphraseRef = useRef<HTMLInputElement>(null);
  const titleRef = useRef<HTMLInputElement>(null);

  const refresh = useCallback(async () => {
    const res = await send<Extract<PopupResponse, { type: "state" }>>({
      type: "getState",
    });
    if (res.type !== "state") return;
    setSyncStatus(res.sync);
    if (!res.initialized) setState({ phase: "setup" });
    else if (!res.unlocked) setState({ phase: "unlock" });
    else {
      const list = await send<Extract<PopupResponse, { type: "credentials" }>>({
        type: "listCredentials",
      });
      setState({
        phase: "open",
        credentials: list.type === "credentials" ? list.items : [],
      });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (
      state.phase !== "open" ||
      (syncStatus.phase !== "connecting" && syncStatus.phase !== "syncing")
    ) {
      return;
    }
    const timeout = window.setTimeout(() => void refresh(), 500);
    return () => window.clearTimeout(timeout);
  }, [refresh, state.phase, syncStatus.phase]);

  async function doAction(req: PopupRequest) {
    setError(null);
    const res = await send<PopupResponse>(req);
    if (res.type === "error") setError(res.error);
    else if (
      req.type === "create" ||
      req.type === "unlock" ||
      req.type === "unlockWithRecoveryKit"
    ) {
      setPassphrase("");
      await refresh();
    }
  }

  async function copyPassword(id: string) {
    // Background decrypts the password and returns it with a SHA-256 clear
    // token. The popup writes it to the clipboard and schedules a conditional
    // clear: it only clears if the clipboard still holds exactly this secret
    // using compare-and-clear, so it never wipes something
    // the user copied afterward.
    const res = await send<PopupResponse>({ type: "copyPassword", id });
    if (res.type !== "copiedPassword") {
      if (res.type === "error") setError(res.error);
      return;
    }
    await navigator.clipboard.writeText(res.password);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);

    const token = res.clearToken;
    setTimeout(() => {
      void (async () => {
        try {
          const current = await navigator.clipboard.readText();
          const digest = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(current),
          );
          const currentToken = [...new Uint8Array(digest)]
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          if (currentToken === token) await navigator.clipboard.writeText("");
        } catch {
          // Clipboard read can be denied; clearing is best-effort.
        }
      })();
    }, 30_000);
  }

  async function addCredential() {
    setError(null);
    const res = await send<PopupResponse>({
      type: "addCredential",
      title: newTitle,
      username: newUsername,
      password: newPassword,
      website: newWebsite,
    });
    if (res.type === "error") {
      setError(res.error);
      return;
    }
    setNewTitle("");
    setNewUsername("");
    setNewPassword("");
    setNewWebsite("");
    setAdding(false);
    await refresh();
  }

  async function generateCredentialPassword() {
    const res = await send<PopupResponse>({
      type: "generatePassword",
      length: 20,
    });
    if (res.type === "password") setNewPassword(res.password);
    else if (res.type === "error") setError(res.error);
  }

  async function enableSync() {
    const token = registrationToken;
    setRegistrationToken("");
    let apiUrl: URL;
    try {
      apiUrl = new URL(syncApiBaseUrl);
    } catch {
      setError("Enter a valid development API URL.");
      return;
    }
    if (apiUrl.protocol === "https:") {
      const originPermission = `${apiUrl.origin}/*`;
      const granted = await chrome.permissions.request({ origins: [originPermission] });
      if (!granted) {
        setError("Safeory needs permission to connect to that sync API origin.");
        return;
      }
    }
    await doAction({
      type: "enrollSync",
      apiBaseUrl: syncApiBaseUrl,
      registrationToken: token,
    });
    await refresh();
  }

  if (state.phase === "loading") {
    return (
      <div className="p-4 text-sm text-[var(--text-secondary)]">Loading…</div>
    );
  }

  return (
    <div className="bg-[var(--surface)] p-4 text-[var(--text-primary)]">
      <div className="mb-3 flex items-center justify-between">
        <h1 className="text-base font-semibold">Safeory</h1>
        {state.phase === "open" ? (
          <button
            onClick={() => void doAction({ type: "lock" }).then(refresh)}
            className="min-h-7 rounded-[var(--radius-default)] border-[var(--border)] [border-width:var(--border-width)] px-2 py-1 text-xs motion-safe:transition-[transform,background-color] motion-safe:duration-150 motion-safe:ease-out [@media(hover:hover)]:hover:bg-[var(--hover-bg)] active:scale-[0.97] active:bg-[var(--active-bg)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)]"
          >
            Lock
          </button>
        ) : null}
      </div>

      {error ? (
        <p
          role="alert"
          className="mb-2 rounded-[var(--radius-default)] bg-[color-mix(in_oklch,var(--danger)_10%,transparent)] px-2 py-1 text-xs text-[var(--danger)]"
        >
          {error}
        </p>
      ) : null}

      {state.phase === "setup" || state.phase === "unlock" ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (state.phase === "setup" && passphrase.length < 12) {
              setError(
                "Use at least 12 characters for your master passphrase.",
              );
              passphraseRef.current?.focus();
              return;
            }
            void doAction(
              state.phase === "setup"
                ? { type: "create", passphrase }
                : { type: "unlock", passphrase },
            );
          }}
          className="space-y-2"
        >
          <p className="text-xs text-[var(--text-secondary)]">
            {state.phase === "setup"
              ? "Create your vault (12+ character passphrase)."
              : "Enter your master passphrase."}
          </p>
          <label
            htmlFor="safeory-extension-passphrase"
            className="block text-xs font-medium text-[var(--text-primary)]"
          >
            Master passphrase
          </label>
          <input
            ref={passphraseRef}
            id="safeory-extension-passphrase"
            type="password"
            autoFocus
            value={passphrase}
            onChange={(e) => {
              setPassphrase(e.target.value);
              if (error) setError(null);
            }}
            placeholder="Master passphrase"
            className="h-9 w-full rounded-[var(--radius-default)] border-[var(--input-border)] bg-[var(--input-fill)] px-2 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] [border-width:var(--border-width)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)]"
          />
          <button
            type="submit"
            className="h-9 w-full rounded-[var(--radius-default)] bg-[var(--primary)] px-3 py-1.5 text-sm text-[var(--primary-foreground)] shadow-[var(--fancy-shadow-primary)] motion-safe:transition-[transform,filter] motion-safe:duration-200 motion-safe:ease-out motion-safe:will-change-transform [@media(hover:hover)]:hover:brightness-95 active:scale-[0.97] active:brightness-90"
          >
            {state.phase === "setup" ? "Create vault" : "Unlock"}
          </button>
        </form>
      ) : null}

      {state.phase === "open" ? (
        <div className="space-y-3">
        <section>
          <div className="mb-2 flex items-center justify-between gap-2">
            <p className="text-xs text-pretty text-[var(--text-secondary)]">
              <span className="tabular-nums">{state.credentials.length}</span>{" "}
              {state.credentials.length === 1 ? "credential" : "credentials"}.
              Visit a login page to autofill.
            </p>
            <button
              type="button"
              onClick={() => setAdding((value) => !value)}
              className="min-h-7 shrink-0 rounded-[var(--radius-default)] border-[var(--border-secondary)] bg-[var(--surface-secondary)] [border-width:var(--border-width)] px-2 py-1 text-xs motion-safe:transition-[transform,background-color] motion-safe:duration-150 motion-safe:ease-out [@media(hover:hover)]:hover:bg-[var(--hover-bg)] active:scale-[0.97] active:bg-[var(--active-bg)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)]"
            >
              {adding ? "Cancel" : "Add credential"}
            </button>
          </div>

          {adding ? (
            <form
              className="mb-3 space-y-2 rounded-[var(--radius-default)] border-[var(--border)] [border-width:var(--border-width)] bg-[var(--surface-secondary)] p-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (newTitle.trim().length === 0) {
                  setError("Enter a title for this credential.");
                  titleRef.current?.focus();
                  return;
                }
                void addCredential();
              }}
            >
              <label
                htmlFor="safeory-extension-title"
                className="block text-xs font-medium text-[var(--text-primary)]"
              >
                Title
              </label>
              <input
                ref={titleRef}
                id="safeory-extension-title"
                autoFocus
                value={newTitle}
                onChange={(e) => {
                  setNewTitle(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="Title"
                className="w-full rounded-[var(--radius-default)] border-[var(--input-border)] bg-[var(--input-fill)] px-2 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] [border-width:var(--border-width)] focus-visible:outline-2 focus-visible:outline-[var(--ring)]"
              />
              <label
                htmlFor="safeory-extension-username"
                className="block text-xs font-medium text-[var(--text-primary)]"
              >
                Username or email
              </label>
              <input
                id="safeory-extension-username"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="Username / email"
                className="w-full rounded-[var(--radius-default)] border-[var(--input-border)] bg-[var(--input-fill)] px-2 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] [border-width:var(--border-width)] focus-visible:outline-2 focus-visible:outline-[var(--ring)]"
              />
              <label
                htmlFor="safeory-extension-website"
                className="block text-xs font-medium text-[var(--text-primary)]"
              >
                Website
              </label>
              <input
                id="safeory-extension-website"
                type="url"
                inputMode="url"
                value={newWebsite}
                onChange={(e) => setNewWebsite(e.target.value)}
                placeholder="https://example.com"
                className="w-full rounded-[var(--radius-default)] border-[var(--input-border)] bg-[var(--input-fill)] px-2 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] [border-width:var(--border-width)] focus-visible:outline-2 focus-visible:outline-[var(--ring)]"
              />
              <div className="flex gap-2">
                <div className="min-w-0 flex-1">
                  <label
                    htmlFor="safeory-extension-password"
                    className="mb-2 block text-xs font-medium text-[var(--text-primary)]"
                  >
                    Password
                  </label>
                  <input
                    id="safeory-extension-password"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Password"
                    className="h-9 w-full rounded-[var(--radius-default)] border-[var(--input-border)] bg-[var(--input-fill)] px-2 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] [border-width:var(--border-width)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)]"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => void generateCredentialPassword()}
                  className="mt-6 min-h-9 rounded-[var(--radius-default)] border-[var(--border-secondary)] bg-[var(--surface-secondary)] [border-width:var(--border-width)] px-2 text-xs motion-safe:transition-[transform,background-color] motion-safe:duration-150 motion-safe:ease-out [@media(hover:hover)]:hover:bg-[var(--hover-bg)] active:scale-[0.97] active:bg-[var(--active-bg)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)]"
                >
                  Generate password
                </button>
              </div>
              <button
                type="submit"
                className="h-9 w-full rounded-[var(--radius-default)] bg-[var(--primary)] px-3 py-1.5 text-sm text-[var(--primary-foreground)] shadow-[var(--fancy-shadow-primary)] motion-safe:transition-[transform,filter] motion-safe:duration-200 motion-safe:ease-out motion-safe:will-change-transform [@media(hover:hover)]:hover:brightness-95 active:scale-[0.97] active:brightness-90"
              >
                Save credential
              </button>
            </form>
          ) : null}

          {state.credentials.length === 0 ? (
            <p className="text-xs text-[var(--text-muted)]">
              No credentials yet.
            </p>
          ) : (
            <ul className="max-h-72 space-y-1 overflow-y-auto">
              {state.credentials.map((c) => (
                <li
                  key={c.id}
                  className="flex items-center justify-between rounded-[var(--radius-default)] border-[var(--border)] [border-width:var(--border-width)] bg-[var(--surface-secondary)] px-2 py-1.5 text-sm"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium" title={c.title}>
                      {c.title}
                    </p>
                    <p
                      className="truncate text-xs text-[var(--text-secondary)]"
                      title={c.username}
                    >
                      {c.username}
                    </p>
                  </div>
                  <button
                    onClick={() => void copyPassword(c.id)}
                    className="ml-2 min-h-7 shrink-0 rounded-[var(--radius-default)] border-[var(--border-secondary)] bg-[var(--surface-secondary)] [border-width:var(--border-width)] px-2 py-1 text-xs motion-safe:transition-[transform,background-color] motion-safe:duration-150 motion-safe:ease-out [@media(hover:hover)]:hover:bg-[var(--hover-bg)] active:scale-[0.97] active:bg-[var(--active-bg)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)]"
                  >
                    {copiedId === c.id ? "Copied" : "Copy password"}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="rounded-[var(--radius-default)] border-[var(--border)] bg-[var(--surface-secondary)] p-2 [border-width:var(--border-width)]">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-xs font-medium">Encrypted sync</h2>
              <p className="text-[11px] text-[var(--text-secondary)]">
                {syncStatus.phase === "not_configured"
                  ? "Local only"
                  : syncStatus.phase === "connecting"
                    ? "Connecting…"
                    : syncStatus.phase === "syncing"
                      ? "Syncing…"
                      : syncStatus.phase === "ready"
                        ? "Connected"
                        : "Needs attention"}
              </p>
            </div>
            {syncStatus.phase === "ready" || syncStatus.phase === "syncing" ? (
              <button
                type="button"
                disabled={syncStatus.phase === "syncing"}
                onClick={() => void doAction({ type: "syncNow" }).then(refresh)}
                className="min-h-7 rounded-[var(--radius-default)] border-[var(--border-secondary)] bg-[var(--surface)] px-2 py-1 text-xs [border-width:var(--border-width)] disabled:opacity-50"
              >
                Sync now
              </button>
            ) : null}
          </div>

          {syncStatus.phase === "not_configured" ? (
            <form
              className="mt-2 space-y-2"
              onSubmit={(event) => {
                event.preventDefault();
                if (registrationToken.length === 0) {
                  setError("Enter the development registration token.");
                  return;
                }
                void enableSync();
              }}
            >
              <label htmlFor="safeory-extension-sync-url" className="block text-xs font-medium">
                Development API URL
              </label>
              <input
                id="safeory-extension-sync-url"
                type="url"
                value={syncApiBaseUrl}
                onChange={(event) => setSyncApiBaseUrl(event.target.value)}
                className="w-full rounded-[var(--radius-default)] border-[var(--input-border)] bg-[var(--surface)] px-2 py-1.5 text-xs [border-width:var(--border-width)]"
              />
              <label htmlFor="safeory-extension-sync-token" className="block text-xs font-medium">
                Registration token
              </label>
              <input
                id="safeory-extension-sync-token"
                type="password"
                autoComplete="off"
                value={registrationToken}
                onChange={(event) => setRegistrationToken(event.target.value)}
                className="w-full rounded-[var(--radius-default)] border-[var(--input-border)] bg-[var(--surface)] px-2 py-1.5 text-xs [border-width:var(--border-width)]"
              />
              <button
                type="submit"
                className="h-8 w-full rounded-[var(--radius-default)] bg-[var(--primary)] px-2 text-xs text-[var(--primary-foreground)]"
              >
                Enable encrypted sync
              </button>
            </form>
          ) : null}

          {syncStatus.accountId ? (
            <div className="mt-2 space-y-0.5 text-[11px] text-[var(--text-secondary)]">
              <p className="truncate" title={syncStatus.accountId}>Account {syncStatus.accountId}</p>
              <p>
                {syncStatus.lastSyncedAt === null
                  ? "No completed cycle yet"
                  : `Last completed ${new Date(syncStatus.lastSyncedAt).toLocaleTimeString()}`}
              </p>
              <p>{syncStatus.pendingUploads} pending · {syncStatus.blockedItems} conflicts</p>
            </div>
          ) : null}

          {syncStatus.phase === "error" ? (
            <div className="mt-2 space-y-2">
              <p role="alert" className="text-[11px] text-[var(--danger)]">
                {syncStatus.error ?? "Encrypted sync failed."}
              </p>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => void doAction({ type: "retrySync" }).then(refresh)}
                  className="min-h-7 flex-1 rounded-[var(--radius-default)] border-[var(--border-secondary)] bg-[var(--surface)] px-2 py-1 text-xs [border-width:var(--border-width)]"
                >
                  Retry
                </button>
                <button
                  type="button"
                  onClick={() => void doAction({ type: "resetSyncConfiguration" }).then(refresh)}
                  className="min-h-7 flex-1 rounded-[var(--radius-default)] border-[var(--border-secondary)] bg-[var(--surface)] px-2 py-1 text-xs [border-width:var(--border-width)]"
                >
                  Reset routing
                </button>
              </div>
            </div>
          ) : null}
        </section>
        </div>
      ) : null}
    </div>
  );
}
