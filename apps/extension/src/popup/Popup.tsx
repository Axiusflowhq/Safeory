import { useCallback, useEffect, useState } from "react";
import type { CredentialSummary, PopupRequest, PopupResponse } from "../messages";

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

  const refresh = useCallback(async () => {
    const res = await send<Extract<PopupResponse, { type: "state" }>>({ type: "getState" });
    if (res.type !== "state") return;
    if (!res.initialized) setState({ phase: "setup" });
    else if (!res.unlocked) setState({ phase: "unlock" });
    else {
      const list = await send<Extract<PopupResponse, { type: "credentials" }>>({
        type: "listCredentials",
      });
      setState({ phase: "open", credentials: list.type === "credentials" ? list.items : [] });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function doAction(req: PopupRequest) {
    setError(null);
    const res = await send<PopupResponse>(req);
    if (res.type === "error") setError(res.error);
    else if (req.type === "create" || req.type === "unlock" || req.type === "unlockWithRecoveryKit") {
      setPassphrase("");
      await refresh();
    }
  }

  async function copyPassword(id: string) {
    // Background decrypts the password and returns it with a SHA-256 clear
    // token. The popup writes it to the clipboard and schedules a conditional
    // clear: it only clears if the clipboard still holds exactly this secret
    // (matching the desktop's compare-and-clear), so it never wipes something
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
    const res = await send<PopupResponse>({ type: "generatePassword", length: 20 });
    if (res.type === "password") setNewPassword(res.password);
    else if (res.type === "error") setError(res.error);
  }

  if (state.phase === "loading") {
    return <div className="p-4 text-sm text-gray-500">Loading…</div>;
  }

  return (
    <div className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <h1 className="text-base font-semibold">Safeory</h1>
        {state.phase === "open" ? (
          <button
            onClick={() => void doAction({ type: "lock" }).then(refresh)}
            className="rounded border px-2 py-0.5 text-xs"
          >
            Lock
          </button>
        ) : null}
      </div>

      {error ? <p className="mb-2 rounded bg-red-50 px-2 py-1 text-xs text-red-700">{error}</p> : null}

      {state.phase === "setup" || state.phase === "unlock" ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void doAction(
              state.phase === "setup"
                ? { type: "create", passphrase }
                : { type: "unlock", passphrase },
            );
          }}
          className="space-y-2"
        >
          <p className="text-xs text-gray-500">
            {state.phase === "setup"
              ? "Create your vault (12+ character passphrase)."
              : "Enter your master passphrase."}
          </p>
          <input
            type="password"
            autoFocus
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Master passphrase"
            className="w-full rounded border px-2 py-1.5 text-sm"
          />
          <button
            type="submit"
            disabled={state.phase === "setup" && passphrase.length < 12}
            className="w-full rounded bg-black px-3 py-1.5 text-sm text-white disabled:opacity-40"
          >
            {state.phase === "setup" ? "Create vault" : "Unlock"}
          </button>
        </form>
      ) : null}

      {state.phase === "open" ? (
        <section>
          <div className="mb-2 flex items-center justify-between gap-2">
            <p className="text-xs text-gray-500">
              {state.credentials.length} credential(s). Visit a login page to autofill.
            </p>
            <button
              type="button"
              onClick={() => setAdding((value) => !value)}
              className="shrink-0 rounded border px-2 py-0.5 text-xs"
            >
              {adding ? "Cancel" : "+ Add"}
            </button>
          </div>

          {adding ? (
            <form
              className="mb-3 space-y-2 rounded border p-2"
              onSubmit={(e) => {
                e.preventDefault();
                void addCredential();
              }}
            >
              <input
                autoFocus
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                placeholder="Title"
                className="w-full rounded border px-2 py-1.5 text-sm"
              />
              <input
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="Username / email"
                className="w-full rounded border px-2 py-1.5 text-sm"
              />
              <input
                value={newWebsite}
                onChange={(e) => setNewWebsite(e.target.value)}
                placeholder="https://example.com"
                className="w-full rounded border px-2 py-1.5 text-sm"
              />
              <div className="flex gap-2">
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Password"
                  className="min-w-0 flex-1 rounded border px-2 py-1.5 text-sm"
                />
                <button
                  type="button"
                  onClick={() => void generateCredentialPassword()}
                  className="rounded border px-2 text-xs"
                >
                  Generate
                </button>
              </div>
              <button
                type="submit"
                disabled={newTitle.trim().length === 0}
                className="w-full rounded bg-black px-3 py-1.5 text-sm text-white disabled:opacity-40"
              >
                Save credential
              </button>
            </form>
          ) : null}

          {state.credentials.length === 0 ? (
            <p className="text-xs text-gray-400">No credentials yet.</p>
          ) : (
            <ul className="max-h-72 space-y-1 overflow-y-auto">
              {state.credentials.map((c) => (
                <li
                  key={c.id}
                  className="flex items-center justify-between rounded border px-2 py-1.5 text-sm"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium">{c.title}</p>
                    <p className="truncate text-xs text-gray-500">{c.username}</p>
                  </div>
                  <button
                    onClick={() => void copyPassword(c.id)}
                    className="ml-2 shrink-0 rounded border px-2 py-0.5 text-xs"
                  >
                    {copiedId === c.id ? "Copied" : "Copy password"}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}
    </div>
  );
}
