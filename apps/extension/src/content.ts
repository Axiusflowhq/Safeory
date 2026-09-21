/**
 * Content script: runs in the page, holds NO keys and NO decrypted data at
 * rest. It detects login forms and shows a generic Safeory affordance. Exact-
 * origin credential summaries are requested only after a trusted user click,
 * and filling requires a second explicit credential choice.
 */

import type {
  ContentRequest,
  ContentResponse,
  CredentialSummary,
  FillPayload,
} from "./messages";

function send<T extends ContentResponse>(req: ContentRequest): Promise<T> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(req, (res: T) => resolve(res));
  });
}

interface LoginForm {
  form: HTMLElement;
  username: HTMLInputElement | null;
  password: HTMLInputElement;
}

function findLoginForms(): LoginForm[] {
  const passwords = Array.from(
    document.querySelectorAll<HTMLInputElement>('input[type="password"]'),
  ).filter((el) => el.offsetParent !== null); // visible only
  const forms: LoginForm[] = [];
  for (const password of passwords) {
    const container =
      password.closest("form") ?? password.closest("div") ?? document.body;
    const username =
      container.querySelector<HTMLInputElement>(
        'input[type="email"], input[autocomplete="username"], input[name*="user" i], input[name*="email" i], input[type="text"]',
      ) ?? null;
    forms.push({ form: container as HTMLElement, username, password });
  }
  return forms;
}

function setNativeValue(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value",
  )?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function fill(form: LoginForm, payload: FillPayload): void {
  if (form.username && payload.username !== "")
    setNativeValue(form.username, payload.username);
  setNativeValue(form.password, payload.password);
}

/** Render a minimal chooser so the user explicitly picks a credential. */
function showChooser(
  anchor: HTMLElement,
  items: CredentialSummary[],
  onPick: (id: string) => void,
  emptyMessage?: string,
): void {
  const box = document.createElement("div");
  box.style.cssText =
    "position:absolute;z-index:2147483647;background:#fff;border:1px solid #ccc;" +
    "border-radius:6px;box-shadow:0 4px 16px rgba(0,0,0,.15);font:13px sans-serif;" +
    "min-width:220px;overflow:hidden;";
  if (items.length === 0) {
    const status = document.createElement("div");
    status.setAttribute("role", "status");
    status.textContent =
      emptyMessage ?? "No Safeory credentials found for this site.";
    status.style.cssText = "padding:9px 10px;color:#555;max-width:280px;";
    box.appendChild(status);
  } else {
    const canHover = window.matchMedia("(hover: hover)").matches;
    for (const item of items) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = `${item.title} — ${item.username}`;
      btn.setAttribute("aria-label", `Fill ${item.title} for ${item.username}`);
      btn.style.cssText =
        "display:block;width:100%;min-height:40px;text-align:left;padding:10px;border:0;" +
        "background:#fff;cursor:pointer;";
      if (canHover) {
        btn.onmouseenter = () => (btn.style.background = "#f0f0f0");
        btn.onmouseleave = () => (btn.style.background = "#fff");
      }
      btn.onclick = (e) => {
        if (!e.isTrusted) return;
        onPick(item.id);
        box.remove();
      };
      box.appendChild(btn);
    }
  }
  const rect = anchor.getBoundingClientRect();
  box.style.top = `${rect.bottom + window.scrollY + 4}px`;
  box.style.left = `${rect.left + window.scrollX}px`;
  document.body.appendChild(box);
  const dismiss = (e: MouseEvent) => {
    if (!box.contains(e.target as Node)) {
      box.remove();
      document.removeEventListener("click", dismiss);
    }
  };
  setTimeout(() => document.addEventListener("click", dismiss), 0);
}

function showCaptureChooser(
  anchor: HTMLElement,
  items: CredentialSummary[],
  username: string,
  onCreate: () => void,
  onUpdate: (item: CredentialSummary) => void,
): void {
  const box = document.createElement("div");
  box.style.cssText =
    "position:absolute;z-index:2147483647;background:#fff;border:1px solid #ccc;" +
    "border-radius:6px;box-shadow:0 4px 16px rgba(0,0,0,.15);font:13px sans-serif;" +
    "min-width:240px;max-width:320px;overflow:hidden;";

  const status = document.createElement("div");
  status.textContent = "Save this login to Safeory";
  status.style.cssText = "padding:9px 10px 5px;color:#333;font-weight:600;";
  box.appendChild(status);

  const matching = items.filter((item) => item.username === username);
  for (const item of matching) {
    const update = document.createElement("button");
    update.type = "button";
    update.textContent = `Update ${item.title}`;
    update.setAttribute("aria-label", `Update ${item.title} in Safeory`);
    update.style.cssText =
      "display:block;width:100%;min-height:40px;text-align:left;padding:10px;border:0;" +
      "background:#fff;cursor:pointer;";
    update.onclick = (event) => {
      if (!event.isTrusted) return;
      onUpdate(item);
      box.remove();
    };
    box.appendChild(update);
  }

  const create = document.createElement("button");
  create.type = "button";
  create.textContent =
    matching.length === 0 ? "Save new credential" : "Save as new credential";
  create.setAttribute("aria-label", "Save new credential in Safeory");
  create.style.cssText =
    "display:block;width:100%;min-height:40px;text-align:left;padding:10px;border:0;" +
    "background:#fff;cursor:pointer;border-top:1px solid #eee;";
  create.onclick = (event) => {
    if (!event.isTrusted) return;
    onCreate();
    box.remove();
  };
  box.appendChild(create);

  const rect = anchor.getBoundingClientRect();
  box.style.top = `${rect.bottom + window.scrollY + 4}px`;
  box.style.left = `${rect.left + window.scrollX}px`;
  document.body.appendChild(box);
  const dismiss = (event: MouseEvent) => {
    if (!box.contains(event.target as Node)) {
      box.remove();
      document.removeEventListener("click", dismiss);
    }
  };
  setTimeout(() => document.addEventListener("click", dismiss), 0);
}

function showStatus(anchor: HTMLElement, message: string): void {
  showChooser(anchor, [], () => undefined, message);
}

function captureTitle(): string {
  const title = document.title.trim();
  return title.length > 0 ? title : window.location.hostname;
}

async function enhanceForms(): Promise<void> {
  const forms = findLoginForms();
  if (forms.length === 0) return;

  for (const form of forms) {
    const badge = document.createElement("button");
    badge.type = "button";
    badge.textContent = "Safeory";
    badge.title = "Fill with Safeory";
    badge.setAttribute("aria-label", "Fill with Safeory");
    badge.style.cssText =
      "margin-left:6px;min-height:28px;font:12px sans-serif;padding:5px 8px;border:1px solid #999;" +
      "border-radius:4px;background:#fff;cursor:pointer;";
    let lookupPending = false;
    badge.onclick = (e) => {
      if (!e.isTrusted) return;
      e.preventDefault();
      e.stopPropagation();
      if (lookupPending) return;
      lookupPending = true;
      void send<ContentResponse>({ type: "findCredentials" })
        .then((res) => {
          if (res.type === "error") {
            showChooser(
              badge,
              [],
              () => undefined,
              "Safeory is temporarily unavailable.",
            );
            return;
          }
          if (res.type !== "credentials") return;
          if (res.locked) {
            showChooser(
              badge,
              [],
              () => undefined,
              "Unlock Safeory from the extension first.",
            );
            return;
          }
          if (res.items.length === 0 || !res.authorization) {
            showChooser(badge, [], () => undefined);
            return;
          }

          showChooser(badge, res.items, (id) => {
            void send<Extract<ContentResponse, { type: "fill" }>>({
              type: "fillCredential",
              id,
              authorization: res.authorization!,
            }).then((fillRes) => {
              if (fillRes.ok && fillRes.payload) fill(form, fillRes.payload);
            });
          });
        })
        .finally(() => {
          lookupPending = false;
        });
    };
    form.password.insertAdjacentElement("afterend", badge);

    const capture = document.createElement("button");
    capture.type = "button";
    capture.textContent = "Save with Safeory";
    capture.title = "Save or update this login in Safeory";
    capture.setAttribute("aria-label", "Save or update this login in Safeory");
    capture.style.cssText =
      "margin-left:6px;min-height:28px;font:12px sans-serif;padding:5px 8px;border:1px solid #999;" +
      "border-radius:4px;background:#fff;cursor:pointer;";
    let capturePending = false;
    capture.onclick = (event) => {
      if (!event.isTrusted) return;
      event.preventDefault();
      event.stopPropagation();
      if (capturePending) return;
      capturePending = true;
      void send<ContentResponse>({ type: "findCredentials" })
        .then((res) => {
          if (res.type === "error") {
            showStatus(capture, "Safeory is temporarily unavailable.");
            return;
          }
          if (res.type !== "credentials") return;
          if (res.locked) {
            showStatus(capture, "Unlock Safeory from the extension first.");
            return;
          }
          if (!res.authorization) {
            showStatus(
              capture,
              "Safeory could not authorize this save request.",
            );
            return;
          }

          const currentUsername = form.username?.value ?? "";
          const submit = (existing?: CredentialSummary) => {
            const password = form.password.value;
            if (password.length === 0) {
              showStatus(capture, "Enter a password before saving this login.");
              return;
            }
            const username = form.username?.value ?? "";
            void send<ContentResponse>({
              type: "captureCredential",
              authorization: res.authorization!,
              title: captureTitle(),
              username,
              password,
              ...(existing
                ? { existing: { id: existing.id, revision: existing.revision } }
                : {}),
            }).then((captureResponse) => {
              if (captureResponse.type === "error") {
                showStatus(capture, captureResponse.error);
                return;
              }
              if (captureResponse.type !== "capture") return;
              if (!captureResponse.ok) {
                showStatus(
                  capture,
                  captureResponse.error ?? "Saving this login failed.",
                );
                return;
              }
              showStatus(
                capture,
                captureResponse.action === "updated"
                  ? "Safeory updated this credential."
                  : "Safeory saved this credential.",
              );
            });
          };

          showCaptureChooser(
            capture,
            res.items,
            currentUsername,
            () => submit(),
            submit,
          );
        })
        .finally(() => {
          capturePending = false;
        });
    };
    badge.insertAdjacentElement("afterend", capture);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => void enhanceForms());
} else {
  void enhanceForms();
}
