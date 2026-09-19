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
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => void enhanceForms());
} else {
  void enhanceForms();
}
