/**
 * Content script: runs in the page, holds NO keys and NO decrypted data at
 * rest. It detects login forms, asks the background worker for credentials
 * matching this origin, and fills only after the user explicitly picks one.
 */

import type { ContentRequest, ContentResponse, CredentialSummary, FillPayload } from "./messages";

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
    const container = password.closest("form") ?? password.closest("div") ?? document.body;
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
  if (form.username && payload.username !== "") setNativeValue(form.username, payload.username);
  setNativeValue(form.password, payload.password);
}

/** Render a minimal chooser so the user explicitly picks a credential. */
function showChooser(
  anchor: HTMLElement,
  items: CredentialSummary[],
  onPick: (id: string) => void,
): void {
  const box = document.createElement("div");
  box.style.cssText =
    "position:absolute;z-index:2147483647;background:#fff;border:1px solid #ccc;" +
    "border-radius:6px;box-shadow:0 4px 16px rgba(0,0,0,.15);font:13px sans-serif;" +
    "min-width:220px;overflow:hidden;";
  for (const item of items) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = `${item.title} — ${item.username}`;
    btn.style.cssText =
      "display:block;width:100%;text-align:left;padding:8px 10px;border:0;" +
      "background:#fff;cursor:pointer;";
    btn.onmouseenter = () => (btn.style.background = "#f0f0f0");
    btn.onmouseleave = () => (btn.style.background = "#fff");
    btn.onclick = (e) => {
      if (!e.isTrusted) return;
      onPick(item.id);
      box.remove();
    };
    box.appendChild(btn);
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

  const res = await send<Extract<ContentResponse, { type: "credentials" }>>({
    type: "findCredentials",
  });
  if (res.locked || res.items.length === 0) return;

  for (const form of forms) {
    const badge = document.createElement("button");
    badge.type = "button";
    badge.textContent = "🔐 Safeory";
    badge.title = "Fill from Safeory";
    badge.style.cssText =
      "margin-left:6px;font:12px sans-serif;padding:2px 6px;border:1px solid #999;" +
      "border-radius:4px;background:#fff;cursor:pointer;";
    badge.onclick = (e) => {
      if (!e.isTrusted) return;
      e.preventDefault();
      e.stopPropagation();
      showChooser(badge, res.items, (id) => {
        void send<Extract<ContentResponse, { type: "fill" }>>({
          type: "fillCredential",
          id,
        }).then((fillRes) => {
          if (fillRes.ok && fillRes.payload) fill(form, fillRes.payload);
        });
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
