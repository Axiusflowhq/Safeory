# ADR 0002: Ship Web App + All-in-One Extension, Drop the Tauri Desktop App

Date: 2026-09-19

## Status

Accepted. Supersedes the deployment-surface assumptions of ADR 0001 (which
remains correct about keeping Tauri *replaceable* — this decision replaces
it).

## Context

Safeory aims to be a full 1Password + Trustworthy alternative. The original
plan shipped a Tauri desktop app and deferred web/extension. A desktop shell
adds a third surface to build, secure, and maintain, while the two surfaces a
password manager and a life-continuity vault actually need are a deep web app
and an always-present browser extension. The WASM ecosystem now supports the
entire crypto core in a browser.

## Decision

- The product ships as exactly two surfaces: a React **web app** (`apps/web`)
  and an **all-in-one browser extension** (`apps/extension`, MV3, Chromium +
  Firefox). No Tauri desktop app; no native mobile apps for now (mobile web +
  extension cover the need).
- The portable Rust core is compiled to WebAssembly in a new `vault-wasm`
  crate (wasm-bindgen) and shared by both surfaces. `vault-crypto`,
  `vault-sharing`, `vault-emergency`, and `vault-models` are pure-Rust and
  WASM-able; `getrandom` uses its `wasm_js` backend.
- `vault-storage` gains a browser backend (IndexedDB behind a storage trait)
  because `rusqlite` (bundled C SQLite) cannot target WASM. `vault-core`
  becomes storage-agnostic.
- `vault-platform` (already pure traits) gets browser/extension
  implementations: WebCrypto non-extractable keys, Async Clipboard API with
  the existing 30s compare-and-clear, and `chrome.storage.session` for
  extension session state.
- Native save dialogs (export, recovery kit) move to the File System Access
  API with an `<a download>` fallback.
- Keys stay inside WASM linear memory (zeroed on lock); only ciphertext and
  redacted projections cross the JS/TS boundary.

## Consequences

- One React codebase (via `packages/ui` + `packages/contracts`) serves both
  the web app and the extension popup/panel.
- Positive: no WebView shell to secure; ADR 0001's core/adapter separation
  means the pivot touches only the adapter and storage layers.
- Negative / costs: the SQLite rollback-journal plaintext test needs an
  IndexedDB analogue; OS-keystore and native-mobile autofill are deferred;
  the browser becomes a trusted process, so CSP, extension isolation, and
  per-origin fill confirmation become part of the security boundary.
- The extension is the flagship password-manager surface and gets its own
  threat-model section before release.
