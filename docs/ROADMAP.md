# Safeory Roadmap — Full 1Password + Trustworthy Alternative

Status: strategy document. `PLAN.md` remains the source of truth for the V1
local platform checklist; this document orders everything after it.

Product definition: one zero-knowledge product that combines
(a) a real password manager (logins, TOTP, autofill, password audit) and
(b) a life-continuity vault (documents, property, insurance, vehicles,
possessions, receipts, emergency access, legacy planning, trusted people).

Why not Vaultwarden: Vaultwarden is a server-only Bitwarden-API clone with no
frontend and no reusable crypto. Safeory's portable `vault-*` crates already
provide a modern crypto core (Argon2id + XChaCha20-Poly1305 + HKDF per-item
keys) that the password-manager features build on directly.

## Decision 0 — product shape: web app + all-in-one extension

The shipping client product has two browser surfaces:

1. **Web app** (`apps/web`, Next.js + React + shadcn/Base UI). This is the deep-management UI for full vault management, Emergency Card, recovery kit, Today/deadlines, attachments, importers, settings, and device management as those features land.
2. **All-in-one browser extension** (`apps/extension`, MV3, Chromium + Firefox target). It owns the always-present password-manager surface: unlock, browse/search, explicit-origin autofill, credential capture, quick add, and compact continuity views.

Both surfaces share the same `vault-wasm` crypto/domain boundary. Keys stay in WASM memory while unlocked; JavaScript receives ciphertext snapshots, redacted projections, or a single explicitly opened record.

Browser persistence is deliberately platform-specific: IndexedDB CAS for the web session and browser-extension storage for the extension background vault. Browser clipboard/filesystem capabilities require explicit user gestures and fail-closed handling where lifetime or permission guarantees are weaker than the core cryptographic guarantees.

Non-goals that STAY: banking/investment aggregation, resale marketplace, whole-vault cloud AI, ads/data business, company-side decryption, and standalone mobile apps (mobile web + the extension cover the need for now).

## Phase map (ordered; each phase keeps all verification gates green)
### Phase 1 — Finish V1 local platform + WASM extraction (core complete)
**Verification status: 233 Rust tests pass (0 failed) workspace-wide in
release; `cargo deny` advisories/bans/licenses/sources all ok; web +
extension + contracts typecheck/lint/build green.**
- ✅ DONE: `vault-storage` is now storage-agnostic. A `VaultStore` trait
  carries the portable data path; `rusqlite` is an optional `sqlite` feature
  (default-on for native SQLite users, off for WASM). Added a serializable `KVSnapshot`
  (ciphertext-only interchange) with `to_snapshot`.
- ✅ DONE: `crates/vault-wasm` — `MemStore` (in-memory `VaultStore`),
  `BrowserVault` session (create/unlock/lock/put/get/list/update/trash with
  keys held in WASM and zeroized on lock), and `WasmVault` wasm-bindgen
  bindings. Compiles to `wasm32-unknown-unknown`; Node smoke test proves
  encrypt/decrypt/lock/fail-closed run in JS and the snapshot has no plaintext.
  Restored browser snapshots are bounded before acceptance using the shared
  storage limits: schema version, object count, duplicate object IDs, encrypted
  item/root/recovery-wrap encoded size, and revision range are validated without
  decrypting the snapshot.
- ✅ DONE: `packages/contracts` — IndexedDB persistence (`persistence.ts`,
  plain TS, ciphertext snapshot only) + a version-fenced `VaultSession`
  controller for the web app. The full mutation + snapshot + CAS save is
  serialized; a post-mutation IndexedDB/CAS failure poisons and locks the
  session and forces reload rather than allowing in-memory state to run ahead
  of the durable snapshot. Pre-commit validation/auth/revision errors remain
  recoverable.
- ✅ DONE: `apps/web` scaffold — React + Next.js + Tailwind consuming
  `@safeory/contracts` + `vault-wasm`; typecheck/lint/build all green.
- ✅ DONE: widened `vault-wasm` bindings — Emergency Card (singleton, hidden
  from lists, CAS revisions), recovery kit (generate/install/verify/
  unlock-with via hex secret), and strong-password generation, each mirrored
  from `vault-core` with fail-closed tests. Verified in Node across the real
  WASM boundary (smoke.test.mjs covers all ten behaviors).
- ✅ DONE: `apps/web` vault UI — sidebar by record type with counts, item
  list + search, and schema-driven create/edit forms for ALL record kinds
  (credentials with inline generator, notes, documents, insurance, financial,
  property, vehicles, possessions, receipts, subscriptions) with masked secret
  fields and date inputs, trash, Emergency Card editor, Recovery Kit panel
  (one-time secret reveal), and a setup/unlock/recovery-unlock gate.
- 🟡 Partial: extension password-copy path — background decrypts only the
  requested unlocked credential and returns a SHA-256 ownership token. The
  popup attempts compare-and-clear after 30s, but popup teardown/clipboard
  permission can prevent that delayed clear; move ownership to a durable
  background/offscreen clipboard path before calling the 30s guarantee done.
- ✅ DONE: `apps/extension` (MV3, Chromium) scaffold — the all-in-one
  extension. Three self-contained bundles: a module **background worker** that
  alone holds the WASM vault (WASM embedded as base64, no runtime fetch),
  authenticates message senders, enforces exact HTTP(S)-origin matching,
  releases credential summaries only after a trusted click, rate-limits lookup
  per tab+origin, and requires a short-lived one-shot fill authorization before
  decrypting the selected credential; a **content script** that detects login
  forms and fills only on trusted user actions (never holds keys or a whole
  decrypted item list); and a React
  **popup** mini-vault (unlock/lock, credential list/add, password generator).
  Ciphertext snapshot persists via `chrome.storage.local`. typecheck/lint/
  build all green.
- TODO: close remaining PLAN.md local-only partials (grant persistence in
  payloads, trusted-person local model UX).
- ✅ DONE: Today/deadlines is exposed as a redacted unlocked-only WASM projection and rendered lazily in the web app. TODO: browser attachments and item links/jump navigation; add headless-browser `wasm-pack test` when a browser is available.
- Keep gates: `cargo fmt/clippy/test/audit/deny`, pnpm typecheck/lint/build.

### Phase 2 — Credential core upgrade (pure `vault-*` crates)
Make credentials a first-class password-manager record, not a secure note:
- Payload schema v5: structured login item (multiple URLs/hosts, username,
  password, password history, encrypted TOTP seed, notes, custom fields).
- Password-strength audit in `vault-core` (local scoring, reuse detection,
  age alerts) feeding the Today panel and the extension badge.
- TOTP generator (RFC 6238); secrets stay encrypted, codes computed on demand.
- Optional breach check via k-anonymity (HIBP range API), explicit opt-in,
  default offline; documented in `server-visible-metadata.md`.
- Importers: Bitwarden CSV/JSON and 1Password 1pux/CSV -> items + attachments.
- Web-app UI for all of the above (built on `vault-wasm`).

### Phase 3 — All-in-one extension (`apps/extension`) — the flagship surface
Replaces the old "native-messaging companion" idea; the extension is now a
first-class, standalone client sharing the same WASM core and UI package.
- MV3 extension for Chromium + Firefox; React UI from `packages/ui`.
- Unlock via the same `vault-wasm`; session unlock state in
  `chrome.storage.session` (memory-scoped, cleared on browser close);
  optional biometric/PIN re-unlock later.
- Autofill: content script detects login forms, suggests items matched by
  exact HTTP(S) origin (never substring; no cross-origin iframe fill),
  fills only on explicit user action; inline password generator.
- Save/capture: offer to save new or updated logins on submit.
- Mini-vault: browse/search all record types, view/copy credentials + TOTP,
  quick-add notes/receipts, read-only Emergency Card, Today/deadline badge.
- ✅ Browser/extension threat model updated for malicious pages, sender
  authentication, exact-origin fill, WASM-memory limits, CSP, browser-local
  persistence races, and clipboard residual risk. Per-tab+origin credential
  discovery throttling and one-shot fill authorization are implemented;
  durable clipboard ownership remains follow-up hardening.

### Phase 4 — Sync + multi-device (self-hosted backend first; in implementation)
- **Status: in implementation.** The self-hosted stack and opaque sync contract
  are being built now. Do not treat the HTTP sync/device/auth endpoint set as
  complete until the implementation and its security tests land end-to-end.
- `apps/api`: Rust HTTP service packaged for Docker. PostgreSQL owns durable
  account/device/opaque sync and policy metadata; an S3-compatible store owns
  ciphertext blobs (Garage preferred); Valkey provides ephemeral queues,
  rate-limit counters, and job coordination; SMTP delivers security
  notifications; a reverse proxy terminates TLS. See `cloudflare.md` (historical
  filename, now the self-hosted backend plan) and `server-visible-metadata.md`.
  No vault plaintext or usable vault keys are server-side, ever.
- Deliver one-machine Docker deployment and documented backup/restore of
  PostgreSQL plus ciphertext object storage before adding any managed-hosting
  convenience path. Hosted/cloud deployments remain optional adapters to the
  same protocol.
- `vault-sync`: device keypairs (X25519), envelope sync protocol,
  conflict = last-writer-wins on revisions + tombstones (history already
  bounded at 20 revisions/item).
- Account creation, email verification, device registration/revocation UX.
- This is what makes the *extension* useful across machines: the web app and
  every installed extension sync through it.

### Phase 5 — Web app reaches full deep-management parity (`apps/web`)
- Deep-management surface: full record editing, attachments (encrypted, per
  `vault-*`), portable export + recovery kit (File System Access API),
  legacy planning, Plan Test, settings, device management.
- **Emergency portal** mode: trusted-person access-request flow,
  waiting-period countdown, release delivery of sealed envelopes with
  client-side decryption in the trustee's browser.
- Strict CSP; no service-worker caching of decrypted data.

### Phase 6 — Mobile (web-first, no native apps for now)
- Responsive/mobile-web build of `apps/web` covers vault access on phones.
- Mobile *password autofill* is intentionally deferred (iOS AutoFill /
  Android Autofill require native shells); revisit only if it becomes a
  hard requirement. Copy/paste from mobile web is the interim answer.

### Phase 7 — Trust Engine end-to-end (the Trustworthy differentiator)
- Trusted-person identity + invitation flow over sync transport.
- Timed-release state machine: PostgreSQL is the durable source of truth for
  wait periods, request/revoke/release transitions, revisions, and idempotency;
  Valkey workers schedule/retry jobs but cannot independently authorize a
  release. The server enforces timing only (documented limitation).
- Enforce legacy/private-forever/destruction intent once grants + release
  machinery exist. Plan Test becomes a full simulation.

### Phase 8 — Hardening & launch
- External security audit of `vault-crypto`/`vault-emergency`/`vault-sharing`
  and the new `vault-wasm` boundary.
- Passkeys/TOTP polish, travel mode, richer audit log, version-history
  restore (currently deferred).
- Performance: unlock-time KDF calibration, WASM bundle size, large-vault
  list virtualization.

## Cross-cutting rules (never waived)
1. Dependency direction stays inward to portable crates; no core crate may
   depend on React/extension/Worker types. (`vault-wasm` wraps the
   core for the web/extension; the core never wraps `vault-wasm`.)
2. New server-visible metadata requires a threat-model update justifying why
   the field cannot remain encrypted.
3. Every new secret-handling surface (extension, web) gets its own
   threat-model section and negative security tests before release.
4. AGPL-3.0-or-later retained across all apps and crates.
5. All gates in README "Validation" stay green on every merge.

## Open decisions needing owner input
| # | Question | Recommendation |
|---|----------|----------------|
| 0 | Crypto delivery | RESOLVED — WASM the Rust core (ADR 0003); no TS rewrite |
| 1 | Browser storage backend | RESOLVED — IndexedDB via plain TS (`packages/contracts/persistence.ts`) persisting the ciphertext `KVSnapshot`; no Rust storage dep in WASM, preserving `#![forbid(unsafe_code)]` |
| 2 | Extension unlock scope | `chrome.storage.session` + per-origin fill confirmation |
| 3 | Breach checking | Opt-in k-anonymity only, default off |
| 4 | Passkeys | Store/sync passkey metadata first; full passkey *provider* in the extension deferred |
| 5 | Mobile | Responsive web only; native autofill deferred |
| 6 | Sync backend | RESOLVED — self-hosted Docker first: Rust HTTP API + PostgreSQL + S3-compatible object storage (Garage preferred) + Valkey + SMTP + reverse proxy/TLS; managed cloud hosting optional later |
| 7 | Self-host packaging | Define the supported Docker Compose topology, secret injection, migrations, health checks, and backup/restore procedure before Phase 4 is called production-ready |
