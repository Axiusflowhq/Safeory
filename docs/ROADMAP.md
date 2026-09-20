# Safeory Roadmap — Combined 1Password Families + Trustworthy Alternative

Status: strategy document. `PLAN.md` remains the source of truth for the V1
local platform checklist; this document orders everything after it.

Product definition: one zero-knowledge consumer product that combines
(a) the credential capabilities expected from 1Password Individual/Families
(logins, TOTP, passkeys, autofill, security health, sharing, recovery, and
multi-device use) and (b) the household operating capabilities expected from
Trustworthy (structured life records, files, connections, reminders, Inbox,
collaboration, continuity, and legacy planning).

This is not a parity commitment for 1Password Business, Enterprise, or
Developer. Workforce SSO/provisioning, SSH agents, CLI secret injection, and
enterprise secrets automation remain outside the consumer product contract.
The complete target architecture and capability contract are in
`docs/architecture/combined-product.md`.

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

Non-goals that STAY: banking/investment aggregation, resale marketplace,
whole-vault cloud AI, ads/data business, company-side decryption, and standalone
native apps for the current roadmap. Responsive web and the extension are the
committed surfaces; native-only autofill, background, and hardware-keystore
capabilities are not claimed.

## Decision 1 — production hosting: AWS

AWS is the production hosting target. Docker Compose remains a local
development/integration environment, not the production deployment model.

Launch-sized production for roughly the first 100 users is defined in
`docs/architecture/aws.md`: Route 53 + ACM, CloudFront, a private S3 static-web
bucket, a small Graviton EC2 Rust API/worker origin, RDS PostgreSQL, a private S3
ciphertext-object bucket, Cognito User Pools for hosted account identity, SES,
ECR, CloudWatch, and AWS-managed secrets. Valkey remains ephemeral and may run
on the AWS API host initially; move it to ElastiCache when independent
availability/scaling justifies the fixed cost.

The AWS decision does not change the zero-knowledge boundary. Master-passphrase
processing, vault/item/attachment encryption and decryption, usable vault keys,
recovery secrets, and unlocked search stay on authorized clients.

## Architecture gates before connected-product claims

The following must be designed and reviewed before their dependent features are
called production-ready:

1. account -> household -> space -> item domain and migration from the current
   single-owner vault;
2. independently rotatable private/shared space keys;
3. a high-entropy Account Secret or equivalent device-enrollment factor for
   remotely stored vaults;
4. a versioned sync protocol covering bootstrap, offline writes, conflicts,
   tombstones, attachments, history, revocation, and client compatibility;
5. minimal append-only security events plus encrypted household activity;
6. privacy modes for reminders, notifications, ingestion, OCR, and AI;
7. authenticated invitation, SecureLink, trustee, and emergency-release
   protocols.

The target sync and household-key distribution contract is
`docs/architecture/sync.md`.

## Phase map (ordered; each phase keeps all verification gates green)

### Phase 1 — Finish V1 local platform + WASM extraction (core complete)
**Verification status: workspace Rust tests and dependency-policy gates are
green; contracts typecheck/test/lint and web + extension typecheck/test/lint/build
gates are green, including the generated-WASM Node smoke test.**
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
  WASM boundary (`smoke.test.mjs` is part of `test:browser` and covers the
  browser-vault crypto/durability surface including principal/grant/retirement
  state and the generated recipient-device pairing responder. Pairing generation,
  private-key restoration, challenge response, and owner completion are exercised
  across the real JS/WASM boundary in addition to native Rust tests).
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
- ✅ DONE: encrypted per-item grant persistence, separate continuity-contact and
  stable local principal registries, bounded recipient-encryption device bindings,
  browser grant-planning UX, and durable browser recipient-device identities. The
  browser stores X25519+Ed25519 private material only as AES-GCM ciphertext under
  a non-extractable local Web Crypto wrapping key, exposes public registration,
  answers one-shot pairing challenges through WASM, and persists the verified
  Ed25519 binding on the owner side. TODO: authenticated remote invitation/pairing
  transport plus signed release/approval enforcement before any grant is actionable
  outside local planning. Pairing proves device-key possession; it does not enable
  release or establish real-world human identity.
- ✅ DONE: Today/deadlines is exposed as a redacted unlocked-only WASM projection and rendered lazily in the web app. Browser attachments are implemented. TODO: item links/jump navigation and headless-browser `wasm-pack test` when a browser is available.
- ✅ DONE (core simulation): `vault-emergency` now includes a fail-closed, revision-fenced timed-release request state machine covering approvals, wait periods, release/expiry, deny/revoke, idempotency, policy/revision changes, overflow, and clock-rewind rejection. TODO: expose only reviewed simulation/readiness surfaces in the web app, then add authenticated remote trustee delivery and a durable PostgreSQL/worker coordinator.
- Keep gates: frozen-lockfile install, `cargo fmt/clippy/test/audit/deny`, Compose
  config validation, Bun typecheck/test:browser/lint/check:icons/build/audit:js.

### Phase 2 — Household, space, and account-key foundation

- ✅ DONE (contract foundation): `vault-sync` now defines bounded, versioned
  Account, Household, Membership, Role, Space, and device-bound SpaceMember
  contracts without human-readable household/space names. Cross-account
  household membership, role/access rules, active ownership, private-space
  isolation, and key-generation bindings fail closed under validation.
- 🟡 Contract ready: a single-owner migration plan preserves existing opaque
  object IDs while assigning them to one account, household, and private space;
  wiring that plan into browser persistence is still outstanding.
- ✅ DONE (crypto foundation): independently rotatable random SpaceKeys and
  device-specific membership envelopes bind space/member/device/generation
  context and reject transplant, rollback, duplicate-recipient, and overflow
  cases. Server publication/rotation fencing and browser persistence remain.
  Random per-item and attachment keys remain unchanged.
- ✅ DONE (contract): the sync protocol specification and initial compatibility
  matrix define independent protocol/mutation/header/envelope/payload versions.
  `vault-sync` implements negotiation plus bounded opaque object and mutation
  contracts. The API now exposes the canonical compatibility advertisement and
  shares wire bounds. `@safeory/contracts` now validates and negotiates that
  advertisement and provides a bounded authenticated browser transport for
  canonical list/download/upload operations with ciphertext hash verification.
  `@safeory/contracts` also provides a bounded credential-free IndexedDB push
  outbox with idempotent replay and acknowledge-after-response semantics, plus
  verified pull-page processing with per-object durable acceptance and
  compare-and-swap cursor checkpoints. Browser-side account/household/
  membership/space and single-owner migration parsers now mirror the canonical
  Rust bounds and cross-reference validation. Matching Rust/browser routing
  evaluators bind account and device identity to distinct account, household,
  and space read/write/manage decisions without treating role as key access.
  The API now persists revision-fenced topologies after verifying every declared
  account/device principal and applies the evaluator to scoped object feeds,
  downloads, and atomic upload commits.
  Browser enrollment now registers a client-generated device UUID together
  with its X25519 encryption and Ed25519 signing public keys, validates the
  one-time bearer response, supports authenticated device revocation, and wraps
  persisted browser bearer tokens under non-extractable API/account/device-bound
  AES-GCM keys without placing credentials in the sync outbox or cursor stores.
  Active-device inventory is bounded to 64, enrollment/revocation is serialized
  per account, and the server refuses to revoke the final active device.
  The opaque-object endpoint validates and durably persists canonical
  mutation/header metadata with atomic operation-ID idempotency. Binding this
  transport and its durable coordinators to web and extension application flows,
  plus cross-account shared-object routing, remains.
- ADR 0006 now defines the high-entropy Account Secret and account-bound remote
  root envelope; the Rust/WASM core implements fresh-device root bootstrap and
  negative context/factor tests. The shared sync contract now carries the
  bounded account-bootstrap singleton through revision-fenced publication and
  authenticated direct metadata discovery. Web and extension development
  enrollment now re-authenticate the local root, confirm the generated Account
  Secret, and durably publish that singleton before topology. Complete
  production identity and recovery/new-device approval. ADR 0007 now defines
  and implements the signed, recipient-encrypted device-credential handoff core;
  durable pending activation, application UX, external review, and server-dump
  resistance validation remain. Cognito
  authentication alone remains insufficient.
- Add minimal security-event and encrypted activity-event formats.

### Phase 3 — Credential core and all-in-one extension

Make credentials first-class password-manager records and complete the browser
surface:

- structured logins with multiple origins, username, password history,
  encrypted TOTP seed, passkeys, notes, custom fields, and attachments;
- password/passphrase generation plus local strength, reuse, age, passkey, and
  2FA opportunity analysis feeding Today and the extension badge;
- optional k-anonymity breach checks, explicit opt-in and default offline;
- Bitwarden CSV/JSON and 1Password 1pux/CSV importers with a review/dry-run step;
- form-fill identities, addresses, and payment cards;
- Chromium and Firefox extension packaging, `chrome.storage.session` unlock,
  save/update capture, inline generation, exact-origin autofill, TOTP, and
  passkeys where browser APIs permit;
- mini-vault search across authorized spaces and compact Today/Emergency Card;
- durable background/offscreen compare-and-clear for clipboard ownership where
  supported, with honest platform limitations;
- keep the implemented sender authentication, origin binding, rate limits,
  one-shot fill authorization, CSP, and fail-closed mutation persistence.

### Phase 4 — AWS sync + multi-device (in implementation)
- **Status: in implementation.** The Rust API and opaque sync contract exist,
  while the production AWS account/deployment integration and client sync UX
  are still being built. Do not treat the HTTP sync/device/auth endpoint set as
  complete until the implementation and its security tests land end-to-end.
- `apps/api`: Rust HTTP service packaged as a versioned container. In production
  RDS PostgreSQL owns durable account/device/opaque sync and policy metadata;
  S3 owns ciphertext blobs; Cognito owns hosted account identity; SES delivers
  account/security notifications; Valkey provides only ephemeral queues,
  rate-limit counters, and job coordination. No vault plaintext or usable vault
  keys are server-side, ever.
- Build the AWS launch topology in `infra/aws/` from the contract in
  `docs/architecture/aws.md`: Route 53/ACM, CloudFront, private S3 web +
  ciphertext buckets, ECR, Graviton EC2 API/worker, RDS PostgreSQL, Cognito,
  SES, IAM/secrets, CloudWatch, backup/restore, and GitHub Actions OIDC deploy.
- Keep `docker-compose.yml` as the local integration environment using
  PostgreSQL/Valkey/Garage/Mailpit; it is not the production hosting plan.
- `vault-sync`: the versioned household/space domain and ciphertext-preserving
  local migration, rotatable space-key envelope, compatibility negotiation, and
  opaque mutation contracts are implemented. The shared browser contracts now
  provide fail-closed compatibility preflight; next wire it into clients and
  integrate scoped object mutations with the API. Exact revision preconditions
  reject stale overwrites; conflict handling preserves
  both candidates or requires explicit
  user resolution rather than silently applying last-writer-wins. Tombstones
  and history remain bounded.
- Cognito-backed account creation/sign-in/email verification plus Safeory
  device registration/revocation UX. Cognito identity does not replace the
  per-device cryptographic identity used by sync/sharing.
- End-to-end web + extension sync: initial bootstrap, incremental pull/push,
  offline/reconnect behavior, conflict handling, tombstones, and revocation.
- Production gate: RDS/S3 restore drill, secrets/IAM review, CloudWatch
  alarms/redaction, TLS/CSP/origin restrictions, and launch-population
  load/soak testing.
- This is what makes the *extension* useful across machines: the web app and
  every installed extension sync through it.

Additional completion requirements from the combined-product architecture:

- household membership and space-key envelope delivery;
- append-only security events and encrypted household activity objects;
- pagination/bounds for large file-centric households;
- interrupted chunk resume, attachment integrity, quota, and garbage collection;
- key-envelope rotation after member/device revocation;
- Travel Mode residency state and authenticated restoration;
- protocol downgrade/compatibility tests across at least the oldest supported
  web and extension versions.

### Phase 5 — Household operating system and private Inbox

- Add dedicated family identity, medical, tax, legal, business, contact, and
  general-document schemas alongside the implemented record kinds.
- Deliver page details, notes, encrypted folders/files, connections, custom and
  recurring reminders, and item/history navigation.
- Add Files, Inbox, Reminders, and Activity views with local search/filtering.
- Support upload, drag/drop, extension capture, and client-side imports.
- Implement local OCR/extraction/classification/summarization and user-reviewed
  filing, field, connection, and reminder suggestions. Any remote processing
  requires a separate opt-in ADR and must not be represented as zero knowledge.
- Provide private-local reminders and an opt-in cloud-scheduled generic
  notification mode using only the minimum metadata permitted by
  `server-visible-metadata.md`.
- Keep strict CSP; never cache decrypted data in a service worker.

### Phase 6 — Household collaboration and secure sharing

- Full, partial, and legacy collaborator invitations over authenticated account
  and device transport.
- Shared-space and selected-item view/edit permissions with revocation and key
  rotation.
- SecureLinks using encrypted immutable copies, explicit audience/expiry,
  revocation, and no password history.
- Device inventory, account recovery roles, security notifications, and
  household activity/audit UX.
- Travel Mode removes non-travel space keys and ciphertext from participating
  devices and restores them only after authenticated sync.
- Portable household export and account deletion with documented server backup
  retention/cryptographic-erasure behavior.

### Phase 7 — Trust Engine end-to-end (continuity differentiator)
- Trusted-person identity + invitation flow over sync transport.
- Promote the already-tested local timed-release state machine to durable
  coordination: PostgreSQL becomes the source of truth for wait periods,
  request/revoke/release transitions, revisions, and idempotency; Valkey workers
  schedule/retry jobs but cannot independently authorize a release. The server
  enforces timing only (documented limitation).
- Enforce legacy/private-forever/destruction intent once grants + release
  machinery exist. Plan Test becomes a full simulation.
- Ship the trustee portal, signed request/approval protocol, owner alerts,
  waiting-period countdown, sealed-capsule delivery, denial/revocation, expiry,
  and policy/revision invalidation across devices.
- Define operational evidence, false-claim handling, support boundaries, audit
  retention, and incident procedures. Device-key possession must never be
  presented as verified human identity.

### Phase 8 — Platform reach, hardening, and launch
- External security audit of `vault-crypto`/`vault-emergency`/`vault-sharing`
  and the new `vault-wasm` boundary.
- Passkeys/TOTP polish, travel mode, richer audit log, version-history
  restore (currently deferred).
- Performance: unlock-time KDF calibration, WASM bundle size, large-vault
  list virtualization.
- Responsive web remains the committed mobile surface. Native clients require
  a new ADR, but Safeory must not claim native mobile autofill, dependable
  background scanning/reminders, universal desktop autofill, or hardware-backed
  biometric isolation until such clients exist.
- Production parity gate covers the declared consumer matrix only. Unsupported
  capabilities remain visible release notes rather than implied parity.

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
| 1 | Browser storage backend | RESOLVED — IndexedDB via plain TS (`packages/contracts/src/persistence.ts`) persisting the ciphertext `KVSnapshot`; no Rust storage dep in WASM, preserving `#![forbid(unsafe_code)]` |
| 2 | Extension unlock scope | `chrome.storage.session` + per-origin fill confirmation |
| 3 | Breach checking | Opt-in k-anonymity only, default off |
| 4 | Passkeys | Store/sync passkey metadata first; full passkey *provider* in the extension deferred |
| 5 | Mobile | Responsive web only; native autofill deferred |
| 6 | Sync backend | RESOLVED — AWS production: Rust HTTP API + Cognito + RDS PostgreSQL + S3 ciphertext storage + Valkey/ElastiCache as ephemeral coordination + SES + CloudFront/Route 53/ACM; Docker Compose is local development only |
| 7 | AWS production packaging | RESOLVED architecture in `docs/architecture/aws.md`; implement reviewable IaC under `infra/aws/`, OIDC CI/CD, migrations, health checks, observability, and tested backup/restore before Phase 4 is production-ready |
| 8 | Product parity boundary | RESOLVED — target 1Password Individual/Families + Trustworthy household/continuity; exclude 1Password Business/Enterprise/Developer |
| 9 | Household key boundary | RESOLVED — ADR 0005 defines device-specific space-key envelopes and monotonic rotation; server/client integration remains |
| 10 | Cloud offline-attack factor | RESOLVED design — ADR 0006 defines the Account Secret and remote-root construction; core implementation landed, while production enrollment and external review remain |
| 11 | Document automation | Local/private processing by default; any remote OCR/AI is explicit opt-in with a separate disclosure/threat ADR |
| 12 | Reminder scheduling | Offer private-local and opt-in minimal-metadata cloud scheduling; never put reminder content in email/push metadata |
