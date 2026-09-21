# Safeory Development Plan

This is the **single source of truth for ongoing development work**.

Future agents should read this file first, continue from the first incomplete
task, preserve completed work, and update this file when a task or gate changes.

Do not create additional roadmaps, ADRs, architecture documents, planning
documents, or security-design markdown while development is in progress. The
final consolidated architecture/security documentation will be written after
the implementation is complete and proven.

---

## Development direction

Safeory has selected **Bitwarden OSS server + Rust SDK/core as the
password-manager foundation**.

Safeory is **not** adopting, importing, re-skinning, or building its product on
Bitwarden's web frontend, browser-extension UI, component library, navigation,
design system, or product shell. Safeory keeps its own frontend and browser UX.
The Bitwarden clients repository is a reference/proof source only. Narrow,
clearly isolated non-UI logic may be ported from it when that is the safest way
to preserve a mature password-manager behavior, but whole client applications or
their UI architecture must not enter the Safeory foundation.

Development should no longer spend time rebuilding generic password-manager
features already provided by that foundation.

Primary engineering focus from now on:

1. finish the OSS-clean Bitwarden server + Rust SDK/core proof;
2. adapt and integrate that backend/core foundation behind Safeory-owned web and
   browser clients;
3. fully test and stabilize the adapted foundation before feature expansion;
4. port Safeory's existing useful life-vault/domain work onto that foundation;
5. implement Household and independently encrypted Safeory Spaces;
6. migrate existing Safeory users/data safely;
7. add Safeory-specific household, continuity, Emergency, Trust Engine, and
   Plan Test features;
8. productionize, harden, externally review, and launch the combined
   Trustworthy-style household/life organization + 1Password-style consumer
   password-manager alternative.

The current Safeory implementation remains available as the tested legacy
prototype and migration source until the new implementation reaches verified
parity. Do not delete working legacy code before its replacement and migration
tests pass.

---

## Non-negotiable rules

- Do not add new generic password-manager functionality to the legacy Safeory
  stack.
- Do not continue the legacy custom generic sync, account bootstrap, generic
  device enrollment, generic attachment transport, or autofill architecture
  except for security fixes, data-loss fixes, migration support, fixtures, or
  tests.
- Reuse and adapt the cleaned Bitwarden server and Rust SDK/core for accounts,
  sessions, devices, credentials, TOTP/passkey cryptography and protocols,
  password-manager sync, revisions, encrypted attachments, imports/exports,
  trash/history, key management, and other mature non-UI password-manager
  primitives that survive Safeory's review.
- Safeory owns the complete product frontend: web UI, browser-extension UI,
  navigation, design system, product shell, household/life-record workflows,
  capture/autofill UX, settings, onboarding, and all customer-facing surfaces.
- Do not import Bitwarden web or browser frontend applications into Safeory.
  Do not re-skin them and call that the Safeory frontend.
- If a mature Bitwarden client-side behavior is needed (for example autofill,
  capture, passkey plumbing, or protocol glue), extract/port only the smallest
  reviewed non-UI logic required and wrap it behind Safeory-owned interfaces and
  tests. Do not inherit Bitwarden UI architecture as a shortcut.
- Safeory-specific work belongs in life records, Household, Spaces, Today,
  Files, Inbox, reminders, relationships, collaboration, Trust Engine,
  continuity, Emergency Card, legacy intent, Plan Test, migration, and product
  UX.
- Never import or depend on `bitwarden_license`,
  `@bitwarden/commercial-sdk-internal`, or any other restricted Bitwarden
  commercial code.
- Do not reproduce or bypass upstream paid-license checks. Safeory implements
  its own product entitlement rules where required.
- A Safeory Space must be a real independently keyed cryptographic boundary.
  A folder, collection, group, tag, or UI grouping is never sufficient.
- Removing a member/device must stop future key/data delivery and rotate future
  access. Previously received plaintext or keys cannot be remotely recalled.
- Raw account/user, Space/sharing-boundary, record, attachment, or trustee
  private keys must not be exposed to ordinary UI JavaScript.
- Server-side services must not receive vault plaintext or usable content keys.
- Preserve negative security tests whenever modifying inherited security
  boundaries.
- Do not weaken zero-knowledge behavior merely to fit an inherited abstraction.
- Treat imported Bitwarden code as unadapted until Safeory-specific integration,
  pruning, security review, compatibility tests, regression tests, and end-to-end
  tests all pass. Passing an upstream build alone never means the foundation is
  stable or ready for feature development.
- Do not start the main Safeory feature-expansion phases on top of a partially
  adapted foundation. First reach the explicit Foundation Adaptation & Stability
  Gate in Phase 1.

---

## Selected upstream baseline

Keep exact source provenance in `docs/provenance/foundation-seed.json`.

Current pinned foundation:

- Bitwarden clients reference/proof baseline only (not a frontend import):
  `07ac2aa903459ea8e1c18e3295b765be0bc3585f`
- Bitwarden server:
  `6fcd3b71f5f2eb0881dd4a3b587fa8afe5957da1`
- Bitwarden Rust SDK:
  `7fd530e4852639d7391d062760891631ee9c15c1`

Do not change these pins casually. A pin change requires reproducing the
corresponding clean build/test evidence and updating the provenance manifest.

---

## Already completed — do not repeat without a reason

### Foundation selection research

- [x] Compared Bitwarden OSS, Passbolt CE, and Padloc as seed candidates.
- [x] Selected Bitwarden OSS as the Safeory password-manager foundation.
- [x] Pinned exact client/server/SDK commits.
- [x] Reproduced Bitwarden OSS Chromium extension build.
- [x] Reproduced Bitwarden OSS Firefox extension build.
- [x] Reproduced Bitwarden OSS self-hosted web build.
- [x] Reproduced Passbolt Chromium and Firefox extension builds as fallback
      evidence.
- [x] Confirmed Padloc's stable branch requires the historical Node 16/npm 8
      toolchain and has materially higher modernization cost.

### Bitwarden SDK proof

- [x] Identified that upstream `bitwarden-pm`'s WASM feature pulls a commercial
      vault dependency even when the explicit license feature is disabled.
- [x] Identified the exact workspace/feature/export edges that must be removed.
- [x] Created a disposable SDK copy with `bitwarden_license` physically
      removed.
- [x] Removed commercial SDK workspace/dependency/feature/export edges in the
      disposable proof.
- [x] Confirmed clean Cargo metadata/dependency tree has no commercial
      dependency.
- [x] Built the cleaned production WASM SDK successfully.

### Bitwarden server proof

- [x] Installed the required disposable .NET/Rust toolchains without changing
      the developer's global setup.
- [x] Confirmed PostgreSQL is a supported first-class Bitwarden database
      provider with Npgsql/EF migrations.
- [x] Confirmed the full upstream test graph compiles on a supported .NET 10
      feature band.
- [x] Ran the large upstream server test graph: 11,760 tests passed; remaining
      failures were concentrated in workstation integration dependencies such as
      Docker/Testcontainers/database containers/Azurite/SMTP-TLS.
- [x] Created a disposable server copy with `bitwarden_license` physically
      removed.
- [x] Built cleaned OSS API, Identity, Notifications, Events,
      EventsProcessor, Admin, and PostgreSQL migrations successfully.

### Safeory transition groundwork

- [x] Added a machine-readable foundation provenance manifest.
- [x] Added `bun run check:foundation` to reject restricted foundation paths
      and dependencies.
- [x] Wired the foundation boundary check into CI.
- [x] Implemented initial transport-independent `SafeoryEnvelopeV1`.
- [x] Added strict envelope version/identity/bounds/extension/reminder/
      relationship/continuity validation.
- [x] Added negative product-domain tests; current suite passes 9/9.
- [x] Wired product-domain tests into CI.
- [x] Preserved the current Safeory implementation as the migration/reference
      implementation.

---

# PHASE 0 — Finish foundation proof

Do not import the foundation into production paths until this phase passes.

## 0.1 Prove the Bitwarden clients reference without adopting its frontend

The clients repository is used only to understand and verify mature
password-manager behavior and to identify any narrowly reusable non-UI logic.
Its web app, browser-extension UI, components, routes, product shell, branding,
and design system are not part of the Safeory import.

- [x] Create a fresh disposable copy of the pinned Bitwarden clients checkout.
- [x] Physically remove the complete `bitwarden_license/` tree in that proof.
- [x] Remove `@bitwarden/commercial-sdk-internal` from package manifests and
      lockfiles in that proof.
- [x] Remove commercial-only project targets/configuration that references
      deleted source.
- [x] Run dependency search proving no restricted package/path remains.
- [x] Install dependencies from a clean checkout.
- [x] Build/run enough upstream web/browser surfaces in the disposable checkout
      to prove the OSS behavior we may need to reproduce or port.
- [x] Run the relevant client unit/integration tests for any non-UI behavior we
      intend to depend on or selectively port.
- [x] Inventory every client-side behavior Safeory still needs after adopting
      the Rust SDK/server and classify it as: available from SDK/core, reimplement
      in Safeory, or selectively port as isolated non-UI logic.
- [x] Record exact build commands/toolchain versions and the final list of any
      client-side non-UI source that is actually selected for porting.
- [x] Explicitly prove that no Bitwarden frontend application, UI component
      tree, route tree, product shell, or design system is selected for import.

Phase 0.1 proof evidence (2026-09-21):

- Disposable proof checkouts are kept under ignored `.proof/` paths. A fresh
  local clone was recreated at `.proof/bitwarden-clients-phase01-final` from the
  pinned commit `07ac2aa903459ea8e1c18e3295b765be0bc3585f`, then prepared from a
  clean working tree with:
  `node scripts/prepare-bitwarden-clients-proof.mjs .proof/bitwarden-clients-phase01-final`.
- `scripts/check-bitwarden-clients-proof.mjs` now verifies the pinned Git commit,
  physical removal of `bitwarden_license/`, package-manifest and lockfile removal
  of `@bitwarden/commercial-sdk-internal`, removal of commercial app project
  configurations, self-hosted browser defaults, disabled upstream update channel,
  and (when dependencies are installed) absence of the commercial SDK from
  `node_modules`.
- Clean dependency reproduction used Node `v24.20.0` and npm `11.19.0` in
  `.proof/bitwarden-clients-clean-repro`; `npm ci` completed from the cleaned
  lockfile. The inherited dependency graph reported 87 npm audit findings
  (3 low, 36 moderate, 44 high, 4 critical). These are retained as explicit
  dependency-risk evidence for the later provenance/security gates rather than
  being hidden or auto-fixed inside the proof.
- The installed proof passed:
  `node scripts/check-bitwarden-clients-proof.mjs .proof/bitwarden-clients-clean-repro --require-installed`.
- Cleaned OSS build commands passed with exit code 0:
  `npm run build:oss:selfhost:prod --workspace @bitwarden/web-vault`,
  `npm run build:prod:chrome --workspace @bitwarden/browser`, and
  `npm run build:prod:firefox --workspace @bitwarden/browser`.
- Candidate non-UI seam tests were exercised before selecting any source for
  permanent import. Common autofill/domain/FIDO2/login-URI tests passed
  299 tests with 2 upstream todos. Browser URL-variation, event-security,
  insertion, FIDO2 background, and FIDO2 content-script suites passed. The
  exploratory full DOM collector suite exposed one upstream timing-sensitive
  late-shadow-root hydration assertion: it fails when run with the full file but
  passed twice when isolated. Because the collector is not selected for import,
  this is recorded as upstream reference instability rather than patched or
  suppressed in Safeory.
- Client behavior classification after the server + Rust SDK/core adoption:
  account/session/device state, encrypted vault records, sync/revisions,
  attachments, imports/exports, TOTP/passkey credential cryptography/storage,
  and key-management primitives belong to the retained server/SDK/core; all
  customer-facing web/extension UI, navigation, onboarding, settings, capture
  prompts, save/update UX, popup/options surfaces, and product shell are Safeory
  reimplementations; URL/origin matching/domain normalization and browser
  WebAuthn messaging/permissions-policy logic are the only current candidates
  for a later isolated non-UI port if Phase 1 proves the SDK/core lacks the needed
  browser seam. DOM collection/insertion remains reference-only unless a narrower
  reviewed helper is demonstrably necessary.
- Final Phase 0.1 selected client-source import list: **none**. No Bitwarden web
  application, browser UI, Angular component tree, route tree, product shell,
  branding, design system, or other frontend source is selected for permanent
  import. The permanent `foundation/` tree therefore remains free of Bitwarden
  frontend code at this gate.

**Exit gate:** the disposable clients proof has no restricted dependency, the
required inherited behaviors are understood/tested, and the permanent Safeory
foundation still contains no Bitwarden frontend.

## 0.2 Reproduce cleaned foundation on Linux CI

- [x] Add CI jobs for cleaned SDK and server build proof plus any explicitly
      selected isolated non-UI client logic.
- [ ] Build the cleaned Rust/WASM SDK on Linux.
- [ ] Build the cleaned server composition on Linux.
- [ ] Build the Safeory-owned web and browser-extension clients against the
      adapted foundation on Linux.
- [ ] Run non-environment-dependent upstream tests for retained server/SDK/core
      code and Safeory tests around adapted behavior.
- [x] Add Docker-backed integration services for the environment-dependent
      server tests that matter to Safeory.
- [x] Ensure PostgreSQL migration tests run against a real PostgreSQL service.

Phase 0.2 implementation evidence (2026-09-21; Linux execution gates still
pending CI):

- Added deterministic SDK proof tooling:
  `scripts/prepare-bitwarden-sdk-proof.mjs` and
  `scripts/check-bitwarden-sdk-proof.mjs`. A fresh checkout of pinned SDK commit
  `7fd530e4852639d7391d062760891631ee9c15c1` was cleaned reproducibly, its
  licensed source/features/API surface was removed, Cargo pruned only now-
  unreachable lock entries, and `cargo check --workspace --locked` passed on the
  prepared checkout.
- The retained cleaned SDK library tests also pass locally with
  `cargo test --workspace --locked --lib`. This host does not provide Bash or
  Binaryen (`wasm-opt`/`wasm2js`), so the release WASM build remains an explicit
  Linux CI gate rather than being claimed from Windows evidence.
- Added deterministic server proof tooling:
  `scripts/prepare-bitwarden-server-proof.mjs` and
  `scripts/check-bitwarden-server-proof.mjs`. A fresh checkout of pinned server
  commit `6fcd3b71f5f2eb0881dd4a3b587fa8afe5957da1` passes the structural OSS gate:
  `bitwarden_license/` is physically absent, the checkout forces the `OSS`
  compilation constant, licensed project references/solution groups are removed,
  `Billing` and `SeederApi` use the upstream `AddOosServices()` registrations,
  and the Aspire host no longer includes SSO/SCIM licensed services.
- This Windows host has no .NET SDK installed, so server compilation is not
  represented as locally proven. The authoritative server build/test proof is
  intentionally delegated to the new Linux CI jobs below.
- Added CI job `foundation-sdk-proof`: recreates the pinned SDK checkout on
  Ubuntu, prepares/checks the OSS graph, runs locked Cargo check and retained
  library tests, installs Binaryen, builds the release WASM package through the
  upstream build script, and rechecks the boundary afterward.
- Added CI job `foundation-server-proof`: recreates the pinned server checkout on
  Ubuntu with .NET `10.0.103` and Rust `1.97.1`, builds the cleaned self-hosted
  service/util composition, runs selected non-environment-dependent upstream
  server tests, and rejects restored assets that retain licensed dependencies.
- Added CI job `foundation-server-postgres` with a real `postgres:17-alpine`
  service. It injects the disposable connection string through the upstream
  `bitwarden-Api` user-secrets mechanism, runs the pinned `dotnet-ef 8.0.8`
  PostgreSQL migration chain, then runs the existing EF repository integration
  suite against that database. GitHub Actions run `35554080600` completed this
  job successfully on 2026-09-21, closing the real-PostgreSQL migration gate.
- The same run exposed a proof-checkout isolation defect while building
  `util/RustSdk`: its standalone Cargo package walked upward into Safeory's parent
  workspace because `.proof/` is nested inside this repository. The server
  preparation script now adds an empty `[workspace]` marker to that nested Cargo
  manifest, reproducing the standalone semantics of an upstream server clone.
  A fresh pinned checkout passes the corrected structural checker and standalone
  Cargo metadata probe; the corrected Linux server build remains pending the next
  CI run.
- Phase 0.1 selected no Bitwarden client source for porting, so there is currently
  no isolated client-code proof job to add. Safeory-owned web/extension builds
  remain in the existing Ubuntu `quality` job; their "against adapted foundation"
  gate stays open until the production foundation adapter is introduced.

**Exit gate:** the retained cleaned backend/core plus Safeory-owned clients
reproduce in clean CI without depending on Bitwarden frontend applications.

## 0.3 Produce legal/provenance artifacts

- [ ] Generate SBOM for retained SDK, server, and any selectively ported non-UI
      client code.
- [ ] Generate license inventory.
- [ ] Generate required notices bundle.
- [x] Record removed restricted paths/packages.
- [x] Record all retained upstream source commits and exact retained source
      boundaries.
- [x] Add a CI failure if restricted paths/dependencies reappear.
- [ ] Obtain qualified license review before public distribution.

Phase 0.3 implementation evidence (2026-09-21; full Linux artifact generation
still pending CI):

- Added `scripts/generate-foundation-provenance.mjs`. It runs the cleaned SDK and
  server boundary checkers first, then records every retained tracked upstream
  file with SHA-256, the pinned source commits, the exact cleanup diffs, and the
  forbidden path/dependency policy.
- Source-only local generation succeeded against the prepared pinned checkouts:
  1,545 retained SDK files and 7,271 retained server files were hashed. The SDK
  CycloneDX 1.6 inventory contained 919 locked Cargo/npm components and reported
  no missing license metadata in that local source-only run.
- The full generator also reads restored NuGet `project.assets.json` files and
  package `.nuspec` metadata to build the server CycloneDX SBOM and dependency
  license inventory. This path intentionally fails if the server composition has
  not been restored; it cannot be represented as locally executed on this host
  because the pinned .NET SDK is unavailable here.
- Added `docs/provenance/README.md` describing the source pins, generated artifact
  contract, source-only limitation, and the separate qualified-review gate.
- Added CI job `foundation-provenance`, dependent on the cleaned SDK/server proof
  jobs. It recreates both pinned cleaned checkouts, restores the retained server
  composition, generates SDK/server SBOMs, license inventory, exact source
  manifests, restricted-removal evidence, copied upstream notice/license files,
  and `THIRD_PARTY_NOTICES.md`, then uploads the bundle as
  `safeory-foundation-provenance`.
- Restricted-source/dependency regression is now fail-closed in CI through the
  clients/SDK/server proof checkers, the permanent foundation-boundary checker,
  and the provenance generator's preflight checks. Full SBOM/license/notices
  checkboxes remain open until the Linux provenance job has actually passed.

**Exit gate:** provenance/SBOM/license/notices pipeline is reproducible and has no
known blocking licensing issue.

## 0.4 Prove inherited password-manager behavior

Create an automated self-hosted fixture using the cleaned server/SDK foundation
through Safeory-owned test clients/harnesses rather than Bitwarden's frontend:

- [x] Create account A.
- [x] Create account B.
- [x] Log in from two separate client/device contexts.
- [x] Create/edit/delete/restore a login.
- [x] Add TOTP.
- [x] Add a passkey where browser automation permits it.
- [ ] Add/download/delete an attachment.
- [x] Sync the same account across two devices.
- [x] Import representative standard password-manager fixtures.
- [x] Import a representative 1Password fixture.
- [x] Capture a new login using the Safeory extension.
- [x] Update an existing login using the Safeory extension.
- [x] Autofill only the correct origin in Chromium using Safeory-owned extension
      UI/integration code.
- [x] Autofill only the correct origin in Firefox using Safeory-owned extension
      UI/integration code.
- [x] Revoke a session/device.
- [ ] Prove the revoked context stops receiving/using future authenticated
      operations.

Phase 0.4 implementation evidence (2026-09-21):

- Added a Safeory-owned .NET behavior harness under
  `tests/foundation/server-behavior/`. It is copied into the disposable cleaned
  server checkout at test time and references only the upstream server test-host
  infrastructure; no Bitwarden frontend application or UI code is imported.
- The first scenario drives the real in-process API/Identity HTTP contracts and
  covers two accounts, two explicit browser device identifiers for account A,
  opaque encrypted login creation with username/password/TOTP/URI data,
  revision-fenced edit, account isolation, second-device sync, soft-delete,
  restore, and durable server-side device deactivation.
- Device deactivation is deliberately followed by a probe of the already-issued
  device access token rather than an assumed assertion. The cleaned server marks
  the device inactive but does not rotate the user security stamp in that method;
  source review confirmed that the upstream API bearer validator does not consult
  `Device.Active` for an already-issued JWT. This is therefore a concrete
  foundation behavior gap rather than a test ambiguity.
- Added CI job `foundation-server-behavior`, dependent on the cleaned server build
  proof, to compile and execute this Safeory-owned harness on Linux and re-run the
  restricted dependency boundary afterward.
- GitHub Actions run `35554744189` completed both `foundation-server-proof` and
  `foundation-server-behavior` successfully. The passing behavior scenario closes
  the account A/account B, two-device login, login CRUD/restore, TOTP storage,
  same-account cross-device sync, account-isolation, and device-deactivation gates
  above. The stronger post-revocation authenticated-operation gate remains open
  until the completed workflow log exposes the probe result.
- Added a separate Safeory-owned Rust SDK behavior harness under
  `tests/foundation/sdk-behavior/`. Against the cleaned pinned SDK it proves public
  cipher encrypt/decrypt, deterministic TOTP generation, decrypted JSON export,
  attachment buffer encryption/decryption using a cipher key, retained password-
  manager import behavior, and encrypted FIDO2/passkey material handling.
- The SDK harness copies the cleaned SDK lockfile, normalizes only reachability via
  offline Cargo metadata, then rejects any resolved package identity absent from
  the pinned SDK lock before tests run with `--locked`. This prevents the harness
  from silently selecting newer registry dependencies. The harness is wired into
  `foundation-sdk-proof` before the release WASM build.
- The harness also imports the retained representative 1Password CXF export through
  the public `ExporterClient::import_cxf` API, decrypts the resulting SDK ciphers,
  and verifies representative login, card, Wi-Fi, custom-field, and note data. The
  Safeory SDK behavior harness also unwraps the account objects from the retained
  standard FIDO Credential Exchange Format header sample and passes each account
  unchanged through the same public SDK importer, verifying a login, origin, and
  SHA-256 TOTP mapping. A separate retained Dashlane CXF export verifies login,
  TOTP, and card mappings from another password manager. The five password-manager
  foundation tests pass locally against the cleaned pinned SDK. This closes the
  1Password fixture gate without adopting any
  Bitwarden frontend/import UI, and closes the representative standard password-
  manager fixture gate on the interoperable CXF boundary.
- Added a separate Safeory server adapter proof layer rather than modifying the
  pure cleaned-OSS proof. `prepare-safeory-server-adapter-proof.mjs` adds a JWT
  `OnTokenValidated` guard for device-bound user tokens: it resolves the token's
  signed `sub` + `device` claims through `IDeviceRepository` and rejects the token
  when that exact device is missing or inactive. Tokens with no device claim are
  left unchanged, preserving service-account/organization/internal token flows.
  `check-safeory-server-adapter-proof.mjs` fails closed if the guard disappears.
- The server behavior fixture now requires selective revocation: after device A2
  is deactivated, its already-issued access token must receive HTTP 401 on `/sync`
  while device A1 for the same account must continue to succeed. The revocation
  checkbox remains open until this adapted path passes Linux CI.
- Linux run `35556222545` exposed two proof-environment/adapter defects. The
  cleaned SDK release build reached Binaryen but Ubuntu's packaged `wasm2js`
  aborted on an internal assertion; Bitwarden's own WASM workflow installs
  Binaryen from npm, so Safeory CI now follows that upstream toolchain path and
  records `wasm-opt`/`wasm2js` versions before the release build.
- The same run reached the real local attachment upload and returned HTTP 500.
  Source inspection showed `LocalAttachmentStorageService` unconditionally seeks
  multipart streams even though ASP.NET multipart section bodies can be
  non-seekable. The Safeory server adapter now guards both local upload seek sites
  with `stream.CanSeek`, preserving rewind behavior for seekable streams while
  accepting normal forward-only HTTP bodies. The adapter checker requires both
  guards, and the behavior test now includes the upload response body in failures.
- Linux run `35559452762` proved that storage-side fix was necessary but not
  sufficient: `PostAttachmentV1` first accessed `Request.Form` to obtain
  `lastKnownRevisionDate`, consuming the multipart request body before
  `MultipartReader` parsed the file and causing `Unexpected end of Stream`. The
  Safeory server adapter now enables request buffering and rewinds the body at both
  attachment endpoints after form/revision parsing. The checker requires exactly
  two buffering + rewind guards. Attachment lifecycle and selective-revocation
  gates remain open until this revised adapter passes Linux behavior CI.
- Added a real Chromium MV3 integration proof with Playwright 1.63.0. The test
  launches the production-built Safeory extension in a persistent Chromium
  context, creates the vault through the actual popup, captures a new login from a
  live HTTP page, updates that credential through the content/background CAS path,
  autofills the updated password on the matching origin, then navigates to a
  second localhost port and verifies that no credential is offered or filled.
- The first real-browser run exposed a packaging defect rather than an autofill
  defect: wasm-bindgen's default initializer fetched `vault_wasm_bg.wasm`, but the
  extension build did not copy that binary into `dist/`. The extension packaging
  step now copies the generated WASM beside `background.js`, and background init
  resolves it explicitly through `chrome.runtime.getURL("vault_wasm_bg.wasm")`.
  After that fix the Chromium behavior proof passes end to end locally. The main
  `quality` CI job now installs Playwright Chromium and runs the same proof after
  the production frontend build.
- Firefox required one additional production packaging change: Firefox MV3 still
  uses `background.scripts` while Chromium uses `background.service_worker`, so
  the shared manifest now declares both background forms and includes a stable
  Gecko extension ID. FirefoxDriver installs the unsigned production build as a
  temporary add-on, launches the Playwright-managed Firefox binary, and uses a
  fixed test-profile WebExtension UUID only to address the real popup page.
- The Firefox behavior proof then repeats the same product flow as Chromium:
  actual popup vault creation, page-driven credential capture, CAS update,
  autofill of the updated password on the exact origin, and no offered/filled
  credential on a second localhost port. It passes locally with
  `selenium-webdriver` 4.49.0. The main `quality` job now installs both Playwright
  Chromium and Firefox and executes both extension behavior proofs.
- Passkey coverage now spans both relevant retained boundaries. The Safeory SDK
  behavior harness enables the coherent `bitwarden-pm/wasm` feature bundle, uses
  Bitwarden's own valid PKCS#8 P-256 test key, attaches a discoverable FIDO2
  credential to a real per-cipher encrypted login, verifies that credential ID and
  private-key material are ciphertext in `LoginView`, then explicitly decrypts
  the FIDO metadata and private key through public vault APIs. The locked/subset
  guard remains intact at 469 pinned SDK packages and the harness passes 5/5 tests
  locally.
- The Chromium behavior proof also provisions a CDP virtual CTAP2 platform
  authenticator with resident-key and user-verification support, creates a real
  WebAuthn P-256 resident credential on a trustworthy localhost origin, and
  verifies the browser authenticator retained exactly one resident credential for
  that relying party. Browser automation therefore proves creation while the SDK
  proof proves encrypted password-manager storage/recovery; no Bitwarden frontend
  passkey provider code is imported.

**Exit gate:** Safeory can rely on the adapted backend/core password-manager
foundation without adopting Bitwarden's frontend.

## 0.5 Prove the Safeory life-record carrier through foundation sync

Use the existing `SafeoryEnvelopeV1` fixture:

- [x] Choose the least-invasive foundation encrypted-record carrier.
- [ ] Persist one representative insurance/life record.
- [x] Render it through one temporary Safeory client route.
- [ ] Edit and revision-sync it.
- [ ] Attach/download/rename/delete a file.
- [ ] Trash and restore the record.
- [ ] Export it.
- [ ] Import it.
- [ ] Sync it to another device.
- [ ] Confirm unknown Safeory extension data survives losslessly.
- [ ] Test corrupted marker/version/identity/JSON/size/attachment boundaries.
- [ ] Prove an older/non-Safeory-compatible client cannot silently rewrite away
      mandatory Safeory data.

Phase 0.5 implementation evidence (2026-09-21):

- Selected an individual-vault blob-encrypted `SecureNote` as the least-invasive
  foundation carrier. The serialized `SafeoryEnvelopeV1` remains ordinary
  Safeory-owned plaintext only inside the SDK `CipherView.notes`; the foundation
  SDK seals the entire secure-note payload into opaque cipher `Data`, so Safeory
  does not introduce a parallel generic sync protocol or a new server record type.
- Legacy field-level `Notes` was rejected as the carrier because the server caps
  that encrypted field at 10,000 characters, below Safeory's 256 KiB envelope
  contract. Blob cipher `Data` is server-opaque and accepts up to 500,000
  characters, leaving sufficient room for the sealed 256 KiB envelope plus crypto
  overhead.
- The pinned SDK already contains versioned blob sealing/unsealing and a security-
  state selection predicate, but those helpers were not wired into the public
  cipher client. It also serialized the sealed outer container as base64-CBOR,
  while the pinned server recognizes the same logical fields only in a JSON object
  with top-level `format_version`, `wrapped_cek`, and `envelope`.
- Added a separate Safeory SDK adapter proof rather than changing the pure cleaned-
  OSS preparation. New blob writes are intentionally limited to qualifying
  individual-vault `SecureNote` records, which is the selected Safeory carrier;
  password-manager Login/Card/Identity/etc. writes remain on the inherited
  field-level path. Blob reads remain generic for compatibility. The adapter wires
  public encrypt/decrypt, create/edit, sync/details parsing, repository-backed
  get/get-all/list, and list/search projection to the existing blob implementation,
  writes the existing sealed container as the server-compatible JSON shape, and
  retains read compatibility for the SDK's earlier base64-CBOR representation.
  Organization ciphers remain on the inherited path.
- Server blob responses intentionally omit obsolete legacy fields such as `name`,
  `notes`, and `secureNote`. The adapted SDK now accepts a missing legacy name only
  when `Data` parses as a valid sealed blob; ordinary responses still fail closed.
  List/search projection decrypts the blob directly into a SecureNote list view
  rather than touching that obsolete encrypted-name slot.
- The adapted SDK behavior harness now passes 7/7 tests locally. Its carrier test
  serializes a representative insurance envelope above 230 KiB but within the
  256 KiB Safeory limit, verifies public encryption produces JSON blob `Data`
  below the server's 500,000-character limit with no legacy notes/type payload,
  decrypts it through both single and full-list public APIs, and confirms unknown
  future extension data survives byte-for-byte at the JSON-value level.
- A second carrier transport test converts the encrypted carrier into the actual
  API request model and verifies opaque `data` is present while legacy
  `notes`/`secureNote` are absent. It then simulates the full server/sync response
  shape with `data` + key + metadata but no legacy name/type payload, converts that
  response back into SDK state, and proves both full decrypt and list/search
  projection recover `Safeory insurance record`. The adapted `bitwarden-vault`
  crate also passes native and `wasm`-feature checks.
- Added a paired server downgrade invariant for the normal personal-vault PUT
  path: once an item is blob-encrypted, an incoming legacy field-level replacement
  is rejected before the stored cipher is mutated. The Linux behavior harness now
  creates a blob secure note, observes it unchanged on a second device, performs a
  revision-fenced blob update, attempts a current-revision legacy overwrite and
  requires HTTP 400, then verifies the opaque blob remains intact. This downgrade
  gate remains unchecked above until the new Linux CI run passes.
- Extracted the representative insurance `SafeoryEnvelopeV1` into a shared product-
  domain fixture consumed by both the strict validator tests and the temporary
  Safeory client route at `/foundation-envelope-proof`. The route is a static Next
  16 Server Component, validates marker/version/outer record identity before
  rendering, and uses only Safeory-owned UI plus the approved Hugeicons library.
  It renders insurance fields, the envelope reminder/relationship binding,
  continuity disposition, and preserved future-extension metadata without
  touching vault runtime state or importing any Bitwarden frontend code.
- Web typecheck and lint pass, all 9 product-domain envelope tests still pass after
  the shared-fixture extraction, and the production static export successfully
  prerenders `/foundation-envelope-proof` with the representative insurance
  record. This closes the temporary-client-route gate independently of the pending
  Linux server persistence proof.

**Exit gate:** Safeory structured records round-trip over foundation transport
without creating a parallel generic sync protocol.

## 0.6 Prove independently keyed Safeory Spaces

Create:

- Alice personal Space;
- Alice+Bob Family Space;
- Alice+Carol Advisor Space;
- Alice-only Travel Space;
- enough additional spaces to reach at least 32.

Prove:

- [ ] Each Space uses a real independent key/sharing boundary.
- [ ] Collection/folder/tag/group membership alone never defines isolation.
- [ ] Bob cannot decrypt Advisor Space ciphertext.
- [ ] Carol cannot decrypt Family Space ciphertext.
- [ ] Ciphertext copied between Space contexts fails authentication/decryption.
- [ ] Removing Bob stops future Family Space key/data delivery.
- [ ] Family Space rotation protects future writes.
- [ ] Moving an item between Spaces rewraps correctly.
- [ ] Personal Space remains inaccessible to Household organizer role alone.
- [ ] 32 Spaces stay within agreed unlock/sync/memory/navigation budgets.
- [ ] If the inherited organization model cannot satisfy this safely or
      efficiently, implement the smallest reviewed client/core key-domain
      extension instead of weakening isolation.

**Exit gate:** Safeory Space isolation is cryptographically demonstrated, not
inferred from UI permissions.

## 0.7 Prove the continuity crypto seam

- [ ] Add a disposable selected-key operation in the cleaned foundation core.
- [ ] Seal one record key to a trustee-device public key.
- [ ] Seal one Space key to a trustee-device public key.
- [ ] Open the capsule on a separate trustee device/context.
- [ ] Ensure raw account/user/Space/record keys never appear in ordinary JS,
      browser storage, logs, or network traffic.
- [ ] Run the existing Safeory timed-release state machine using only opaque
      capsule references.
- [ ] Measure the security-sensitive patch surface that must be maintained.

**Exit gate:** selected continuity release is possible without a whole-vault
backdoor or JavaScript raw-key export.

## 0.8 Phase 0 final gate

Phase 0 is complete only when:

- [ ] disposable clients reference proof is complete and no Bitwarden frontend
      is selected for permanent import;
- [ ] cleaned SDK build passes;
- [ ] cleaned server build passes;
- [ ] cleaned dependency/provenance checks pass;
- [ ] Safeory-owned password-manager integration/e2e harness passes against the
      cleaned server/SDK foundation;
- [ ] Safeory envelope round-trip passes;
- [ ] 32-Space isolation/rotation test passes;
- [ ] selected-key continuity spike passes;
- [ ] legal/provenance review has no blocking issue.

---

# PHASE 1 — Import and establish the Safeory-owned foundation

Start only after Phase 0 passes.

## 1.1 Import source

- [ ] Import cleaned SDK into `foundation/sdk`.
- [ ] Import cleaned server into `foundation/server`.
- [ ] Do **not** import Bitwarden web/frontend/browser application trees.
- [ ] If Phase 0 selected any client-side non-UI implementation, port only that
      smallest reviewed subset into a clearly isolated Safeory-owned module with
      provenance and dedicated compatibility tests; do not vendor the surrounding
      Bitwarden client application.
- [ ] Preserve required upstream copyright/license notices.
- [ ] Update provenance with final imported commit/tree hashes.
- [ ] Ensure no nested upstream `.git` directories remain unless deliberately
      retained for a documented history-import strategy.
- [ ] Keep the import in reviewable commits: raw import, restricted-code
      removal, Safeory adaptation.

## 1.2 Establish the cleaned foundation build/test baseline

- [ ] Add foundation workspaces/build entry points without breaking legacy
      verification.
- [ ] Add CI for the cleaned SDK, cleaned server, PostgreSQL migrations, and the
      Safeory-owned web/Chromium/Firefox clients that consume the foundation.
- [ ] Preserve applicable upstream security tests.
- [ ] Replace deleted/commercial upstream tests only with equal or stronger
      Safeory tests.
- [ ] Remove MySQL/SQLite/runtime/database-provider surfaces that Safeory does not
      support after the PostgreSQL path and migrations are proven equivalent for
      all retained behavior.
- [ ] Remove enterprise/business server surfaces Safeory does not need, including
      unused Admin Console, enterprise billing, SSO/SCIM/PAM/Secrets Manager and
      organization/business-only behavior, using compile/test-driven deletion
      rather than blind directory removal.
- [ ] After every upstream-code removal, run the retained upstream tests plus
      Safeory compatibility/security tests before considering the deletion safe.
- [ ] Add secret scanning, dependency audit, source/license checks, SBOM and
      artifact provenance.

## 1.3 Adapt the retained backend/core to Safeory

- [ ] Remove Bitwarden-hosted service assumptions from retained server/SDK/core
      paths.
- [ ] Remove upstream analytics/telemetry/update behavior not required by Safeory.
- [ ] Remove commercial plan/license behavior from retained backend/core paths.
- [ ] Remove unused CLI/enterprise surfaces unless a concrete Safeory feature
      requires the underlying non-UI primitive.
- [ ] Adapt account/session/device/auth flows to Safeory-owned client contracts.
- [ ] Adapt vault/sync/revision/attachment/import/export behavior to Safeory-owned
      web and extension clients without exposing raw keys to ordinary UI JS.
- [ ] Adapt password-manager crypto and protocol APIs behind stable Safeory
      interfaces so upstream details do not leak throughout the product codebase.
- [ ] Keep the security-sensitive patch surface small and measured.
- [ ] Document retained upstream boundaries in provenance rather than copying
      Bitwarden product UI or branding.

## 1.4 Establish the Safeory-owned password-manager client shell

- [ ] Keep/extend the existing Safeory design system and navigation rather than
      importing/rebranding Bitwarden frontend code.
- [ ] Implement Safeory-owned account/login/unlock/password-manager surfaces
      against the adapted SDK/server APIs.
- [ ] Implement Safeory-owned credential list/detail/edit flows.
- [ ] Implement Safeory-owned generator, TOTP, passkey, import/export, attachment,
      trash/history, device/session, capture, and autofill UX required for the
      consumer password-manager baseline.
- [ ] Keep browser-extension UI and product behavior Safeory-owned in Chromium
      and Firefox.
- [ ] Keep inherited password-manager internals behind Safeory interfaces so
      upstream organization/business terminology does not leak into consumer UX.

## 1.5 Foundation Adaptation & Stability Gate — mandatory before feature expansion

Do not begin Phase 2 or later product-feature expansion merely because the
Bitwarden code compiles. The imported foundation is considered **fully adapted
and stable** only after all of the following pass together on the actual Safeory
architecture:

- [ ] Clean SDK/server builds pass from a fresh checkout on supported developer
      platforms and Linux CI.
- [ ] Safeory web build passes against the adapted foundation.
- [ ] Safeory Chromium extension build passes.
- [ ] Safeory Firefox extension build passes.
- [ ] All retained applicable upstream unit/security/integration tests pass, with
      environment-dependent suites backed by the required real services.
- [ ] PostgreSQL schema/migration tests pass against a real PostgreSQL instance.
- [ ] Safeory unit, contract, browser, API, crypto, storage, sync, and negative
      security regression suites pass.
- [ ] Two-device end-to-end tests cover account creation/login, unlock, credential
      create/edit/delete/restore, TOTP, passkeys where automatable, encrypted
      attachments, revisions/sync, import/export, offline/reconnect, and
      device/session revocation.
- [ ] Safeory-owned Chromium and Firefox tests cover capture/update/autofill with
      strict origin/sender boundaries and no Bitwarden frontend dependency.
- [ ] Fresh install, upgrade, restart, lock/unlock, corruption/failure, retry,
      rollback, and recovery paths relevant to the retained foundation pass.
- [ ] Restricted/commercial source and dependencies remain absent.
- [ ] Removed enterprise/database/client surfaces do not reappear through
      transitive build or runtime dependencies.
- [ ] Secret scanning, dependency audits, SBOM, notices, license inventory, and
      artifact provenance pass.
- [ ] Security review confirms no usable vault/content key reaches server-side
      services or ordinary UI JavaScript and that zero-knowledge invariants were
      not weakened during adaptation.
- [ ] Compatibility tests prove Safeory can safely maintain/update the retained
      upstream server/SDK boundary without relying on undocumented UI coupling.
- [ ] Soak/load/reconnect testing shows no known foundation-level data-loss,
      sync, session, attachment, or key-management blocker.
- [ ] The adapted foundation has a recorded stable baseline commit before Phase 2
      feature work begins.

**Phase 1 exit:** a reproducible, Safeory-owned client product runs on the
cleaned/adapted Bitwarden server + Rust SDK/core foundation, the full adaptation
and stability gate is green, and no Bitwarden frontend is part of the product.
Only after this point should the main Trustworthy-style household/life-vault and
continuity feature expansion proceed.

---

# PHASE 2 — Safeory life vault on the foundation

Start only after **Phase 1.5 Foundation Adaptation & Stability Gate** is fully
green. Phase 2 assumes the Bitwarden-derived backend/core has already been
cleaned, adapted, integrated with Safeory-owned clients, and proven stable.

## 2.1 Finalize the Safeory life envelope

- [ ] Finalize V1 marker/version format.
- [ ] Finalize maximum serialized size.
- [ ] Finalize unknown-extension preservation rules.
- [ ] Finalize outer-record/inner-record identity binding.
- [ ] Finalize reminder representation.
- [ ] Finalize relationships/links representation.
- [ ] Finalize continuity-intent representation.
- [ ] Add Rust/core implementation or binding if required so validation does
      not live only in JS.
- [ ] Add fuzz/property/boundary tests.

## 2.2 Port existing Safeory record types

Port and test:

- [ ] documents;
- [ ] secure/general notes that are not better represented as foundation secure
      notes;
- [ ] insurance;
- [ ] financial records;
- [ ] property;
- [ ] vehicles;
- [ ] possessions;
- [ ] receipts;
- [ ] subscriptions;
- [ ] important contacts/relationships;
- [ ] emergency information.

Use foundation-native credential/card/identity/note types where they are a better
fit. Do not duplicate foundation record types simply to preserve the legacy
schema.

## 2.3 Port Safeory product behavior

- [ ] Port masking/reveal behavior.
- [ ] Port schema-driven editing patterns worth retaining.
- [ ] Port links/relationships.
- [ ] Port deadlines.
- [ ] Port Today calculations.
- [ ] Port trash/restore expectations.
- [ ] Port encrypted attachment UX on top of foundation attachment machinery.
- [ ] Port readable export for Safeory records.
- [ ] Port encrypted backup/migration support where still required.

## 2.4 Files and Inbox

- [ ] Build Files using foundation attachments/items.
- [ ] Build folders/filing UX without treating folders as cryptographic
      boundaries.
- [ ] Implement local/private extraction pipeline.
- [ ] Send extracted suggestions into encrypted Inbox review.
- [ ] Require explicit user promotion before durable record changes.
- [ ] Keep ordinary SMTP forwarding outside the zero-knowledge default.

**Phase 2 exit:** the primary current Safeory life-vault record set works on the
foundation with native sync/attachments/revisions/export behavior.

---

# PHASE 3 — Household, Spaces, and collaboration

## 3.1 Household

- [ ] Implement Household creation.
- [ ] Implement consumer household roles.
- [ ] Keep administrative role separate from decryption authority.
- [ ] Implement member invitation.
- [ ] Implement member removal.
- [ ] Implement device-aware membership/revocation behavior.
- [ ] Add minimal encrypted household activity UX.

## 3.2 Spaces

- [ ] Personal Space.
- [ ] Family Space.
- [ ] Advisor Space.
- [ ] Travel Space.
- [ ] Estate/purpose custom Spaces.
- [ ] Space creation.
- [ ] Space membership.
- [ ] Space rotation.
- [ ] Item move between Spaces.
- [ ] Space deletion/retirement semantics.
- [ ] Negative cross-Space isolation tests.

## 3.3 Collaboration

- [ ] Shared record editing.
- [ ] Shared files.
- [ ] Shared reminders where intended.
- [ ] Conflict behavior for concurrent changes.
- [ ] Member/device revoke behavior.
- [ ] SecureLink-style encrypted immutable external share.
- [ ] Expiry.
- [ ] Revocation.
- [ ] Rate limiting.
- [ ] Audience binding where selected.
- [ ] Explicit warning that recipients can copy plaintext they legitimately
      receive.

**Phase 3 exit:** household members can safely collaborate across independently
encrypted Spaces with tested revocation/rotation boundaries.

---

# PHASE 4 — Migrate the current Safeory implementation

Migration remains local/client-side.

## 4.1 Build migrator

- [ ] Open/authenticate a legacy Safeory vault locally.
- [ ] Produce dry-run inventory.
- [ ] Assign deterministic migration IDs.
- [ ] Map credentials to foundation-native records.
- [ ] Map life records to Safeory envelopes.
- [ ] Map attachments to foundation-native attachment APIs.
- [ ] Map relationships/reminders.
- [ ] Map Emergency Card.
- [ ] Map trusted-person and continuity intent that remains valid.
- [ ] Preserve supported recovery/export material.
- [ ] Upload only already-encrypted foundation data.
- [ ] Read back and authenticate every migrated record/attachment.
- [ ] Produce encrypted migration report.
- [ ] Preserve encrypted legacy backup.
- [ ] Support interruption/resume.
- [ ] Support idempotent retry.
- [ ] Support rollback.
- [ ] Never automatically delete the source vault.

## 4.2 Migration test matrix

- [ ] Empty vault.
- [ ] Small vault.
- [ ] Large vault.
- [ ] Every supported record kind.
- [ ] Large attachments.
- [ ] Trash/history where representable.
- [ ] Emergency Card.
- [ ] Trusted people.
- [ ] Legacy disposition.
- [ ] Corrupt legacy record.
- [ ] Interrupted migration.
- [ ] Repeated migration.
- [ ] Foundation write failure.
- [ ] Foundation read-back mismatch.
- [ ] Rollback.

**Phase 4 exit:** representative legacy vaults migrate locally, verify after
read-back, and remain safely recoverable.

---

# PHASE 5 — Finish consumer password-manager parity gaps

Do not rewrite mature backend/core password-manager capabilities that are already
inherited, adapted, and proven through the Phase 1 stability gate. Safeory still
owns the complete customer-facing UX. This phase is for Safeory integration and
consumer password-manager behavior gaps only, not adoption of Bitwarden UI.

- [ ] Confirm multi-origin login UX.
- [ ] Confirm TOTP UX.
- [ ] Confirm passkey UX.
- [ ] Confirm generator UX.
- [ ] Confirm password health/security-reporting UX that is available without
      restricted upstream code; build a clean Safeory replacement where needed.
- [ ] Confirm save/update capture.
- [ ] Confirm identity/form-fill behavior.
- [ ] Confirm standard imports.
- [ ] Confirm 1Password import path.
- [ ] Confirm Chromium.
- [ ] Confirm Firefox.
- [ ] Confirm attachment handling.
- [ ] Confirm device/session inventory and remote revoke.
- [ ] Confirm offline/reconnect behavior.
- [ ] Confirm export and deletion behavior.
- [ ] Add explicit compatibility tests around every Safeory modification to
      foundation autofill/passkey/key-management boundaries.

**Phase 5 exit:** Safeory does not regress the inherited consumer password-manager
baseline while adding Safeory features.

---

# PHASE 6 — Household operating features

- [ ] Family records.
- [ ] Medical records.
- [ ] Tax records.
- [ ] Legal records.
- [ ] Business/important organization records needed by consumer households.
- [ ] Contacts/connections.
- [ ] Rich Files organization.
- [ ] Recurring reminders.
- [ ] Reminder completion/reschedule.
- [ ] Private-local reminder mode.
- [ ] Opt-in cloud wake mode using minimum server-visible metadata.
- [ ] Generic notification copy with no sensitive record content.
- [ ] Household activity surface.
- [ ] Browser capture into Inbox/life records where appropriate.
- [ ] Local OCR/document extraction.
- [ ] Review-before-save workflow.
- [ ] Search across decrypted authorized local data only.

**Phase 6 exit:** Safeory functions as a practical household life organizer, not
only a password manager with extra record types.

---

# PHASE 7 — Trust Engine and continuity

Reuse the existing tested legacy policy/state-machine behavior where it remains
sound, but integrate it with the new foundation rather than the old generic
sync/device architecture.

## 7.1 Trusted people/devices

- [ ] Trustee relationship creation.
- [ ] Trustee device binding.
- [ ] Explicit proof-of-possession.
- [ ] Device rotation/removal.
- [ ] Retired signing/encryption identity handling.
- [ ] Clear UX that device-key possession is not proof of a person's real-world
      identity.

## 7.2 Release policies

- [ ] Selected records/Spaces only.
- [ ] Waiting periods.
- [ ] Approval thresholds.
- [ ] Owner notification.
- [ ] Deny.
- [ ] Revoke.
- [ ] Expiry.
- [ ] Exact policy/revision fencing.
- [ ] Idempotency.
- [ ] Clock/rollback protection where relevant.
- [ ] Tamper-evident minimal security events.

## 7.3 Release delivery

- [ ] Seal selected keys only.
- [ ] Store only opaque capsules server-side.
- [ ] Deliver only after policy eligibility.
- [ ] Open only on authorized trustee client.
- [ ] Prove server cannot decrypt.
- [ ] Prove whole-vault key is never released.
- [ ] Prove unrelated Space/record keys are not released.

## 7.4 Product flows

- [ ] Emergency Card.
- [ ] "If something happens to me" workflow.
- [ ] Selected legacy access.
- [ ] Private-forever intent.
- [ ] Destroy-on-death intent with honest backup/deletion limitations.
- [ ] Trustee portal.
- [ ] Plan Test.
- [ ] Plan Test simulation must never create a live release.
- [ ] Readiness/preparedness UX.

**Phase 7 exit:** reviewed multi-device e2e tests prove selected release without
server decryption, whole-vault over-release, or waiting-policy bypass.

---

# PHASE 8 — Travel Mode and production platform

## 8.1 Travel Mode

- [ ] Select travel-safe Spaces.
- [ ] Remove non-travel Space key material from participating device.
- [ ] Remove relevant cached local ciphertext where feasible.
- [ ] Prove hidden-only implementation is rejected.
- [ ] Restore through authenticated synchronization/re-enrollment.
- [ ] Document browser/OS backup limitations honestly.

## 8.2 Production services

Implement production infrastructure according to the approved AWS baseline in
`infra.md`. If a measured requirement later changes a selected service or
scaling strategy, update `infra.md` in the same change so infrastructure does not
drift into undocumented architecture.

- [ ] Run cleaned foundation server under Safeory ownership.
- [ ] Use PostgreSQL for foundation durable storage.
- [ ] Implement Safeory Coordinator as a separate service.
- [ ] Give Coordinator a separate PostgreSQL role/schema or database.
- [ ] Use Valkey only for ephemeral work/rate limits/deduplication.
- [ ] Use S3 for encrypted foundation attachments/blobs.
- [ ] Use SES for account/security/generic workflow notifications.
- [ ] Use CloudFront + Route 53 + ACM for edge/DNS/TLS.
- [ ] Use ECR for service images.
- [ ] Use IAM/SSM/Secrets Manager for service secrets.
- [ ] Add CloudWatch/CloudTrail logging/audit.
- [ ] Disable request-body/secret logging.
- [ ] Do not introduce Cognito as a second account identity plane.

## 8.3 Foundation-to-Coordinator auth

- [ ] Short-lived assertion.
- [ ] Audience-bound.
- [ ] Account-bound.
- [ ] Device/session-bound.
- [ ] Scoped.
- [ ] Non-refreshable at Coordinator.
- [ ] Reject after foundation session/device revoke.
- [ ] Prevent confused-deputy/caller-supplied-ID escalation.

## 8.4 Backup and recovery

- [ ] PostgreSQL backup/restore.
- [ ] S3 versioning/recovery policy.
- [ ] Coordinator-state recovery.
- [ ] Foundation-state recovery.
- [ ] Migration rollback drill.
- [ ] Region-loss drill.
- [ ] Key-rotation drill.
- [ ] Incident response runbook encoded in operational automation/checklists.

**Phase 8 exit:** production-equivalent deployment passes security, backup,
restore, revocation, and failure drills.

---

# PHASE 9 — Security hardening and launch

- [ ] Full dependency/security audit.
- [ ] SBOM and notices for every release.
- [ ] Secret scanning.
- [ ] SAST.
- [ ] Artifact signing/provenance.
- [ ] External review of modified foundation cryptography.
- [ ] External review of Safeory Space mapping/key rotation.
- [ ] External review of selected-key continuity capsules.
- [ ] External review of browser-extension origin/sender boundary.
- [ ] External review of migration code.
- [ ] External review of Trust Engine release state machine.
- [ ] Large-vault load/soak.
- [ ] Many-Space load/soak.
- [ ] Large-attachment tests.
- [ ] Multi-device stress/reconnect tests.
- [ ] Malicious/corrupt import tests.
- [ ] Metadata-leakage review.
- [ ] Support/privacy/security wording review against shipped behavior.
- [ ] Final source/license publication requirements satisfied.
- [ ] Final release-candidate regression pass covers the complete Safeory-owned
      frontend plus adapted Bitwarden server/Rust-core foundation as one product.
- [ ] Final end-to-end acceptance suite proves the combined product delivers the
      intended Trustworthy-style household/life organization and continuity
      workflows together with the intended 1Password-style consumer password
      manager baseline without weakening zero knowledge.
- [ ] No release blocker remains in password-manager core, household/life-vault,
      Spaces, migration, Trust Engine, Emergency/continuity, browser extension,
      backup/recovery, or production operations.

After Phase 9 passes and the final implementation is frozen, create the final
architecture/security documentation from the actual code and verified behavior.
Only then should Safeory be considered the fully adapted, tested, stable release
candidate for the combined product.

---

# Legacy implementation: retain until cutover

The following existing work remains valuable as migration/test/reference code:

- Safeory record schemas and product behavior;
- masking/reveal behavior;
- deadline/Today logic;
- encrypted Files/attachments UX;
- recovery behavior;
- Emergency Card;
- legacy/private-forever/destruction planning metadata;
- `vault-emergency` policy/timed-release logic;
- selected `vault-sharing` recipient-capsule and pairing concepts;
- strict parsing/resource bounds;
- security-negative tests;
- browser origin/sender/one-shot-fill tests;
- existing export/backup fixtures.

The following old platform components should eventually be removed only after
replacement + migration + rollback tests pass:

- custom account/root bootstrap;
- custom generic device credential handoff;
- custom generic opaque-object sync;
- old browser credential stores;
- bespoke generic autofill/capture implementation;
- generic password-manager record machinery superseded by the foundation;
- generic Rust API routes superseded by the foundation server.

---

# Security invariants that must survive every phase

- Zero knowledge by default.
- No usable vault key on the server.
- No plaintext vault body/attachment on the server.
- Server-visible metadata minimized to what is operationally required.
- Human-readable Household/Space names should remain encrypted where possible;
  use opaque routing identifiers where a foundation/server name is required.
- Private Space keys never follow Household organizer/admin role alone.
- Safeory Space isolation is cryptographic.
- Member/device removal affects future delivery, not already copied plaintext.
- Travel Mode removes key/ciphertext residency rather than merely hiding UI.
- Remote OCR/AI is not silently enabled; any future disclosure mode needs
  explicit user consent and separate review.
- Plaintext SMTP ingestion is not zero knowledge.
- Device signatures prove possession of a device key, not human identity,
  intent, capacity, or survival status.
- Emergency/continuity controls cannot perfectly establish death/incapacity;
  waiting, approvals, alerts, dispute/deny/revoke behavior must remain honest.
- Recovery must not create a company-side decryption backdoor.
- Do not add advisory ignores merely to make CI green.
- New security-sensitive dependencies require explicit review.

---

# Verification gates

Keep the existing Safeory regression suite green during the transition:

```text
bun install --frozen-lockfile
bun run check:foundation
bun run test:product-domain
bun run typecheck
bun run test:browser
bun run lint
bun run check:icons
bun run build
bun run audit:js

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo deny check advisories bans licenses sources

docker compose config --quiet
```

As foundation code enters the repository, add equivalent cleaned-foundation
build/test commands to CI. Do not remove legacy gates until the corresponding
legacy component has been migrated and retired.

---

# Agent operating rules

When continuing development:

1. Read this entire file.
2. Inspect `git status`; preserve unrelated/uncommitted work.
3. Start at the first incomplete task in the earliest active phase.
4. Do a substantial coherent slice rather than a tiny documentation-only change.
5. Prefer implementation + tests + validation over additional planning.
6. Do not redo completed research unless new evidence invalidates it.
7. Do not create new planning/architecture/security docs during development.
   `infra.md` is the explicitly approved infrastructure baseline and operational
   exception; keep it current when infrastructure decisions materially change.
8. Update checkboxes/status in this file when work materially completes.
9. Keep machine-readable provenance current when foundation pins/imports change.
10. Never delete legacy behavior until replacement, migration, read-back, and
    rollback tests prove it safe.
11. Run the relevant verification gates before stopping.
12. Report concrete blockers and continue with the next safe task instead of
    stopping after small preparatory work.
13. Never bypass Phase 1.5: feature expansion must not proceed on an imported but
    unadapted or partially tested Bitwarden foundation.
14. Never import or rebrand Bitwarden frontend applications. Safeory frontend
    and browser UX remain Safeory-owned throughout development.

---

# Immediate next work

The next agent should continue **Phase 0.1: Prove the Bitwarden clients reference
without adopting its frontend**, then move through the cleaned server/Rust SDK
proof and Foundation Adaptation & Stability Gate in order.

Do not continue the old Safeory generic sync/device-enrollment backlog.
Do not import Bitwarden web/browser frontend applications.

The next material milestone is:

> Clean and adapt the Bitwarden server + Rust SDK/core behind Safeory-owned web
> and browser clients; selectively port only reviewed non-UI client logic where
> necessary; then pass the complete Foundation Adaptation & Stability Gate before
> starting the main household/life-vault/continuity feature expansion.
