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

Safeory has selected **Bitwarden OSS as the password-manager foundation**.

Development should no longer spend time rebuilding generic password-manager
features already provided by that foundation.

Primary engineering focus from now on:

1. finish the OSS-clean Bitwarden import and prove it end to end;
2. integrate the foundation cleanly into the Safeory repository;
3. port Safeory's existing useful life-vault/domain work onto that foundation;
4. implement Household and independently encrypted Safeory Spaces;
5. migrate existing Safeory users/data safely;
6. add Safeory-specific household, continuity, Emergency, Trust Engine, and
   Plan Test features;
7. productionize, harden, externally review, and launch.

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
- Reuse Bitwarden OSS for accounts, sessions, devices, credentials, TOTP,
  passkeys, password-manager sync, revisions, attachments, imports/exports,
  trash/history, capture, autofill, and browser-extension fundamentals.
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

---

## Selected upstream baseline

Keep exact source provenance in `docs/provenance/foundation-seed.json`.

Current pinned foundation:

- Bitwarden clients canonical import baseline:
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

## 0.1 Produce an OSS-clean clients tree

- [ ] Create a fresh disposable copy of the pinned Bitwarden clients checkout.
- [ ] Physically remove the complete `bitwarden_license/` tree.
- [ ] Remove `@bitwarden/commercial-sdk-internal` from package manifests and
      lockfiles.
- [ ] Remove commercial-only project targets/configuration that references
      deleted source.
- [ ] Remove hosted Bitwarden endpoints/telemetry/update behavior from the proof
      build where required to make the OSS product self-contained.
- [ ] Run dependency search proving no restricted package/path remains.
- [ ] Install dependencies from a clean checkout.
- [ ] Build OSS web.
- [ ] Build Chromium MV3.
- [ ] Build Firefox.
- [ ] Run relevant client unit/integration tests.
- [ ] Record exact build commands/toolchain versions in this file if they differ
      from upstream defaults.

**Exit gate:** one disposable clean clients tree builds web + Chromium +
Firefox with no restricted source or package dependency.

## 0.2 Reproduce cleaned foundation on Linux CI

- [ ] Add CI jobs for cleaned client, SDK, and server build proof.
- [ ] Build the cleaned Rust/WASM SDK on Linux.
- [ ] Build the cleaned server composition on Linux.
- [ ] Build web/Chromium/Firefox on Linux.
- [ ] Run non-environment-dependent upstream test suites.
- [ ] Add Docker-backed integration services for the environment-dependent
      server tests that matter to Safeory.
- [ ] Ensure PostgreSQL migration tests run against a real PostgreSQL service.

**Exit gate:** all required cleaned foundation surfaces reproduce in clean CI.

## 0.3 Produce legal/provenance artifacts

- [ ] Generate SBOM for clients, SDK, and server.
- [ ] Generate license inventory.
- [ ] Generate required notices bundle.
- [ ] Record removed restricted paths/packages.
- [ ] Record all retained upstream source commits.
- [ ] Add a CI failure if restricted paths/dependencies reappear.
- [ ] Obtain qualified license review before public distribution.

**Exit gate:** provenance/SBOM/license/notices pipeline is reproducible and has no
known blocking licensing issue.

## 0.4 Prove inherited password-manager behavior

Create an automated self-hosted fixture using the cleaned foundation:

- [ ] Create account A.
- [ ] Create account B.
- [ ] Log in from two separate client/device contexts.
- [ ] Create/edit/delete/restore a login.
- [ ] Add TOTP.
- [ ] Add a passkey where browser automation permits it.
- [ ] Add/download/delete an attachment.
- [ ] Sync the same account across two devices.
- [ ] Import representative standard password-manager fixtures.
- [ ] Import a representative 1Password fixture.
- [ ] Capture a new login using the extension.
- [ ] Update an existing login using the extension.
- [ ] Autofill only the correct origin in Chromium.
- [ ] Autofill only the correct origin in Firefox.
- [ ] Revoke a session/device.
- [ ] Prove the revoked context stops receiving/using future authenticated
      operations.

**Exit gate:** Safeory can rely on the inherited password-manager platform rather
than reproducing those capabilities itself.

## 0.5 Prove the Safeory life-record carrier through foundation sync

Use the existing `SafeoryEnvelopeV1` fixture:

- [ ] Choose the least-invasive foundation encrypted-record carrier.
- [ ] Persist one representative insurance/life record.
- [ ] Render it through one temporary Safeory client route.
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

- [ ] cleaned web build passes;
- [ ] cleaned Chromium build passes;
- [ ] cleaned Firefox build passes;
- [ ] cleaned SDK build passes;
- [ ] cleaned server build passes;
- [ ] cleaned dependency/provenance checks pass;
- [ ] password-manager e2e fixture passes;
- [ ] Safeory envelope round-trip passes;
- [ ] 32-Space isolation/rotation test passes;
- [ ] selected-key continuity spike passes;
- [ ] legal/provenance review has no blocking issue.

---

# PHASE 1 — Import and establish the Safeory-owned foundation

Start only after Phase 0 passes.

## 1.1 Import source

- [ ] Import cleaned clients into `foundation/clients`.
- [ ] Import cleaned SDK into `foundation/sdk`.
- [ ] Import cleaned server into `foundation/server`.
- [ ] Preserve required upstream copyright/license notices.
- [ ] Update provenance with final imported commit/tree hashes.
- [ ] Ensure no nested upstream `.git` directories remain unless deliberately
      retained for a documented history-import strategy.
- [ ] Keep the import in reviewable commits: raw import, restricted-code
      removal, Safeory adaptation.

## 1.2 Establish build/test baseline

- [ ] Add foundation workspaces/build entry points without breaking legacy
      verification.
- [ ] Add CI for web, Chromium, Firefox, SDK, server, and PostgreSQL migrations.
- [ ] Preserve applicable upstream security tests.
- [ ] Replace deleted/commercial upstream tests only with equal or stronger
      Safeory tests.
- [ ] Add secret scanning, dependency audit, source/license checks, SBOM and
      artifact provenance.

## 1.3 Strip upstream product assumptions

- [ ] Remove Bitwarden product branding.
- [ ] Remove Bitwarden trademarks/assets.
- [ ] Remove hosted Bitwarden service URLs.
- [ ] Remove upstream analytics/telemetry not required by Safeory.
- [ ] Remove upstream update channels.
- [ ] Remove commercial plan/license UX.
- [ ] Remove enterprise-only SSO/SCIM/PAM/secrets-manager surfaces that Safeory
      does not need.
- [ ] Remove unused CLI/enterprise surfaces unless a concrete Safeory feature
      requires them.
- [ ] Replace support/legal/account links with Safeory-owned destinations.

## 1.4 Establish Safeory product shell

- [ ] Rebrand account/login/unlock surfaces.
- [ ] Add Safeory navigation shell.
- [ ] Add Passwords.
- [ ] Add Household.
- [ ] Add Today.
- [ ] Add Files.
- [ ] Add Inbox.
- [ ] Add Reminders.
- [ ] Add Plan.
- [ ] Keep password-manager internals functional while hiding upstream
      organization/business terminology from consumer UX.

**Phase 1 exit:** a reproducible Safeory-branded cleaned foundation can create an
account, sign in, manage native credentials, sync two devices, and autofill
Chromium/Firefox.

---

# PHASE 2 — Safeory life vault on the foundation

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

Do not rewrite features that are already inherited and working. This phase is
for Safeory integration gaps only.

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

After Phase 9 passes and the final implementation is frozen, create the final
architecture/security documentation from the actual code and verified behavior.

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
8. Update checkboxes/status in this file when work materially completes.
9. Keep machine-readable provenance current when foundation pins/imports change.
10. Never delete legacy behavior until replacement, migration, read-back, and
    rollback tests prove it safe.
11. Run the relevant verification gates before stopping.
12. Report concrete blockers and continue with the next safe task instead of
    stopping after small preparatory work.

---

# Immediate next work

The next agent should begin with **Phase 0.1: Produce an OSS-clean clients
tree**.

Do not continue the old Safeory generic sync/device-enrollment backlog.

The next material milestone is:

> Clean Bitwarden clients tree with no `bitwarden_license` source and no
> `@bitwarden/commercial-sdk-internal`, followed by passing web, Chromium, and
> Firefox builds/tests from that cleaned tree.
