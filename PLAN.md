# Safeory Plan — Local V1 Foundation for the Combined Product

Source vision: Private Life OS — organize life, own possessions, continue through
emergencies, protect with zero-knowledge encryption. Trustworthy is the baseline;
the Ownership Wallet + Continuity Engine + real privacy are the differentiators.

Target product: a zero-knowledge consumer alternative to 1Password
Individual/Families plus Trustworthy's household organization, collaboration,
continuity, and legacy workflows. This 23-item checklist measures the existing
single-household local foundation; it is not the complete combined-product
parity checklist. See `docs/architecture/combined-product.md` and
`docs/ROADMAP.md` for the account/household/space architecture and ordered work.

Rule: cloud integration starts only after the local platform below is stable.

## V1 scope (the 23 launch items) — status

### PRIVATE LIFE
| # | Item | Status |
|---|------|--------|
| 1 | Documents | ✅ Done — encrypted metadata (number masked), search, browser/native trash/restore + permanent purge |
| 2 | Important records | ✅ Done — secure notes, credentials (masked + generator + guarded 30s clipboard copy) |
| 3 | Property | ✅ Done — masked address/reference, ownership validation |
| 4 | Insurance | ✅ Done — masked policy number, renewal feeds Today |
| 5 | Vehicles | ✅ Done — make/model/year/renewal, reg/VIN masked, renewal feeds Today |
| 6 | Valuable possessions | ✅ Done — category/location/brand/serial/purchase/warranty, serial masked, warranty feeds Today |

### OWNERSHIP
| # | Item | Status |
|---|------|--------|
| 7 | Receipts | ✅ Done — dedicated encrypted receipts, masked references, links/attachments, return/refund tracking + Today deadlines |
| 8 | Warranty tracking | ✅ Done — `warranty_expiry` + Today alerts |
| 9 | Expiry/renewal reminders | ✅ Done — tested deadlines engine in `vault-core`, Today panel over IPC |

### PEOPLE
| # | Item | Status |
|---|------|--------|
| 10 | Trusted people | 🟡 Partial — encrypted continuity contacts are separate from stable principal UUIDs; browser devices now have durable wrapped X25519/Ed25519 identities plus a local challenge/responder pairing flow, while remote invitation/trust/release coordination remains |
| 11 | Granular permissions | 🟡 Partial — per-item encrypted `AccessPolicy` persistence + fail-closed evaluation + browser planning UX for explicit principal-bound record rules are implemented; authenticated release/approval enforcement remains |

### PLAN
| # | Item | Status |
|---|------|--------|
| 12 | Emergency access | 🟡 Partial — Emergency Card (records + contacts + instructions) works; a local fail-closed timed-release state machine now handles request/wait/approval/release/expiry/deny/revoke simulation, but no release UI, remote delivery, or durable server coordinator exists |
| 13 | Waiting periods | 🟡 Local state machine — 1h/24h/7d/custom waiting periods, approval thresholds, release eligibility, expiry, revocation, exact item-revision/policy fencing, idempotency, and clock-rewind protection are tested locally; no durable server timer/coordinator yet |
| 14 | Selected legacy access | 🟡 Local planning done — each active record can be marked Unspecified/Selected for legacy/Private forever/Destroy on death; this is encrypted planning metadata only, with no trusted-person release or automatic deletion enforcement yet |
| 15 | "If something happens to me" | 🟡 Partial — card + instructions + kit cover the single-device case |
| 16 | Plan test | 🟡 Not wired — the underlying recovery, Emergency Card, planning metadata, pairing, and local timed-release primitives exist, but the integrated Plan Test/readiness UI and preparedness score have not shipped yet |

### PRIVACY
| # | Item | Status |
|---|------|--------|
| 17 | Client-side encryption | ✅ Done — XChaCha20-Poly1305, per-item keys, Argon2id KEK |
| 18 | Zero-knowledge server | 🟡 Partial — `apps/api` implements account/device coordination, isolated pending-device activation, opaque revision-fenced ciphertext transport, topology-backed household/space authorization, and direct metadata discovery for the bounded account-bootstrap singleton; shared browser contracts durably coordinate approved-device grants and inventory confirmation, and web now drives explicit approval/grant export, while joining-device/extension UX, hosted recovery, cross-account shared-object routing, production AWS identity, and end-to-end multi-device sync remain |
| 19 | Local encrypted vault | ✅ Done — SQLite ciphertext-only, rollback-journal tested |
| 20 | E2EE sharing | 🟡 Partial — `vault-sharing` v2 provides recipient-confidential X25519 envelopes plus a separate Ed25519 trusted-device pairing/signing foundation; share-v2's `sender_public` itself remains unauthenticated and there is no transport/release protocol |
| 21 | Recovery kit | ✅ Done — save/print, install/confirm, live-key replacement, unlock-with-kit, recovery-authenticated backup restore with new passphrase, 2-of-3 social recovery crypto + e2e test |
| 22 | Device management | 🟡 Partial — configurable auto-lock, lock-on-background, settings, Strict local lock shortcut, and durable local wrapped recipient device identities with delete/rotate support; no synced inventory, reviewed new-device enrollment, remote revoke, space-key rotation, or Travel Mode |
| 23 | Portable export | ✅ Done — readable JSON + authenticated encrypted browser/native backups, including encrypted attachments |

## What is implemented but not wired (crypto-ready, no IPC/UI)
- `vault-sharing`: seal/open envelopes for item keys and recovery shares.
- `vault-emergency`: policy evaluation, local timed-release request state machine, Shamir threshold (`blahaj`, RUSTSEC-2024-0398 fix), sealed share envelopes, full no-vendor recovery path.
- Compartment key hierarchy: spec'd, not coded (`safeory:v1:compartment-wrap`).

## Backlog — ordered, post-V1

1. Integrate the implemented versioned account -> household -> private/shared
   space contracts and ciphertext-preserving single-owner migration with the
   application bootstrap. Strict browser parsing/validation mirrors the Rust
   contracts, and the API now durably publishes revision-fenced topology and
   enforces it for same-account scoped transport. Cross-account shared-object
   routing remains. The independently rotatable, device-specific space-key
   envelope crypto is implemented; durable envelope publication and rotation
   fencing remain.
2. Finalize production Account Secret/device enrollment for cloud accounts.
   ADR 0006 now fixes the high-entropy Account Secret format, two-factor remote
   root-wrap construction, local migration, fresh-device import, and recovery
   invariants; the Rust/WASM core implements and tests that root bootstrap
   without exposing the key to JavaScript. The shared wire contract now defines
   a bounded account-scoped singleton with CAS publication and authenticated
   direct discovery. Web and extension development enrollment now generate and
   confirm the Account Secret, re-authenticate before account creation, and
   durably queue the account bootstrap envelope before publishing topology.
   ADR 0007 now defines and implements the signed, recipient-encrypted
   device-credential handoff core plus a bounded pending-device API state
   machine. Shared browser contracts now persist encrypted approval drafts,
   retry exact preparation, activate, and verify approver inventory before
   credential storage. Web approval/grant export is wired. Production identity,
   joining-device and extension UX, hosted recovery, and external cryptographic
   review remain.
   Cognito identity must not become the sole protection for remotely stored root
   wraps.
3. Integrate the implemented browser compatibility/opaque transport client and
   credential-free durable push outbox/pull cursor coordinator into web/extension
   application mutation and acceptance flows. A strict encrypted-item adapter now
   binds local encrypted records to revision/hash-fenced opaque mutations and
   verifies pulled record/header identity before acceptance. Fail-closed three-way
   reconciliation now separates safe fast-forwards, replays, local-ahead state,
   and concurrent edits. A CAS-fenced IndexedDB acceptor durably retains the
   accepted baseline or encrypted conflict candidate, with crash-safe ordering
   around a snapshot callback. `VaultSession` now implements that callback with
   exact-ciphertext WASM compare-and-swap plus the existing snapshot durability
   fence, without locking an active root key. Initial single-owner topology IDs
   and migration assignments are now persisted before idempotent publication.
   A composed encrypted-item runtime now pulls first, reconstructs missing local
   outbox entries from the durable vault with content-derived operation IDs,
   preserves queued revision chains, publishes authenticated tombstone metadata,
   and then flushes. The web settings surface now performs explicit same-origin
   development enrollment, resumes locally wrapped device credentials after
   unlock, and schedules serialized cycles after durable mutations, reconnect,
   foregrounding, and a bounded interval. The extension now has matching
   development enrollment, wrapped credentials, durable remote acceptance,
   mutation/manual/unlock triggers, and an MV3 alarm while its background vault
   remains unlocked. Reviewed production account enrollment remains. Then
   complete multi-device bootstrap,
   household membership, attachment transport, offline queues, exact-revision conflicts,
   tombstones, revocation, key rotation, pagination, and web/extension
   convergence.
4. Finish trusted-device and collaborator invitation transport. Contacts remain
   separate; pairing proves device-key possession, not human identity.
5. Complete consumer password-manager parity: structured multi-origin logins,
   TOTP, passkeys, security health, save/update capture, form-fill identities,
   importers, Firefox support, shared spaces, SecureLinks, and Travel Mode.
6. Complete household operating workflows: family/medical/tax/legal/business/
   contact schemas, files/folders, connections, recurring reminders, Inbox,
   activity, browser capture, and local/private document extraction.
7. Wire the local timed-release simulation into reviewed Plan Test flows, then
   implement the durable PostgreSQL/worker coordinator, signed trustee protocol,
   owner alerts, authenticated release delivery, audit, denial/revocation, and
   expiry on AWS.
8. Enforce legacy/private-forever/destruction intent only after the remote Trust
   Engine exists, including documented S3/backups and cryptographic-erasure
   semantics.
9. AWS productionization: reviewable IaC, Cognito account identity, Safeory
   device auth, RDS metadata/policy state, S3 ciphertext, Valkey coordination,
   SES generic notifications, end-to-end sync, monitoring, and restore drills.
10. OS keystore + biometric unlock where browser/platform APIs permit; a native
    client requires its own ADR before claiming native autofill or hardware
    isolation.
11. Expanded home inventory and account-closure automation. Safeory still does
    not contact providers, process payments, cancel subscriptions, or close
    accounts automatically.
12. Version-history restore/rollback and richer encrypted activity. Bounded
    browse-only history exists, but restore remains deferred because historical
    attachment references may no longer have live attachment data.

## Non-goals (explicit)
Banking/investment aggregation, resale marketplace, whole-vault cloud AI,
ads/data business of any kind, and company-side decryption — ever. Password
autofill is a core extension feature and is intentionally in scope.
The current consumer scope also excludes 1Password Business/Enterprise/Developer
parity: workforce SSO/provisioning, enterprise posture administration, SSH
agents, CLI secret injection, and infrastructure-secret automation.

## Verification gates (must stay green)
`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, `cargo audit`, `cargo deny check advisories bans licenses sources`,
frozen-lockfile JavaScript install, Compose config validation, `bun run typecheck`, `bun run test:browser`, `bun run lint`,
`bun run check:icons`, `bun run build`, and `bun run audit:js`. Dependency additions follow the review
rule in `docs/security/dependency-risk-register.md` — deny failures block, no silent ignores.
