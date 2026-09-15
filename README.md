# Safeory

Safeory is a local-first, zero-knowledge consumer vault for important personal
information: documents, records, property, insurance, vehicles, and possessions,
with an encrypted emergency card, recovery kit, and portable export — all
working offline on one device, before any cloud or trusted-person networking.

## Current phase

Phase 1 — working local platform (no cloud yet).

Implemented now:

- portable Rust workspace with Tauri kept as a replaceable shell,
- random AccountRootKey protected by an Argon2id-derived KEK,
- HKDF-separated per-item key wrapping,
- XChaCha20-Poly1305 authenticated encrypted item envelopes,
- SQLite persistence of ciphertext-only secret-bearing records,
- explicit database/envelope/payload version checks,
- process-restart round-trip and negative security tests,
- active SQLite rollback-journal plaintext inspection,
- strict desktop CSP and minimal Tauri capability surface,
- one-time fail-closed migration of the pre-Safeory `com.lifevault.desktop`
  app-data directory to `com.safeory.desktop`, preserving the complete local
  vault directory rather than creating a fresh empty vault,
- local desktop vault setup, lock/unlock, secure notes, masked credentials,
  encrypted document-metadata, receipt, insurance, financial, property, vehicle,
  and possession records, revisioned editing, stale-edit conflict protection,
  metadata-only list projections with narrow on-demand secret reveal/edit,
  backend-owned credential password copy with conditional 30-second clipboard
  clearing that never exposes generic clipboard access to the renderer,
  encrypted cross-item links with title resolution and jump navigation,
  CSPRNG-backed strong-password generation, record-type filtering, local
  search, a Today panel driven by a tested local deadlines engine, trash with
  restore/permanent-delete, and a 10-minute inactivity lock,
- encrypted Emergency Card: selected records, emergency contacts, and
  instructions in one singleton record, hidden from lists, with stale-edit
  protection and graceful handling of trashed references,
- no-backdoor recovery kit: high-entropy key with dedicated plaintext Save and
  print workflows, explicit install/confirm, safe replacement for the live
  vault, unlock-with-kit while locked, recovery-authenticated encrypted-backup
  restore with a new master passphrase, and threshold (2-of-3 style) social
  recovery plus sealed recovery-share envelopes at the crypto layer,
- local Plan Test: metadata-only readiness checks for Emergency Card records,
  contacts, instructions, and recovery configuration, plus a read-only recovery
  key self-test against the exact currently open vault root; it also summarizes
  whether active records have local legacy-planning preferences without counting
  those unenforced preferences as readiness,
- encrypted per-record legacy planning intent (`Unspecified`, `Selected for
  legacy`, `Private forever`, `Destroy on death`) with exact-revision mutation,
  detail-only IPC, lifecycle/backup preservation, and explicit UI copy that no
  sharing, release, death verification, or automatic deletion is enforced yet,
- encrypted credential account-closure planning (`Unspecified`, `Keep open`,
  `Close account`, `Review manually`) with private instructions, exact-revision
  detail-only IPC, lifecycle/backup preservation, and no automatic provider
  contact, sign-in, death verification, credential sharing, or account closure,
- bounded encrypted per-record version history: up to 20 earlier active snapshots
  per item, archived from the previous authenticated ciphertext inside the same
  revision-CAS transaction; browsing is read-only and available only from an
  active record detail, protected fields require explicit reveal, historical
  attachment references are metadata only, purge erases retained history, and
  encrypted backups preserve it,
- encrypted local subscription tracking with provider/plan/cost context, a
  bounded billing-cycle vocabulary, optional next-renewal dates surfaced in
  Today, revision history/backup/lifecycle preservation, and no provider login,
  payment processing, automatic renewal, or cancellation action,
- Trust Engine core: conditional access policies with fail-closed local
  evaluation (destruction/deny wins, private-forever, multi-approval,
  waiting periods as documented server-enforced policy, not time-lock crypto),
- portable export and recovery: human-readable active-record JSON plus a
  validated encrypted SQLite snapshot, both written atomically through
  Rust-owned native save dialogs to user-chosen locations; the renderer cannot
  supply arbitrary export paths, and the active vault database is rejected as
  an output target; encrypted backups can be restored transactionally from Settings
  or during first-run setup using either the backup master passphrase or the
  recovery key captured by that backup, without overwriting device-only
  preferences,
- encrypted local file attachments with per-file keys, authenticated 1 MiB
  chunks, metadata-only renderer IPC, Trash/restore lifecycle preservation,
  tombstone-based permanent deletion, and attachment-complete encrypted
  backup/restore,
- local database schema migration (v1/v2/v3 to v4) preserving existing vaults;
  v4 adds bounded encrypted item history without backfilling older revisions,
- focused Tauri adapter tests for locked-state gating, redacted unlock failure,
  item listing, credential revision plumbing, and stale-edit rejection,
- portable Rust item-size bounds before encryption/persistence, with regression
  tests proving oversized creates/updates fail without replacing valid data,
- Ownership Wallet: encrypted `vehicle`/`possession` records, including optional
  possession category/location metadata for local organization, with masked list
  projections for registration/VIN/serial and narrow secret reveal; dedicated encrypted `receipt` records
  with masked references and return/refund Today tracking, plus encrypted
  cross-item `links` (receipt <-> possession, policy <-> vehicle) with title
  resolution, jump navigation, and stale-edit-safe link management,
- Trust Engine V1 spec (`docs/architecture/trust-engine.md`) frozen before
  screens: compartment key hierarchy, per-object policy model, and no-backdoor
  recovery order; policy evaluation, Shamir threshold sharing, and sealed
  recovery-share envelopes implemented and tested in the portable core
  (no IPC/server path yet),
- pinned Rust/JS lockfiles and dependency/security CI policy.

Not implemented yet: grant persistence inside item payloads, trusted-person
grant UX, enforcement of legacy/private-forever/destruction intent, Emergency
Access timed-release coordination, automated account closure, account/passkey flows,
Cloudflare sync. Cloud integration starts only
after this local platform is stable.

## Validation

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo deny check advisories bans licenses sources
corepack pnpm install --frozen-lockfile
corepack pnpm --filter @safeory/desktop typecheck
corepack pnpm --filter @safeory/desktop lint
corepack pnpm --filter @safeory/desktop build
```

Security design and known dependency risks live under `docs/security/`.

## License

Copyright (C) 2026 Safeory contributors.

Safeory is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. See `LICENSE` for the full text.
