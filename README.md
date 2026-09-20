# Safeory

Safeory is a local-first, zero-knowledge family life vault. Its target combines
the consumer credential capabilities expected from 1Password
Individual/Families with Trustworthy-style household organization,
collaboration, continuity, and legacy planning. The implemented foundation
already protects documents, credentials, records, property, insurance,
vehicles, possessions, receipts, subscriptions, attachments, recovery, and an
Emergency Card offline on one device.

The target does not include 1Password Business/Enterprise/Developer features
such as workforce SSO/provisioning, SSH agents, CLI secret injection, or
enterprise secrets automation. The authoritative combined-product contract is
`docs/architecture/combined-product.md`.

## Current phase

Phase 1 — browser-first local platform with the AWS-hosted sync/API layer in implementation.

Implemented now:

- portable Rust crypto/domain/storage crates with Argon2id root-key wrapping, HKDF-separated per-item keys, XChaCha20-Poly1305 authenticated envelopes, explicit schema/version checks, bounded encrypted records, and negative security tests;
- `crates/vault-wasm`, which runs the browser vault core in WebAssembly, keeps usable vault keys inside WASM memory, persists ciphertext snapshots through browser storage, and exposes only redacted list/deadline projections until a user explicitly opens a record;
- `apps/web`, the primary full-vault interface, with setup/unlock/recovery, schema-driven record editing, encrypted attachments, Emergency Card, recovery kit, master-passphrase rotation, search, trash/restore/permanent purge, and a local Today/deadlines view;
- `apps/extension`, an MV3 browser extension with an isolated background vault, exact-origin credential matching, trusted-click discovery, bounded request throttling, one-shot fill authorization, and a compact credential surface;
- ciphertext-only browser snapshot validation, IndexedDB CAS persistence, and fail-closed durability poisoning when an in-memory mutation cannot be saved;
- portable emergency/recovery primitives, encrypted legacy/account-closure planning metadata, bounded history and attachment formats in the native core, browser encrypted attachment persistence with authenticated chunked add/download/delete and backup/restore, browser readable export, plus Trust Engine policy/threshold foundations and local dual-key trusted-device pairing with durable wrapped recipient keys and a browser pairing responder;
- `apps/api` plus a local Docker integration stack for account/device coordination and opaque encrypted-object sync using PostgreSQL, Valkey, S3-compatible object storage, and SMTP; the production target is AWS as documented in `docs/architecture/aws.md`;
- `vault-sync` versioned account/household/membership/private-and-shared-space
  contracts, including fail-closed topology validation and a local single-owner
  ciphertext-preserving migration plan;
- pinned Rust/JS lockfiles and dependency/security CI policy.

Not implemented yet: browser/API integration and server enforcement for the
account/household/private-and-shared-space contracts, production Account
Secret/device enrollment, end-to-end multi-device sync,
remote collaboration and SecureLinks, TOTP/passkeys/security health/importers,
the household Inbox and private document automation, recurring/cloud reminders,
remote pairing/invitation transport, durable emergency release delivery, and
Plan Test. A fail-closed local timed-release state machine exists in
`vault-emergency`, but it is not wired to a release UI or server coordinator.

## Validation
```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo deny check advisories bans licenses sources
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.15.0 --locked
node scripts/build-vault-wasm.mjs
bun install --frozen-lockfile
cp .env.example .env
docker compose config --quiet
bun run typecheck
bun run test:browser
bun run lint
bun run check:icons
bun run build
bun run audit:js
```

Security design and known dependency risks live under `docs/security/`.
The JavaScript workspace uses Bun 1.4.1 as its primary package manager; `bun.lock`
is the canonical JavaScript lockfile.
The post-V1 strategy (password-manager + autofill + sync/mobile) is in
`docs/ROADMAP.md`. The product ships as a **web app + browser extension**
(ADR 0002) running the Rust core compiled to WASM (ADR 0003); see
`crates/vault-wasm` for the browser vault core, `packages/contracts` for the
shared session/persistence layer, `apps/web` for the web app, and
`apps/extension` for the browser extension.

Architecture documents:

- `docs/architecture/combined-product.md` — product scope, household/space
  model, sync responsibilities, private automation, reminders, and launch gates;
- `docs/architecture/overview.md` — component and trust-boundary overview;
- `docs/architecture/sync.md` — opaque sync, household key distribution,
  conflicts, revocation, SecureLinks, and Travel Mode;
- `docs/architecture/trust-engine.md` — collaboration, continuity, and key
  release model;
- `docs/architecture/aws.md` — production deployment contract;
- `docs/security/cryptography.md`, `server-visible-metadata.md`, and
  `threat-model.md` — cryptography and privacy/security boundaries.

## Production AWS infrastructure

AWS is the production hosting target. The launch-sized topology uses CloudFront
and a private S3 bucket for the static web app, a small Graviton EC2 host for the
Rust API/worker, RDS PostgreSQL, a private S3 ciphertext-object bucket, Cognito
for hosted account identity, SES for notifications, Route 53/ACM for DNS/TLS,
ECR for API images, and CloudWatch plus AWS-managed secrets for operations.

Vault encryption/decryption, master-passphrase processing, recovery secrets,
usable vault keys, and unlocked search remain on authorized user devices. See
`docs/architecture/aws.md` for the complete production topology, security
boundary, scaling path, and production-ready gate.

## Local Docker development infrastructure

Safeory includes a Docker Compose development/integration stack that mirrors the
production service boundaries without being the production deployment. Compose builds the Safeory web app and
Rust API, runs PostgreSQL for durable server-visible metadata/state, Valkey for
ephemeral coordination, Garage for S3-compatible ciphertext object storage, and
Mailpit for local SMTP testing. Vault decryption remains client-side; the API
does not receive usable vault keys or vault plaintext.

Running the stack requires Docker Compose v2 and a Linux-capable Docker daemon.
On Windows, use Docker Desktop in Linux-container mode or a Docker Engine inside
WSL2 with the Compose plugin installed; the standalone Windows Docker CLI alone
is not sufficient for these Linux images.

```text
cp .env.example .env
# Replace every DEV_ONLY / placeholder credential in .env before non-local use.
docker compose up -d --build --wait
docker compose ps
```

Default host endpoints are loopback-only:

- Web app: `http://127.0.0.1:8080`
- API diagnostics: `http://127.0.0.1:8081/health/live` and `/health/ready`
- PostgreSQL: `127.0.0.1:5432`
- Valkey: `127.0.0.1:6379`
- Garage S3 API: `http://127.0.0.1:3900`
- Garage admin API: `http://127.0.0.1:3903`
- Mailpit SMTP: `127.0.0.1:1025`
- Mailpit UI: `http://127.0.0.1:8025`

Garage `v2.4.1` uses its single-node bootstrap mode here, so the bucket and S3
access key from `.env` are created automatically on first launch. The metadata
and object data live in persistent named volumes. This development topology uses
`replication_factor = 1`, which has no node redundancy. It is intentionally not
the production storage topology; production uses AWS RDS/S3 and the controls in
`docs/architecture/aws.md`.

Stop the services without deleting stored data with `docker compose down`.
Deleting the named volumes is intentionally not part of the normal teardown.

## License

Copyright (C) 2026 Safeory contributors.

Safeory is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. See `LICENSE` for the full text.
