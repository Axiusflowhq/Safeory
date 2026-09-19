# Safeory

Safeory is a local-first, zero-knowledge consumer vault for important personal
information: documents, records, property, insurance, vehicles, and possessions,
with an encrypted emergency card, recovery kit, and portable export — all
working offline on one device, before any cloud or trusted-person networking.

## Current phase

Phase 1 — browser-first local platform with the self-hosted sync/API layer in implementation.

Implemented now:

- portable Rust crypto/domain/storage crates with Argon2id root-key wrapping, HKDF-separated per-item keys, XChaCha20-Poly1305 authenticated envelopes, explicit schema/version checks, bounded encrypted records, and negative security tests;
- `crates/vault-wasm`, which runs the browser vault core in WebAssembly, keeps usable vault keys inside WASM memory, persists ciphertext snapshots through browser storage, and exposes only redacted list/deadline projections until a user explicitly opens a record;
- `apps/web`, the primary full-vault interface, with setup/unlock/recovery, schema-driven record editing, Emergency Card, recovery kit, search, trash, and a local Today/deadlines view;
- `apps/extension`, an MV3 browser extension with an isolated background vault, exact-origin credential matching, trusted-click discovery, bounded request throttling, one-shot fill authorization, and a compact credential surface;
- ciphertext-only browser snapshot validation, IndexedDB CAS persistence, and fail-closed durability poisoning when an in-memory mutation cannot be saved;
- portable emergency/recovery primitives, encrypted legacy/account-closure planning metadata, bounded history and attachment formats in the native core, plus the Trust Engine policy and threshold-sharing foundations;
- `apps/api` and Docker-first self-hosted infrastructure for account/device coordination and opaque encrypted-object sync using PostgreSQL, Valkey, S3-compatible object storage, and SMTP;
- pinned Rust/JS lockfiles and dependency/security CI policy.

Not implemented yet: complete browser attachment/export parity, full trusted-person grant UX and timed emergency release, automated account closure, account/passkey flows, and end-to-end multi-device sync UX.

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
corepack pnpm install --frozen-lockfile
corepack pnpm typecheck
corepack pnpm lint
corepack pnpm build
```

Security design and known dependency risks live under `docs/security/`.
The post-V1 strategy (password-manager + autofill + sync/mobile) is in
`docs/ROADMAP.md`. The product ships as a **web app + browser extension**
(ADR 0002) running the Rust core compiled to WASM (ADR 0003); see
`crates/vault-wasm` for the browser vault core, `packages/contracts` for the
shared session/persistence layer, `apps/web` for the web app, and
`apps/extension` for the browser extension.

## Self-hosted Docker infrastructure

Safeory includes a Docker-first self-hosted stack and does not require
Cloudflare or another managed backend. Compose builds the Safeory web app and
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
`replication_factor = 1`, which has no node redundancy; production deployments
should use unique generated secrets, backups, multiple Garage nodes/zones as
appropriate, and a TLS reverse proxy or private network rather than exposing
these service ports directly.

Stop the services without deleting stored data with `docker compose down`.
Deleting the named volumes is intentionally not part of the normal teardown.

## License

Copyright (C) 2026 Safeory contributors.

Safeory is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. See `LICENSE` for the full text.
