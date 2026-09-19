# Safeory Architecture Overview

## Security objective

Safeory is a local-first encrypted vault. Plaintext and usable vault keys stay on authorized user devices. Backend infrastructure stores ciphertext and the minimum metadata needed to authenticate devices, synchronize opaque objects, and coordinate emergency-access policy.

A stolen backend database and object store must be insufficient by themselves to directly recover readable vault contents.

## Layering

```text
React UI
  |
  | narrow typed IPC
  v
Tauri adapter (replaceable)
  |
  v
vault-core
  |-- vault-models
  |-- vault-crypto
  |-- vault-storage
  |-- vault-platform
  |-- vault-sync
  |-- vault-sharing
  `-- vault-emergency
  |
  | ciphertext + minimum metadata only
  v
Self-hosted Rust HTTP API
  |-- PostgreSQL (accounts, devices, opaque sync/policy state)
  |-- S3-compatible object storage (ciphertext blobs; Garage preferred)
  |-- Valkey (ephemeral queues, rate limits, job coordination)
  `-- SMTP (security notifications only)
```

Dependency direction always points inward toward portable Rust crates. No core crate may depend on Tauri, React, a WebView, a particular reverse proxy, database driver, object-store vendor, or cloud-provider SDK type.

## Local-first ownership

- SQLite is the local persistence substrate.
- Sensitive item fields are serialized then encrypted before SQLite persistence.
- The local database may contain synchronization metadata and encrypted envelopes, but no intentionally plaintext vault secrets.
- Search is performed locally after unlock. Search indexes containing plaintext secrets are not persisted in Phase 0.
- Network synchronization is secondary and may be unavailable without preventing core local vault operation.

## Initial vertical slice

```text
master passphrase
  -> Argon2id KEK
  -> unwrap random AccountRootKey
  -> derive item-wrap context key
  -> unwrap random per-item key
  -> decrypt authenticated item payload
```

Creation is the reverse path. The database receives only salts, nonces, ciphertexts, opaque IDs, revisions, and format metadata.

## Platform boundaries

`vault-platform` defines capabilities such as secure key storage, biometrics, filesystem, clipboard, clock, randomness, and network transport. Platform-specific implementations live outside the security-domain crates. Phase 0 uses the OS CSPRNG directly and does not yet persist root keys in OS secure storage.

## Backend shape (later phases)

Self-hosting is the primary deployment target. The first supported backend is a
Docker-deployed stack that can run on one operator-controlled host and later be
split across machines without changing the client protocol:

- Rust HTTP API: authentication coordination, device registration, opaque sync
  metadata, emergency policy, trusted-person workflow, and presigned/object
  storage mediation where needed.
- PostgreSQL: authoritative server-visible account, device, revision,
  idempotency, audit, and emergency-workflow state.
- S3-compatible object storage: encrypted records, attachments, and other
  ciphertext blobs. Garage is the preferred self-hosted implementation. MinIO's
  community distribution is no longer maintained/prebuilt, so it is not the
  default recommendation; compatibility with standard S3 APIs remains the
  portability boundary.
- Valkey: ephemeral rate-limit counters, retry queues, worker coordination, and
  short-lived job state. Durable security decisions stay in PostgreSQL.
- SMTP: account/security notifications with no vault content.
- Reverse proxy/TLS: the public ingress terminates HTTPS and forwards only the
  API surface required by Safeory. Deployment may use an operator-selected
  reverse proxy as long as TLS and security headers are enforced.

Managed cloud services may be supported later as interchangeable deployment
options. They must preserve the same protocol and zero-knowledge boundary; no
cloud provider is required for the primary product architecture.

No backend component receives usable vault decryption keys or vault plaintext.
