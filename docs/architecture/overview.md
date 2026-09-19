# Safeory Architecture Overview

## Security objective

Safeory is a local-first encrypted vault. Plaintext and usable vault keys stay on authorized user devices. Backend infrastructure stores ciphertext and the minimum metadata needed to authenticate devices, synchronize opaque objects, and coordinate emergency-access policy.

A stolen backend database and object store must be insufficient by themselves to directly recover readable vault contents.

## Layering

```text
React web app                    Browser extension
      \                           /
       \                         /
        +---- typed contracts ---+
                   |
                   v
              vault-wasm
          /        |        \
 vault-models  vault-crypto  vault-storage (browser MemStore)
      |            |               |
      +------------+---------------+
                   |
                   | ciphertext + minimum metadata only
                   v
          Self-hosted Rust HTTP API
            |-- PostgreSQL
            |-- S3-compatible object storage
            |-- Valkey
            `-- SMTP
```

Dependency direction points inward toward portable Rust crates. Security-domain crates do not depend on React, browser UI types, a particular reverse proxy, object-store vendor, or cloud-provider SDK type.

## Local-first ownership

- Browser clients persist ciphertext snapshots locally: IndexedDB for the web
  session and browser-managed extension storage for the extension background vault.
- Sensitive item fields are serialized and encrypted inside the Rust/WASM
  boundary before browser persistence.
- `vault-storage` retains its SQLite implementation for native library utilities,
  tests, migration/backup formats, and future non-browser adapters; it is not a
  shipping client surface.
- Search is performed locally after unlock. Search indexes containing plaintext secrets are not persisted in Phase 0.
- Network synchronization is secondary and may be unavailable without preventing core local vault operation.

The browser build uses the same crypto/domain model through `vault-wasm`, with a
ciphertext-only `MemStore` snapshot persisted in IndexedDB. Browser snapshot
restore validates the shared storage schema/object-count/revision/encoded-size
bounds and duplicate object IDs before accepting the encrypted state. Local web
mutations are serialized through mutation -> snapshot -> IndexedDB CAS; if the
durable save fails after the WASM mutation, the session fails closed, locks,
poisons itself, clears plaintext-derived UI state, and requires reload from the
durable IndexedDB snapshot rather than continuing on divergent memory.

The browser extension keeps the unlocked WASM vault in its background worker.
Untrusted page content receives only exact-origin credential summaries after a
trusted Safeory click. Discovery is throttled per tab+origin, and a short-lived
authorization bound to that same context is consumed once before the selected
credential is decrypted for fill.

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

## Backend shape (in implementation)

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
Opaque self-hosted synchronization is in implementation; this architecture
describes the intended server-visible contract and deployment boundaries, not a
claim that the complete sync/auth/device HTTP endpoint surface has shipped.
