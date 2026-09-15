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
Cloudflare API / D1 / R2 / Durable Objects / Queues
```

Dependency direction always points inward toward portable Rust crates. No core crate may depend on Tauri, React, a WebView, or Cloudflare SDK types.

## Local-first ownership

- SQLite is the local persistence substrate.
- Sensitive item fields are serialized then encrypted before SQLite persistence.
- The local database may contain synchronization metadata and encrypted envelopes, but no intentionally plaintext vault secrets.
- Search is performed locally after unlock. Search indexes containing plaintext secrets are not persisted in Phase 0.
- Cloud synchronization is secondary and may be unavailable without preventing core local vault operation.

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

- Workers: authentication coordination, device registration, sync metadata, emergency policy, trusted-person workflow.
- D1: server-visible metadata only.
- R2: encrypted records/attachments/exports.
- Durable Objects: race-sensitive emergency-access state machine.
- Queues: idempotent notifications and retryable jobs.

No backend component receives vault decryption keys.
