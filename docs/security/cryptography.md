# Cryptographic Design

Status: implemented cryptographic baseline; format version 1 with current item
payload schema evolution documented below.

Changes to algorithms, KDF parameters, envelope formats, or key hierarchy require review and an ADR/migration plan.

## Libraries

- `argon2` (RustCrypto) for Argon2id.
- `chacha20poly1305` (RustCrypto) for XChaCha20-Poly1305.
- `hkdf` + `sha2` (RustCrypto) for HKDF-SHA-256 domain separation.
- `getrandom` for OS CSPRNG bytes.
- `zeroize` for best-effort clearing of owned secret buffers.

No custom cryptographic primitive is implemented.

## Key hierarchy

```text
Master passphrase
  |
  | Argon2id + random 128-bit salt
  v
32-byte KEK
  |
  | XChaCha20-Poly1305 unwrap
  v
random 256-bit AccountRootKey
  |
  | HKDF-SHA-256 info="lifevault:v1:item-wrap"
  v
ItemWrapKey
  |
  | XChaCha20-Poly1305 unwrap
  v
random 256-bit per-item key
  |
  `-> XChaCha20-Poly1305 item payload
```

The AccountRootKey is generated randomly and is never a passphrase hash.

## Passphrase KDF

Phase 0 baseline:

- Algorithm: Argon2id, version 0x13.
- Salt: 16 random bytes per root-key wrapping record.
- Output: 32 bytes.
- Memory: 64 MiB.
- Iterations: 3.
- Parallelism: 1.

Wrap records are untrusted input at unlock time. Format v1 rejects Argon2 values
outside reviewed bounds before invoking Argon2: memory 19 MiB through 512 MiB,
iterations 2 through 10, and parallelism 1 through 4. This prevents a corrupted or
malicious local record from requesting unbounded KDF work. Expanding these bounds
requires security review.

OWASP's current documented minimum is 19 MiB, 2 iterations, p=1. Safeory's current baseline starts above that floor. Before production release, benchmark representative supported browser devices and calibrate toward an interactive unlock cost without silently dropping below the reviewed security floor. Parameters are stored with the wrapped-root record so future rewrapping can upgrade them.

Changing the master passphrase re-derives a KEK and rewraps the same random AccountRootKey; it does not require re-encrypting every item.

## Authenticated encryption

AEAD: XChaCha20-Poly1305 with 256-bit keys and 192-bit nonces.

Every item/root-wrap encryption call uses a fresh nonce from the OS CSPRNG and binds structured authenticated data. Authentication failure is terminal for that record; the application does not attempt best-effort plaintext recovery.

```text
EncryptedEnvelopeV1 {
    version: 1,
    payload_schema_version: 1,
    algorithm: "xchacha20poly1305",
    key_id: opaque identifier,
    nonce: 24 bytes,
    ciphertext: bytes,
    authenticated_metadata: {
        purpose,
        object_id,
        revision,
        schema_version
    }
}
```

Authenticated metadata is serialized deterministically by the Rust core rather than supplied by UI code.

## Domain separation

HKDF-SHA-256 derives context keys from the AccountRootKey. Phase 0 reserves:

> Compatibility note: the implemented v1 item/root encryption domains retain the historical `lifevault:*` prefix as immutable wire-format labels so existing encrypted vaults remain decryptable after the Safeory product rename. New domains use the `safeory:*` prefix.

- `lifevault:v1:item-wrap`
- `safeory:v1:attachment-wrap`
- `safeory:v1:sync-auth` (future)
- `safeory:v1:emergency-wrap` (future)

A key derived for one purpose must not be reused for another purpose.

Implemented additional domains (Trust Engine foundation):

- `safeory:v1:recovery-wrap` — HKDF-SHA256 KEK from a 256-bit CSPRNG recovery
  secret (fresh 128-bit salt per wrap) unwrapping the AccountRootKey with AAD
  `safeory:recovery-wrap:v1`. Argon2id is deliberately NOT used here: the
  recovery secret is already high-entropy, so a fast HKDF is the correct KDF;
  Argon2id stays reserved for the low-entropy passphrase path. Browser clients
  expose the generated recovery key only as an explicit one-time unlocked UI
  surface. The key must not be logged, sent to the server, or persisted in
  browser plaintext storage. Copy/download/print destinations are outside
  Safeory's erasure boundary and may retain plaintext. Replacing the recovery
  key atomically replaces the singleton recovery wrap for the live vault. It does not rewrite historical encrypted backups: an older
  backup retains the recovery wrap captured when that snapshot was created, and
  recovery-authenticated restore requires that captured key. Safeory unwraps the
  staged backup's AccountRootKey with the recovery wrap, runs the same full
  authenticated backup validation as passphrase restore, then creates a fresh
  Argon2id passphrase wrap for that exact recovered root using the user's new
  master passphrase. Only the staged candidate is rewrapped; the selected source
  backup is not modified, and the captured recovery wrap is preserved.
- `safeory:v1:share-wrap` — per-envelope wrap key from an ephemeral-static
  X25519 DH shared secret, HKDF salt `SHA256(ephemeral_pub || recipient_pub)`,
  XChaCha20-Poly1305 payload with AAD binding sender/recipient/fingerprint/
  ephemeral/purpose. Recipient fingerprint (`SHA256(domain || pubkey)[..16]`)
  is bound into the AAD so an envelope cannot be retargeted silently.
  `sender_public` is self-asserted: `open` checks it against a
  caller-supplied expectation, so sender authorization belongs to the
  grant-policy layer, not the transport envelope. Long-term device secrets
  rely on `x25519-dalek`'s `zeroize` drop handling (default feature, kept on).
- Threshold recovery uses standard Shamir secret sharing over GF(256) via the
  reviewed `blahaj` crate (`zeroize_memory` feature on) — the maintained fork
  carrying the RUSTSEC-2024-0398 polynomial-coefficient-bias fix that the
  unmaintained `sharks` crate never received; no custom threshold crypto.
  Thresholds below 2 are rejected so a single share can never
  reconstruct a capsule key or recovery secret.

## Threshold splitting (implemented in `vault-emergency`)

Capsule keys and recovery secrets are split with standard Shamir secret
sharing over GF(256) via the pinned `blahaj` fork (RUSTSEC-2024-0398 fix).
Thresholds below 2 are
rejected so a single share can never reconstruct a secret; at most 255 shares
are supported. Reconstruction rejects malformed or duplicate shares. No
custom threshold cryptography is implemented.

## Attachment encryption and nonce construction

Each attachment is immutable in V1 and receives a fresh random 256-bit file key. A key derived from the AccountRootKey with HKDF-SHA256 domain `safeory:v1:attachment-wrap` wraps that file key with XChaCha20-Poly1305. The wrap AAD binds the attachment ID, file-key ID, and attachment revision. Replacing a file creates a new attachment object rather than reusing a file key or nonce space.

The encrypted attachment manifest is authenticated under the file key and contains either an Active state (`attachment_id`, encrypted owner item ID, filename, plaintext size, fixed chunk size, chunk count) or a Tombstone state (`attachment_id`, owner item ID, deletion time). The manifest AAD binds the attachment ID, revision, and payload schema version. No plaintext owner mapping or filename is stored in the SQLite attachment tables.

Active files are split into fixed 1 MiB plaintext chunks. One random 16-byte nonce prefix is generated per attachment key and each 24-byte XChaCha nonce is constructed as `prefix || u64_be(slot)`: data chunk `i` uses slot `i`, while the manifest uses slot `u64::MAX`. The chunk AAD binds attachment ID, attachment revision, owner item ID, chunk index, chunk count, and total plaintext size. This makes nonce uniqueness structural and prevents chunk transplant, reorder, truncation, count, and size changes from authenticating under the same envelope.

Deletion creates a fresh authenticated tombstone envelope with a fresh file key/wrap, removes the attachment reference from the encrypted parent item, and deletes all old chunk rows in the same SQLite transaction. The old file key is therefore not retained in the tombstone. Moving an item to Trash retains its attachments so restore remains lossless; permanent item purge tombstones its attachments and removes their chunks atomically.

## Memory handling

- Root keys, KEKs, derived wrap keys, and per-item keys use zeroizing owned buffers.
- Secret key types do not implement `Debug` or `Display`.
- Logs and errors must never contain passphrases, plaintext item values, keys, or decrypted titles.
- Avoid cloning key buffers.

Rust/zeroization cannot guarantee erasure of copies made by the compiler, OS, swap, crash capture, device drivers, or compromised processes. This is best-effort minimization, not guaranteed memory destruction.

### Browser/WASM plaintext boundary

- AccountRootKey, KEK, derived wrapping keys, and per-item keys remain Rust-owned inside the WASM vault and are never intentionally returned as JavaScript values.
- The master passphrase necessarily exists transiently in a browser input and JS string while creating or unlocking. JavaScript/browser copies cannot be guaranteed erased; the WASM/Rust side minimizes further copies and zeroizes owned secret buffers where possible.
- Global list/search state uses redacted summaries. Full decrypted fields and notes cross the binding only after an explicit record open. Deadline projection exposes only item ID, kind, title, deadline label/date/days-until, and revision.
- Extension credential matching uses a separate summary projection that excludes passwords and notes. A password is decrypted for content-script fill only after trusted user intent, exact sender-derived origin matching, and one-shot authorization.
- Lock drops the Rust-owned root-key wrapper and clears browser plaintext-derived application state. WASM linear memory and JavaScript strings cannot provide guaranteed physical erasure from the browser/OS process.
- Recovery keys and other explicitly displayed secrets are high-value plaintext. They must not be persisted in IndexedDB/local storage, URLs, logs, analytics, server-rendered props, or network requests.
- Credential generation uses the CSPRNG through `getrandom`. The portable Rust implementation uses rejection sampling, includes every required character class, excludes visually ambiguous alphanumerics, and shuffles cryptographically before returning the explicitly requested generated value.
- Clipboard copy is user initiated. Browser cleanup is ownership-checked and best-effort where the browser permits delayed clipboard access; OS clipboard history, synchronization, accessibility tools, malware, or another process can retain copied data outside Safeory's control.
- Browser attachment/export work must use user-mediated browser file APIs. Plaintext bytes may exist transiently in browser memory during an explicit operation; no server component receives them.
### Plaintext item bounds

Before item encryption, the portable Rust core rejects records that exceed the supported local limits: titles are bounded to 256 Unicode scalar values, an item may contain at most 32 fields, at most 64 item links, and at most 16 attachment references; field names are bounded to 64 characters, each field value to 100,000 characters, notes to 100,000 characters, and credential account-closure instructions to 100,000 characters. The storage boundary additionally caps the vault at 65,536 encrypted item rows, each encoded encrypted item record at 128 MiB, and encoded root/recovery wraps at 16 KiB before those attacker-controlled BLOBs are materialized. Version history retains at most 20 earlier encrypted revisions per item, 131,072 history rows vault-wide, and 1 GiB of history ciphertext; every historical row uses the same 128 MiB encoded-envelope ceiling. Attachments are currently bounded to 64 MiB plaintext per file, 16 per item, 16,384 attachment objects (including tombstones) per vault, and 1 GiB of encrypted attachment storage per vault; filenames are bounded to 255 Unicode scalar values. Restore/read paths enforce the core-record, history, and attachment object/count/BLOB bounds before materializing attacker-controlled collections. These are resource-abuse bounds, not cryptographic limits.

## Versioning and migration

Root wraps, item envelopes, and attachment envelopes carry independent format/payload versions. Item payload schema v3 introduced encrypted attachment references. Item payload schema v4 added the required encrypted per-record legacy-planning disposition. Item payload schema v5 added the required encrypted `AccountClosurePlan`; v1-v3 decode with `LegacyDisposition::Unspecified` plus a default closure plan, and v4 preserves its legacy disposition while injecting only the default closure plan. Subscription records were added within the v5 shape through the `subscription` item-kind enum value plus ordinary encrypted fields; a pre-subscription decoder fails closed on that unknown enum value for v1-v4. Item payload schema v6 established the downgrade boundary for the expanded possession field set (`category` and `location`): current readers still accept v5, but older v5 binaries reject v6 before deserialization rather than reading and later rewriting a possession while dropping fields they do not preserve. Item payload schema v7 is the current write version and establishes the same downgrade boundary for optional Emergency Card contact email. Current readers accept v6 cards that predate email and default the missing contact email to empty; older v6 binaries reject v7 before deserialization, so they cannot load a newer Emergency Card and later erase its email field on rewrite. The possession fields and Emergency Card contact email remain ordinary data inside the authenticated encrypted item payload. Current-schema top-level fields are strict: missing or unknown mandatory planning fields fail deserialization. The schema version is authenticated in item-payload AAD, so relabeling ciphertext across payload versions fails authentication. Readers reject unknown mandatory algorithms/versions rather than guessing. SQLite schema v4 adds encrypted_item_history and is unchanged by payload v7; migration from v1-v3 creates the history table empty and does not synthesize old versions. Each history row is the exact previous authenticated EncryptedItemV1 envelope copied verbatim inside the same transaction that advances the current item revision. History capture therefore does not decrypt/re-encrypt archive copies, and a stale or failed CAS cannot leave a history row. Trash/restore preserve existing history without adding lifecycle-only snapshots; permanent purge deletes all history for that item atomically. Encrypted database backup/restore preserves and validates history rows and bounds. Future payload migrations read with the old format and write a new authenticated format without silently deleting records that fail migration.

The encrypted item envelope also carries a payload schema version. Readers reject
newer payload schemas before deserialization, preventing an older binary from
silently reading and later rewriting a newer payload while dropping unknown data.

## Emergency access (future)

Emergency grants will wrap only authorized keys to the trusted recipient's public key using reviewed public-key primitives/libraries. The server controls release timing but never decrypts the capsule. V1 waiting periods are policy enforcement, not cryptographic time-lock encryption.
