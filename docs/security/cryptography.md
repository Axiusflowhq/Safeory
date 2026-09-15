# Cryptographic Design

Status: Phase 0 implementation design, format version 1.

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

OWASP's current documented minimum is 19 MiB, 2 iterations, p=1. The desktop baseline starts above that floor. Before production release, benchmark representative supported devices and calibrate toward an interactive unlock cost without silently dropping below the reviewed security floor. Parameters are stored with the wrapped-root record so future rewrapping can upgrade them.

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

> Compatibility note: the implemented v1 item/root encryption domains retain the historical `lifevault:*` prefix as immutable wire-format labels so existing encrypted vaults remain decryptable after the Safeory product rename. New, not-yet-implemented domains use the `safeory:*` prefix.

- `lifevault:v1:item-wrap`
- `safeory:v1:attachment-wrap` (future)
- `safeory:v1:sync-auth` (future)
- `safeory:v1:emergency-wrap` (future)

A key derived for one purpose must not be reused for another purpose.

Implemented additional domains (Trust Engine foundation):

- `safeory:v1:recovery-wrap` — HKDF-SHA256 KEK from a 256-bit CSPRNG recovery
  secret (fresh 128-bit salt per wrap) unwrapping the AccountRootKey with AAD
  `safeory:recovery-wrap:v1`. Argon2id is deliberately NOT used here: the
  recovery secret is already high-entropy, so a fast HKDF is the correct KDF;
  Argon2id stays reserved for the low-entropy passphrase path.
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

## Attachment nonce construction (future)

Large attachments will use a random per-file key. Chunk nonces will be derived from a per-file random nonce prefix plus a monotonically increasing chunk index, with the index authenticated as metadata. This makes nonce uniqueness under one file key structural rather than relying on a fresh random nonce for every chunk. Exact framing will be specified before attachment code is written.

## Memory handling

- Root keys, KEKs, derived wrap keys, and per-item keys use zeroizing owned buffers.
- Secret key types do not implement `Debug` or `Display`.
- Logs and errors must never contain passphrases, plaintext item values, keys, or decrypted titles.
- Avoid cloning key buffers.

Rust/zeroization cannot guarantee erasure of copies made by the compiler, OS, swap, crash capture, device drivers, or compromised processes. This is best-effort minimization, not guaranteed memory destruction.

### Desktop IPC memory boundary

- The AccountRootKey, KEK, derived wrapping keys, and per-item keys remain in Rust and are never returned to the WebView.
- The master passphrase necessarily exists in the password field and Tauri IPC argument while creating or unlocking a vault. The Rust command moves the received `String` into a zeroizing buffer immediately, but renderer/IPC copies cannot be guaranteed erased.
- Decrypted note content and non-password credential metadata are returned to the renderer only while the vault is unlocked because the UI must display them. Credential list/search responses never contain password values.
- A credential password crosses IPC only after an explicit Reveal or Edit action through the narrow `get_credential` command. Passwords are masked by default; secret-bearing edit detail is held only in the mounted credential editor's local state rather than top-level application state. Hide/unmount drops the current React password-state reference, but JavaScript/WebView/OS memory erasure cannot be guaranteed. A renderer compromise during an unlocked reveal/edit remains inside the plaintext trust boundary.
- Document list/search responses omit the encrypted document-number value and expose only the record title, issuer, expiry, notes, and a presence flag. The document number crosses IPC only for an explicit Reveal or Edit through `get_document`, using the same revision and renderer-generation fences as credential secret access. Secret-bearing edit detail remains editor-local rather than entering top-level application state. Phase 0 document records are metadata only; no file attachment bytes are stored or exposed.
- Insurance list/search responses omit policy-number values and expose only title, provider, policy type, renewal date, notes, and a presence flag. Policy numbers cross IPC only for explicit Reveal or Edit through `get_insurance`, with expected-revision checks and renderer-generation fencing identical to other reveal-only secrets. Secret-bearing edit detail remains editor-local rather than entering top-level application state.
- Financial list/search responses expose only title, institution, account type, currency, and an account-number presence flag. Account numbers and freeform financial notes are excluded from top-level renderer list/search state. Account-number reveal uses a narrow command that returns only that value; full financial detail is fetched only inside the keyed editor and is generation-fenced.
- Property list/search responses expose only title, property type, constrained ownership status, and presence flags. Address, property reference, and freeform property notes are excluded from top-level renderer list/search state. Address and property-reference reveals use separate narrow commands; full property detail is fetched only inside the keyed editor. Ownership is restricted to a reviewed categorical set before it may enter summary state.
- Manual lock and the 10-minute renderer inactivity timer invalidate the renderer session generation before invoking the Rust lock command, immediately clearing decrypted item/editor state. Responses from the prior generation are discarded so delayed list/save/reveal work cannot repopulate plaintext after lock. Rust lock then drops the `VaultSession` and root key.
- Credential editor inputs opt out of WebView login-autofill semantics so stored third-party credentials are not deliberately offered to the host credential manager as Safeory login fields.
- Credential generation uses the OS CSPRNG through `getrandom`. The portable Rust core uses rejection sampling rather than modulo-biased byte reduction, guarantees at least one lowercase letter, uppercase letter, digit, and symbol, excludes visually ambiguous alphanumeric characters, and cryptographically shuffles the result. The desktop command currently requests 20 characters and requires an unlocked vault; the generated value crosses IPC only after the user explicitly chooses Generate.
- Phase 0 does not expose credential clipboard-copy actions. Clipboard support requires a reviewed timed-clear design before it is added.

### Plaintext item bounds

Before item encryption, the portable Rust core rejects records that exceed the supported local limits: titles are bounded to 256 Unicode scalar values, an item may contain at most 32 fields, field names are bounded to 64 characters, each field value to 100,000 characters, and notes to 100,000 characters. These are resource-abuse bounds, not cryptographic limits. They are enforced for both create and update before ciphertext generation or storage mutation.

## Versioning and migration

Root wraps and item envelopes carry independent format versions and algorithms. Readers reject unknown mandatory algorithms/versions rather than guessing. Future migrations read with the old format and write a new authenticated format without silently deleting records that fail migration.

The encrypted item envelope also carries a payload schema version. Readers reject
newer payload schemas before deserialization, preventing an older binary from
silently reading and later rewriting a newer payload while dropping unknown data.

## Emergency access (future)

Emergency grants will wrap only authorized keys to the trusted recipient's public key using reviewed public-key primitives/libraries. The server controls release timing but never decrypts the capsule. V1 waiting periods are policy enforcement, not cryptographic time-lock encryption.
