# ADR 0006: Protect Remote Root Bootstrap with an Account Secret

Date: 2026-09-20

## Status

Accepted for implementation. External cryptographic review remains a cloud-
launch gate.

## Context

Safeory's existing device-local root wrap derives its key from the master
passphrase with bounded Argon2id parameters. That is appropriate for a local
encrypted snapshot, but publishing the same wrap to a service would let anyone
who copied the server database run password guesses offline. Cognito, email
verification, API rate limits, and device bearer credentials cannot repair that
failure because none adds entropy to stolen ciphertext.

Fresh devices also need the same random `AccountRootKey`; creating another root
produces a different vault even if the user types the same passphrase. The
bootstrap format therefore has to transport the existing root without giving
the service either usable key material or a password-only verifier.

## Decision

Each cloud account has a client-generated 256-bit Account Secret. Its printable
V1 code is `SFO-A1-<64 uppercase hex>-<8 uppercase checksum hex>`. The checksum
is the first four bytes of SHA-256 over a domain label and the raw secret. It is
only typo detection and adds no entropy.

The Account Secret:

- is never sent to Safeory, Cognito, email, telemetry, or support;
- is not an HTTP bearer, login password, recovery code, or device credential;
- is shown only through an explicit setup/recovery disclosure flow; and
- has no `Debug`, `Display`, or serialization implementation in the crypto core.

The remotely stored V1 root envelope uses:

1. Argon2id v1.3 over the master passphrase and a fresh public 16-byte salt,
   using the bounded parameters carried by the envelope;
2. HKDF-SHA-256 Extract with the Account Secret as the secret salt and the
   Argon2id output as input key material;
3. HKDF Expand with a versioned domain label and account UUID; and
4. XChaCha20-Poly1305 over the 32-byte `AccountRootKey` with a fresh 24-byte
   nonce.

The authenticated data binds the format version, account UUID, all Argon2id
parameters, and passphrase salt. The decoder rejects unknown JSON fields, nil
or substituted account IDs, unsupported algorithms/versions, unbounded KDF
parameters, and any ciphertext length other than the exact 48 bytes expected
for a 32-byte root plus authentication tag.

This remote envelope is a separate type and domain from local passphrase,
recovery-kit, session-resume, item, attachment, sharing, and space-key wraps.
An enrolled device immediately converts an authenticated remote root into the
existing device-local passphrase wrap. Normal local unlock therefore remains
offline and does not require repeatedly entering or retaining the Account
Secret.

### Enrollment and migration rules

- First-device cloud setup generates the Account Secret inside WASM, requires
  the user to confirm its recovery copy, re-authenticates the local root with
  the master passphrase, and only then publishes the remote envelope as
  revision-fenced account bootstrap metadata.
- A fresh device must authenticate the hosted account, obtain a server device
  credential through an approved enrollment path, and supply the master
  passphrase plus Account Secret before it can accept synchronized ciphertext.
- An existing-device approval path may deliver an AccountRootKey/space-key
  capsule only after dual X25519/Ed25519 possession proof and explicit user
  approval. Its signed capsule and server state machine require a follow-up ADR
  or amendment; the current unauthenticated `sender_public` share field is not
  sufficient authorization.
- Existing local vaults migrate without changing item ciphertext: unlock,
  generate an Account Secret, create the remote root envelope, and retain the
  existing local root wrap.
- Passphrase or Account Secret rotation creates a new revision-fenced remote
  envelope. It does not claim to revoke plaintext or keys already obtained by
  a previously authorized device.

### Recovery rules

The existing recovery kit remains an independent high-entropy path to the same
root. After hosted-account recovery, a client that opens the recovery wrap may
generate a new Account Secret, publish a new remote root-envelope revision, and
revoke/rotate devices under the reviewed server recovery workflow. Hosted
identity recovery alone never releases a root or manufactures an Account
Secret.

## Security properties and limits

- A stolen server envelope without the Account Secret does not support
  password-only offline guessing.
- A stolen Account Secret without the passphrase still faces the configured
  Argon2id work factor for every guess.
- Compromise of both factors and the envelope reveals the root; this is an
  intentional two-factor key-combining design, not threshold cryptography.
- This does not protect an unlocked compromised client, malicious browser
  extension, keylogger, or exfiltrated recovery kit.
- The service can still deny service, suppress newer revisions, or serve stale
  metadata. Revision fencing, signed security events, and rollback detection
  are separate protocol requirements.
- The checksummed printable code is not a substitute for encrypted storage or
  safe handling.

## Consequences

- `vault-crypto` owns the immutable Account Secret and remote-root wire format;
  clients do not recreate the construction in TypeScript.
- `vault-wasm` can export an account-bound remote envelope from an unlocked,
  passphrase-reauthenticated vault and initialize a fresh local vault from it
  without exposing the root key to JavaScript.
- The shared sync contract carries the envelope as a non-tombstonable, 4 KiB
  `account_bootstrap` singleton whose object UUID equals its account UUID. The
  API exposes authenticated direct metadata discovery and applies its existing
  hash-and-revision CAS before storing a replacement body.
- Web and extension development enrollment implement first-device generation,
  confirmation, re-authentication, and durable publication; production identity
  integration and a pending-device approval state machine are still required
  before launch.
- A reviewed printable-kit experience, secure existing-device transfer, server
  recovery workflow, and external cryptographic review remain required.
