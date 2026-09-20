# Dependency Risk Register

Verified: 2026-09-20

This register records security-relevant direct dependencies and narrowly scoped policy exceptions that require ongoing review. It is not an allowlist of vulnerabilities.

## New direct crypto dependency: `x25519-dalek` 2.0.1 (pinned)

- Pulled in by `vault-sharing` for the X25519 device-share envelope
  (`safeory:v2:share-wrap`) and by `vault-models` to reject non-contributory
  recipient-encryption public keys before they enter the trusted-principal
  registry. Pinned `=2.0.1` with `static_secrets`
  (default features kept on so the `zeroize` drop handling for `StaticSecret`
  / `SharedSecret` stays active — verified against the vendored source; the
  memory-handling section of `cryptography.md` depends on this).
- `vault-sync` reuses the `vault-sharing` envelope for the `space-key:v1`
  purpose; it does not add another curve implementation or public-key
  construction.
- No custom curve code: ephemeral keygen, DH, and contributory checks all come
  from the audited crate; Safeory only adds key encoding/bounds, HKDF key
  separation, and AEAD envelope framing with reviewed RustCrypto primitives.
- Watch items: keep pinned; re-verify `zeroize`-as-default on every upgrade;
  `cargo audit`/`cargo deny` must stay green (any new advisory follows the
  review rule below, not a silent ignore).

## New direct crypto dependency: `ed25519-dalek` 3.0.0 (pinned)

- Pulled in by `vault-sharing` for the dedicated trusted-device signing identity
  and by `vault-models` to validate persisted Ed25519 verification keys. It is
  pinned `=3.0.0`; Safeory uses raw 32-byte verification keys, 64-byte
  signatures, `verify_strict`, and the crate's weak-key check. The signing key is
  role-separated from the existing X25519 recipient-encryption key.
- Pairing signs a fixed binary, domain-separated transcript after the candidate
  device decrypts a one-time X25519 challenge. This proves possession of both
  private keys at pairing time; it does not verify a human identity and does not
  make the existing X25519 share-envelope sender field a signature.
- The dependency brings `curve25519-dalek` 5 alongside `x25519-dalek` 2.0.1's
  older curve25519 line. That duplicate is intentional for now: deduplicating by
  upgrading X25519 would change a separately reviewed secret/zeroization path and
  must not be bundled into the signing change merely to reduce the graph.
- Watch items: keep pinned; do not enable legacy/hazmat features; review any
  Ed25519 or curve25519 advisory immediately; re-run `cargo audit` and `cargo
  deny` on every upgrade.

## New direct crypto dependency: `blahaj` 0.6.0 (pinned)

- Pulled in by `vault-emergency` for Shamir threshold sharing of capsule keys
  and recovery secrets. Pinned `=0.6.0` with `zeroize_memory` so share buffers
  are cleared.
- `blahaj` is the maintained fork of the unmaintained `sharks` crate,
  carrying the fix for RUSTSEC-2024-0398 (biased Shamir polynomial
  coefficients in `sharks` <= 0.5.0). The vulnerable crate was never added:
  the advisory fired on first `cargo deny` run and the fork was chosen
  instead, per the review rule below. No custom threshold crypto anywhere in
  the tree; grant thresholds below 2 are rejected at the API boundary.
- Watch items: same as above — pinned, audited via `cargo audit`/`cargo deny`,
  no silent ignores.

## API transport dependencies

- `safeory-api` adds pinned `sqlx` 0.9.0 for PostgreSQL, `redis` 1.7.0 for
  Valkey, and `axum`/`tokio` for the HTTP runtime. The API is intentionally a
  coordination/metadata service and contains no vault decryption path.
- SQLx's Rustls transport graph introduces `ring` 0.17.14,
  `rustls-webpki` 0.103.15, and `untrusted` 0.9.0 under the ISC license, plus
  `webpki-roots` 1.0.9 under CDLA-Permissive-2.0. Redis introduces
  `xxhash-rust` 0.8.18 under BSL-1.0.
- `deny.toml` allows those licenses only for those exact crate versions rather
  than widening the workspace-wide allowlist. The exceptions are licensing
  approvals, not advisory ignores; vulnerability checks remain unchanged.
- Watch items: re-review these exact exceptions whenever SQLx/Rustls/Redis is
  upgraded or the API transport graph changes.

## Review rule

Do not add new advisory ignores merely to make CI green. For any new finding:

1. determine the direct/transitive path,
2. check whether a safe compatible upgrade exists,
3. assess whether the affected API is reachable,
4. document mitigation and residual risk here,
5. remove the dependency or upgrade when practical.
