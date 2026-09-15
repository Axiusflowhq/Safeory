# Dependency Risk Register

Verified: 2026-09-15

This register records security-relevant dependency findings that cannot currently
be removed without abandoning the latest stable Tauri 2 desktop stack. It is not
an allowlist of vulnerabilities and must be revisited on every Tauri upgrade.

## Current RustSec findings

`cargo audit` 0.22.2 currently exits successfully with seven informational
warnings in the resolved Rust dependency graph and no failing vulnerability
advisories.

### RUSTSEC-2024-0429 — `glib` 0.18.5 soundness issue

- Source: transitive Linux desktop dependency through Tauri/GTK.
- RustSec classifies this as `INFO Unsound` and lists `glib >=0.20.0` as patched.
- The affected API is `glib::VariantStrIter` iteration. Safeory does not depend
  on `glib` directly or call this API directly.
- Residual risk: if the affected path is exercised by the shell stack, undefined
  behavior/crash is possible. A renderer or shell crash is not treated as a safe
  place for vault secrets.
- Mitigation: keep all security/business logic in portable Rust core crates, keep
  Tauri narrow, track Tauri/gtk-rs upgrades, and remove this exception as soon as
  the stable Tauri graph accepts a patched `glib`.

### Unmaintained transitive crates

The current stable Tauri graph also includes RustSec informational advisories for:

- RUSTSEC-2024-0370 (`proc-macro-error` 1.0.4), through the Linux GTK stack.
- RUSTSEC-2025-0075, -0080, -0081, -0098, and -0100 (`rust-unic` family),
  through Tauri's `urlpattern` dependency.

RustSec provides no patched version for `proc-macro-error`; the affected
`rust-unic` crates are likewise reported as unmaintained. These IDs are explicitly
annotated in `deny.toml` so `cargo deny` does not silently start failing on known,
reviewed informational advisories. `cargo audit` remains a separate CI gate and
continues to print them on every run.

## New direct crypto dependency: `x25519-dalek` 2.0.1 (pinned)

- Pulled in by `vault-sharing` for the ephemeral-static X25519 device-share
  envelope (`safeory:v1:share-wrap`). Pinned `=2.0.1` with `static_secrets`
  (default features kept on so the `zeroize` drop handling for `StaticSecret`
  / `SharedSecret` stays active — verified against the vendored source; the
  memory-handling section of `cryptography.md` depends on this).
- No custom curve code: ephemeral keygen, DH, and contributory checks all come
  from the audited crate; Safeory only adds HKDF key separation and
  AEAD envelope framing with reviewed RustCrypto primitives.
- Watch items: keep pinned; re-verify `zeroize`-as-default on every upgrade;
  `cargo audit`/`cargo deny` must stay green (any new advisory follows the
  review rule below, not a silent ignore).

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

## Review rule

Do not add new advisory ignores merely to make CI green. For any new finding:

1. determine the direct/transitive path,
2. check whether a safe compatible upgrade exists,
3. assess whether the affected API is reachable,
4. document mitigation and residual risk here,
5. remove the dependency or upgrade when practical.
