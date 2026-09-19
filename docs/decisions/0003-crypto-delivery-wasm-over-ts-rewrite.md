# ADR 0003: Deliver the Rust Core to the Browser via WASM, Not a TypeScript Rewrite

Date: 2026-09-19

## Status

Accepted.

## Context

ADR 0002 moved the product to web app + browser extension, which means vault
cryptography must run in the browser. Three options were considered:

1. **WASM the existing Rust core** (`vault-crypto`, `vault-models`,
   `vault-sharing`, `vault-emergency` behind a new `vault-wasm` crate).
2. **Rewrite client crypto in TypeScript on WebCrypto.** Rejected: WebCrypto
   offers neither Argon2id nor XChaCha20-Poly1305, forcing PBKDF2 + AES-GCM —
   a weaker KDF and a downgrade that breaks the immutable wire format
   (`docs/architecture/trust-engine.md` rule 1) and requires migrating every
   existing vault. It also discards the tested Rust core, the Shamir/policy
   engine, and the negative security test suite, and doubles the
   implementation/audit surface permanently.
3. **TypeScript app with JS crypto libraries** (libsodium.js, hash-wasm).
   Rejected: those libraries are themselves WASM builds, so this adopts WASM
   anyway while substituting a foreign, less-scrutinized implementation and
   still requiring the full vault-logic rewrite.

## Decision

Compile the portable Rust core to `wasm32-unknown-unknown` via a new
`vault-wasm` wasm-bindgen crate. `getrandom` uses its `wasm_js` backend.
Keys remain in WASM linear memory and are zeroed on lock; only ciphertext and
redacted projections cross the JS/TS boundary. The refactor budget is spent
on the storage trait + IndexedDB backend and the `packages/ui` extraction —
not on re-implementing cryptography.

## Consequences

- One crypto implementation, one audit surface; existing Rust tests and the
  `cargo audit`/`deny` gates keep protecting the shipped crypto.
- The wire format (`lifevault:v1:item-wrap`, `safeory:v1:*`) is preserved;
  existing vaults open unchanged in web and extension.
- Cost: WASM bundle size and a JS<->WASM boundary that needs its own
  threat-model section and `wasm-bindgen-test` coverage (tracked in
  `docs/ROADMAP.md` Phase 1 and Phase 8).
