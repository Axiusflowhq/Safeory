# Dependency Baseline

Verified: 2026-09-15

Safeory uses stable production releases only for core dependencies. Alpha, beta, canary, RC, and nightly releases are excluded unless an ADR explicitly approves an exception.

| Dependency | Version | Verified date | Official source | Reason |
| --- | ---: | --- | --- | --- |
| Rust | 1.98.1 | 2026-09-15 | rust-lang.org releases | Primary security/business core toolchain |
| pnpm | 12.4.1 | 2026-09-15 | npm registry / pnpm | Reproducible JS workspace manager |
| TypeScript | 7.0.2 | 2026-09-15 | npm registry | Strict frontend/contracts typing |
| React / React DOM | 19.2.8 | 2026-09-19 | npm registry | Browser presentation layer |
| Vite | 8.3.0 | 2026-09-15 | npm registry / vite.dev | Frontend build/dev tooling |
| @vitejs/plugin-react | 6.1.1 | 2026-09-15 | npm registry | React integration for Vite |
| Tailwind CSS / @tailwindcss/vite | 4.3.3 | 2026-09-15 | npm registry | UI styling and Vite integration |
| @base-ui/react | 1.8.0 | 2026-09-15 | npm registry / base-ui.com | Accessible primitives under shadcn |
| shadcn CLI | 4.21.0 | 2026-09-15 | npm registry / ui.shadcn.com | Source-owned component generator |
| @solar-icons/react | 2.2.0 | 2026-09-15 | npm registry / Solar Icons | Product-specific React icons |
| @hugeicons/react | 1.1.10 | 2026-09-15 | npm registry / Hugeicons | React renderer for Hugeicons |
| @hugeicons/core-free-icons | 4.3.3 | 2026-09-15 | npm registry / Hugeicons | Free Hugeicons data used by the React renderer |
| Oxlint | 1.83.0 | 2026-09-15 | npm registry / oxc.rs | TypeScript/React linting without an incompatible TypeScript peer ceiling |
| Prettier | 3.9.6 | 2026-09-15 | npm registry / prettier.io | Deterministic frontend formatting |
| argon2 | 0.6.0 | 2026-09-15 | crates.io / RustCrypto | Argon2id passphrase KDF |
| chacha20poly1305 | 0.11.0 | 2026-09-15 | crates.io / RustCrypto | XChaCha20-Poly1305 AEAD |
| hkdf | 0.13.0 | 2026-09-15 | crates.io / RustCrypto | Domain-separated key derivation |
| sha2 | 0.11.0 | 2026-09-15 | crates.io / RustCrypto | HKDF hash function |
| zeroize | 1.9.0 | 2026-09-15 | crates.io | Best-effort secret memory clearing |
| getrandom | 0.4.3 | 2026-09-15 | crates.io / rust-random | OS CSPRNG access |
| rusqlite | 0.40.2 | 2026-09-15 | crates.io | Local SQLite storage |
| serde | 1.0.229 | 2026-09-15 | crates.io | Versioned serialization |
| serde_json | 1.0.151 | 2026-09-15 | crates.io | Initial encrypted payload encoding |
| uuid | 1.26.1 | 2026-09-15 | crates.io | Opaque object identifiers |
| thiserror | 2.0.20 | 2026-09-15 | crates.io | Explicit typed errors |
| wasm-bindgen | 0.2.106 | 2026-09-19 | crates.io | Rust->WASM/JS bindings for the browser vault core (`vault-wasm`) |
| vite-plugin-wasm | 3.5.0 | 2026-09-19 | npm registry | Bundle the vault-wasm `.wasm` artifact in the web app and extension background worker |
| @types/chrome | 0.1.13 | 2026-09-19 | npm registry | MV3 extension API types (content/background/popup messaging) |

## Verification notes

- Rust 1.98.1 is pinned instead of 1.98.0 because 1.98.1 fixes a vtable-generation miscompilation.
- `@base-ui-components/react` is deprecated; new code uses `@base-ui/react`.
- shadcn currently defaults new projects to Base UI; this repository still pins `--base base` explicitly.
- shadcn `iconLibrary` is pinned to `hugeicons`; product UI may also use Solar Icons. Lucide and other icon libraries are intentionally not dependencies.
- Vite 8.3.0 is the current stable verified release.
- `typescript-eslint` 8.70.0 currently declares TypeScript `<6.0.0`, so it is not compatible with the verified stable TypeScript 7.0.2 baseline. Safeory keeps TypeScript current and uses Oxlint rather than downgrading the compiler.

## Security review process

1. Verify each stable version from the official registry/project source.
2. Check release recency, compatibility, and published advisories.
3. Run `cargo audit` after generating `Cargo.lock`.
4. Run `pnpm audit --prod` after generating `pnpm-lock.yaml`.
5. Run `cargo deny check` in CI for advisories, licenses, sources, and duplicate policy.
6. Record any exception in an ADR; never suppress an advisory silently.

Cryptographic rationale and format decisions are documented in `docs/security/cryptography.md`.
