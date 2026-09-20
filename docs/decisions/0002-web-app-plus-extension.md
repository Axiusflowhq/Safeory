# ADR 0002: Web App + All-in-One Browser Extension

Date: 2026-09-19

## Status

Accepted.

## Context

Safeory combines password management with a private life-continuity vault. The product needs one deep-management surface and one always-present browser surface while preserving a single client-side cryptographic implementation and a narrow server-visible metadata boundary.

The parity boundary is the consumer product defined in
`docs/architecture/combined-product.md`: 1Password Individual/Families-style
credential management plus Trustworthy-style household organization,
collaboration, continuity, and legacy planning.

## Decision

- The user-facing product has two browser surfaces: the React web app in `apps/web` and the MV3 browser extension in `apps/extension`.
- `vault-wasm` exposes the portable Rust crypto/domain model to both surfaces. Usable vault keys remain in WASM memory; JavaScript receives ciphertext snapshots, redacted projections, or explicitly requested single-record plaintext.
- Browser persistence uses ciphertext snapshots through IndexedDB for the web app and extension-managed browser storage for the extension.
- Browser platform capabilities use browser APIs such as the Clipboard API and File System Access API where supported, with explicit user gestures and documented fallbacks.
- Backend services coordinate accounts, devices, opaque encrypted objects, and future emergency-policy state without receiving usable vault decryption keys or vault plaintext.

## Consequences

- Web and extension security boundaries, CSP, sender authentication, exact-origin autofill, browser-storage races, and WASM memory handling are first-class product concerns.
- Shared UI and contracts are extracted only where reuse is demonstrated; security-domain behavior remains in portable Rust crates or the narrow contracts layer.
- Native-only SQLite utilities can remain available to core tests/tools without defining a shipping application surface.
- Browser limitations around clipboard lifetime, filesystem APIs, and background execution must fail closed or be stated explicitly rather than hidden behind platform assumptions.
- Responsive web is the committed mobile surface, but this ADR does not provide
  native mobile autofill, dependable background scanning/reminders, universal
  desktop autofill, or hardware-backed biometric isolation. Safeory must not
  claim those capabilities until a later ADR adds an appropriate native client.
- Web and extension initially keep separate ciphertext stores. The product is
  not a combined cross-device system until the reviewed household/space model
  and sync protocol converge those stores.
