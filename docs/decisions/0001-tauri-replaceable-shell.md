# ADR 0001: Tauri Is a Replaceable Desktop Shell

Date: 2026-09-15

## Status

Accepted.

## Context

Safeory needs a desktop shell now, but cryptography, storage, sync, sharing, and emergency-access rules must survive a future move to another host or mobile platform. Putting business/security logic in Tauri commands would couple the security boundary to a WebView framework and make independent testing harder.

## Decision

- Portable Rust crates own business and security behavior.
- Tauri depends on `vault-core`; `vault-core` never depends on Tauri.
- IPC is narrow, typed, and domain-specific.
- No generic shell execution, arbitrary filesystem read, arbitrary process spawn, arbitrary HTTP proxy, or arbitrary SQL command is exposed to the renderer.
- Platform services are expressed behind `vault-platform` capability interfaces.

## Consequences

The adapter contains some translation boilerplate, but core behavior can be tested without a WebView and reused by another host. Renderer compromise is limited to explicitly exposed domain operations rather than generic machine capabilities.
