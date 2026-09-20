# ADR 0005: Space-Key Envelopes and Rotation

Date: 2026-09-20

## Status

Accepted.

## Context

Private, shared, and purpose spaces must be independently revocable without
rewrapping the AccountRootKey or exposing usable keys to the sync service. A
space may be readable on several devices belonging to different household
members. Removing a member or device must fence future writes under the old
generation, while acknowledging that plaintext and keys already delivered
cannot be recalled.

Safeory already has a reviewed X25519/HKDF/XChaCha20-Poly1305 device-envelope
primitive in `vault-sharing`. Creating a second public-key construction for
spaces would expand the cryptographic surface without adding a security
property.

## Decision

Every space has a random 256-bit `SpaceKey` and a positive, monotonically
increasing safe-integer generation. Initial provisioning starts at generation
1. Rotation creates a fresh random key and advances exactly one generation;
generation zero, overflow, skipped generations, and rollback are rejected.

One envelope is created per active authorized recipient device. Space envelopes
reuse `safeory:v2:share-wrap` with the distinct purpose `space-key:v1`. The
authenticated plaintext uses a fixed binary format and binds:

- space ID and key generation;
- membership ID and recipient device ID;
- sender device ID; and
- the 256-bit SpaceKey.

The same routing fields appear outside the ciphertext for authorization and
delivery. Opening requires caller-supplied expected values and checks that the
authenticated inner values match the outer routing context. This rejects
cross-space, cross-member, cross-device, and cross-generation transplantation.

The client prepares the new key and complete bounded envelope set before
publishing rotation metadata. The server must later atomically fence writes
under the old generation and publish the new envelopes with an idempotent
operation. The plaintext `SpaceKey` is client-only and is never serialized into
the sync contract or sent to the service.

The envelope's claimed X25519 sender remains context binding, not sender
authentication. Security-state mutations will require a separate
domain-separated Ed25519 signature and active-device authorization when the
remote mutation protocol is implemented.

## Consequences

- Private, shared, and purpose spaces can rotate independently.
- Removing access prevents future envelope delivery and future writes after the
  rotation fence, but cannot revoke keys or plaintext already copied.
- All authorized active devices need new envelopes for a rotation to complete.
- Offline clients that learn of a newer generation must reject old-generation
  writes and reconcile before publishing.
- Item and attachment keys remain random; space membership distributes the
  applicable space authority rather than replacing per-object encryption.
- Travel Mode can later remove selected SpaceKeys and reacquire them through
  authenticated sync without changing ciphertext bodies.
