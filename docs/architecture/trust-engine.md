# Trust Engine + Key Hierarchy

Status: cryptographic/policy foundation, encrypted per-item grant persistence,
stable local trusted-principal UUIDs, recipient-encryption device bindings, and
browser grant-planning UX are implemented. The local dual-key pairing/signing
verifier, durable browser recipient-device key store/responder, and persisted
signing-key binding are implemented; authenticated remote pairing transport,
AWS-coordinated timed release, and actionable release enforcement remain in
progress.

This document covers continuity authorization inside the combined-product
architecture. Household membership and ordinary collaboration are separate from
emergency/legacy policy; see `docs/architecture/combined-product.md`.

Implementation status: the policy model (`AccessPolicy`/`AccessGrant`,
conditions, wait periods, durations, private-forever, destruction) with
fail-closed local evaluation, plus Shamir 2-of-3 style threshold sharing and
sealed recovery-share envelopes, is implemented and tested in `vault-emergency`.
The canonical grant DTOs live in `vault-models` and are persisted inside each
encrypted `VaultItem` payload. The encrypted Emergency Card keeps continuity
contacts and access principals as separate typed collections: contacts never
become principals implicitly. Each principal has a stable UUID and may have
bounded device UUIDs carrying X25519 recipient-encryption public keys. An
explicitly paired device also carries a separate Ed25519 verification key
installed only after the dual-key possession proof succeeds. X25519 by itself
is not a signature or identity proof, and successful dual-key pairing proves
device-key possession rather than the person's real-world identity.
Removed principal/device UUIDs and removed paired-device Ed25519 verification
keys are retained as encrypted retirement tombstones. This prevents both old
grant identifiers and revoked signing identities from being rebound after
removal. Existing device UUIDs also cannot be rebound to another principal or
recipient/signing key; rotation is remove + add with a fresh device UUID and
fresh key pair.
Browser grant planning binds explicit principal UUIDs to the canonical per-record
scope `record`; advanced/custom/legacy rules are preserved rather than rewritten.
The portable local timed-release state machine is implemented in
`vault-emergency`: it models request creation, approvals, configured waiting
periods, release eligibility, finite-duration expiry, denial, revocation,
revision/policy invalidation, idempotent retries, and clock-rewind rejection.
It is currently a simulation/test primitive only — no shipped UI or server path
releases anything today. The integrated Plan Test/readiness UI is also still
pending. Each regular vault item can
also carry one encrypted `LegacyDisposition` planning preference
(`Unspecified`, `SelectedForLegacy`, `PrivateForever`, `DestroyOnDeath`). That
preference is not an `AccessPolicy`, grants no access, and triggers no automatic
release or deletion.

## Non-goals for V1

- No server-side decryption, no admin unlock, no whole-account legacy unlock.
- No automatic whole-vault AI access. No email/browser ingestion in V1.
- Password autofill belongs to the password-manager extension and is outside the
  Trust Engine scope. Banking connections and marketplaces remain non-goals.

## Identity and access layers

Safeory must not collapse these distinct concepts:

1. **Account identity** authenticates a person to the hosted service.
2. **Household membership and role** authorize account-management operations.
3. **Device identity** proves possession of encryption/signing keys and is
   independently revocable.
4. **Space membership** delivers current private/shared content keys.
5. **Per-item grants** narrow or extend access to a specific record.
6. **Continuity policy** controls future emergency/incapacity/death release.

A household `owner` or `organizer` does not automatically receive another
member's private-space keys. A full collaborator receives explicitly selected
shared-space membership, not implicit private access. A partial collaborator
receives only selected space/item envelopes and capabilities. A legacy
collaborator receives no current content key solely from the legacy
designation.

Server-side role checks and client-side cryptographic authorization are both
required. Passing one without the other fails closed.

## V1 scope (from product vision)

PRIVATE LIFE: documents, records, property, insurance, vehicles, possessions.
OWNERSHIP: receipts, warranty tracking, expiry/renewal reminders.
PEOPLE: trusted people, granular permissions (local model first).
PLAN: emergency access, waiting periods, selected legacy access, "if something
happens to me", plan test.
PRIVACY: client-side encryption, zero-knowledge server, local vault, E2EE
sharing envelope format, recovery kit, device management, portable export.

## Key hierarchy (target, backwards-compatible)

```text
Master passphrase + production Account Secret/device enrollment factor
  -> reviewed unlock/key-combining construction
  -> unwrap AccountRootKey (random 256-bit; passphrase-only v1 exists today)
       |-- private/shared space key envelopes (target)
       |     `-- per-item keys in that space
       |-- HKDF "lifevault:v1:item-wrap" -> current per-item keys (existing)
       |-- HKDF "safeory:v1:compartment-wrap:<space-id>" (target)
       |-- attachment keys
       `-- HKDF "safeory:v1:emergency-wrap" -> emergency capsule keys
```

Rules:

1. Existing `lifevault:v1:item-wrap` domain is immutable wire format. Do not
   rename. New compartments use `safeory:v1:*`.
2. ADR 0006 defines the high-entropy Account Secret, remote root envelope,
   local-format migration, and recovery invariants. The Rust/WASM foundation is
   implemented; server publication, enrollment/recovery coordination, signed
   device transfer, and external review remain. Cognito authentication does not
   replace client-side key protection.
3. All Ownership kinds reuse the existing per-item envelope. Item payload schema
   v4 introduced the required per-item legacy-planning disposition. Readers
   explicitly decode v1-v3 as `Unspecified`; older builds that only understand
   through v3 reject v4 rather than silently dropping the field. Later payload
   versions retain that boundary; the current write version and compatibility
   matrix are maintained in `docs/security/cryptography.md`. The SQLite schema
   did not change for the v4 payload-only migration.
   Compartments remain future work, with key separation requiring its own
   reviewed migration.
4. Per-item keys stay random per revision. Sharing wraps only the item key to
   the recipient device public key; never the root/compartment key.
5. Destroying a space/item key makes its blobs cryptographically
   inaccessible (secure-deletion principle). Cloud replicas are assumed.

6. Removing a collaborator prevents future envelope delivery and rotates the
   affected space key for future writes. It cannot revoke plaintext or keys
   already copied by a formerly authorized device; product copy must state this
   limitation.

7. Travel Mode is implemented at the space boundary by deleting non-travel
   space keys and local ciphertext from participating devices. Hiding UI rows is
   not Travel Mode.

## Ownership Graph (V1 minimal)

- The object is the node; local encrypted files are attachment objects. V1 nodes:
  `receipt`, `vehicle`, `possession`. Relations: explicit `links: Vec<Uuid>` on
  `VaultItem` (default empty, so v1/v2 payloads still decode).
- Link semantics: receipt <-> possession, policy <-> vehicle/property,
  service record <-> vehicle. Links are encrypted inside the item payload,
  never server-visible.
- Server-visible metadata gains nothing in V1 (see
  `docs/security/server-visible-metadata.md`).

## Trust Engine (V1 policy model, enforcement local-first)

Per-object policy (persisted in the encrypted item payload and evaluated locally):

```text
Policy {
  owner_only_default,
  grants: [ { trustee_id, what, permission, condition, wait_period,
              duration, approvals_required } ],
  private_forever: bool,       // never inheritable
  destruction: Option<LegacyCondition>, // destroy key under condition
}
```

Conditions V1: `normal | emergency | incapacity | death`.
`emergency` maps to the timer-coordinated release path. The portable core now
models timing and state transitions locally; the future durable coordinator will
enforce those transitions across devices but cannot decrypt (documented
limitation, no fake time-lock crypto claims).

V1 enforcement order: owner-only + explicit per-item grants + waiting period +
deny/revoke wins over release. 2-of-3 threshold uses standard Shamir sharing
over the capsule key, not custom crypto. The portable `vault-sharing` and
`vault-emergency` cores are implemented and tested; grant persistence and local
grant-management wiring are implemented in authenticated encrypted payloads.
The local pairing/signing foundation now uses a dedicated Ed25519 device key
separate from the X25519 recipient-encryption key. Pairing proves possession of
both keys against a one-time owner challenge and persists that binding to the
existing device UUID. This is device-key authentication, not human-identity
verification. Future release must still verify a domain-separated signed
request from an active paired device, resolve it to a principal UUID, and only
then evaluate policy. The local release state machine is implemented; remote
authenticated delivery and durable coordination remain pending.

## Remote protocol requirements

The production Trust Engine must add:

- authenticated invitations and explicit acceptance;
- owner-generated, one-time, expiring pairing challenges delivered through an
  account-authenticated channel;
- signed, domain-separated request/approval/deny/revoke messages;
- resolution of every signer to an active device and principal at decision time;
- durable PostgreSQL state transitions preserving the local state-machine
  invariants, with Valkey used only for retries and wakeups;
- notification of all active owner devices without disclosing record names;
- policy/revision fencing immediately before capsule delivery;
- tamper-evident minimal security events plus encrypted readable activity;
- trustee-side capsule receipt and decryption without exposing a usable key to
  the coordinator;
- operational rules for false death/incapacity claims, evidence handling,
  support intervention, abuse, appeals, and incident response.

Device-key possession is never equivalent to verified human identity. If
Safeory offers identity/evidence verification, its provider, assurance level,
retention, appeal path, and limitations require a separate reviewed design.

Plan Test uses isolated simulation identifiers and can never create a live
request, approval, capsule, notification, or server timer.

## Recovery (no backdoor)

Recovery kit (printable, high-entropy) + trusted device + 2-of-3 social
recovery. Support cannot decrypt. Recovery secret theft is catastrophic and
must be messaged as such in UI copy.

## What lands in code first

1. `ItemKind::Vehicle`, `ItemKind::Possession` + constructors — DONE.
2. Masked list projections + narrow reveal commands — DONE (same pattern as
   financial/property).
3. Recovery-kit wrap (`safeory:v1:recovery-wrap`, HKDF not Argon2) — DONE in
   `vault-crypto`, with threshold splitting (pinned `blahaj` fork carrying
   the RUSTSEC-2024-0398 fix, threshold >= 2)
   and E2EE recovery-share envelopes (`vault-sharing`) composed in
   `vault-emergency`; an end-to-end test reconstructs the root key from any
   2-of-3 sealed shares and decrypts vault items. Compartment-wrap key
   separation (`safeory:v1:compartment-wrap:<id>`) remains future work with
   its own review + migration.
4. Grants/waiting-period policy engine — DONE locally in `vault-emergency` as a
   fail-closed evaluator plus revision-fenced release-request state machine:
   owner-only default, explicit grants, approvals, waiting periods,
   finite-duration expiry, deny/revoke, private-forever and destruction winning
   over release. The policy is persisted per encrypted item;
   stable principal UUIDs, recipient-device registry, and browser planning UX are
   implemented. The local dual-key pairing/signing foundation plus native/WASM
   owner-side challenge/proof verification APIs are implemented. The browser now
   persists recipient X25519+Ed25519 private material encrypted under a
   non-extractable Web Crypto wrapping key, exposes only a public registration
   bundle, answers one-shot challenges through WASM, and lets the owner verify and
   persist the Ed25519 binding. Remote invitation/pairing transport, product
   release UI, trustee delivery, and the durable server coordinator remain future
   work. Local waiting-period/duration transition semantics are now executable
   and tested rather than declarative-only.
5. Per-record legacy planning disposition — DONE locally as encrypted payload
   metadata with exact-revision client operations and reader UX. It is deliberately separate
   from the Trust Engine policy object until real release/deletion enforcement is
   implemented.
