# Trust Engine + Key Hierarchy

Status: cryptographic/policy foundation, encrypted per-item grant persistence,
stable local trusted-principal UUIDs, recipient-encryption device bindings, and
browser grant-planning UX are implemented. The local dual-key pairing/signing
verifier and persisted signing-key binding are implemented; recipient-side
durable key storage/responder, AWS-coordinated timed release, and actionable
release enforcement remain in progress.

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
The timed-release state machine is still pending — no UI or server path can
release anything today. The local Plan
Test checks only locally enforceable preparedness (Emergency Card
completeness and recovery-key verification) and reports aggregate local legacy
planning coverage; it is not a release simulation. Each regular vault item can
also carry one encrypted `LegacyDisposition` planning preference
(`Unspecified`, `SelectedForLegacy`, `PrivateForever`, `DestroyOnDeath`). That
preference is not an `AccessPolicy`, grants no access, and triggers no automatic
release or deletion.

## Non-goals for V1

- No server-side decryption, no admin unlock, no whole-account legacy unlock.
- No automatic whole-vault AI access. No email/browser ingestion in V1.
- Password autofill belongs to the password-manager extension and is outside the
  Trust Engine scope. Banking connections and marketplaces remain non-goals.

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
Master passphrase
  -> Argon2id KEK
  -> unwrap AccountRootKey (random 256-bit, existing v1 format)
       |-- HKDF "lifevault:v1:item-wrap" -> per-item keys (existing)
       |-- HKDF "safeory:v1:compartment-wrap:<compartment-id>"
       |     -> per-compartment wrap key -> per-item keys in that compartment
       |-- HKDF "safeory:v1:emergency-wrap" -> emergency capsule keys (Phase 3)
```

Rules:

1. Existing `lifevault:v1:item-wrap` domain is immutable wire format. Do not
   rename. New compartments use `safeory:v1:*`.
2. All Ownership kinds reuse the existing per-item envelope. Item payload schema
   v4 introduced the required per-item legacy-planning disposition. Readers
   explicitly decode v1-v3 as `Unspecified`; older builds that only understand
   through v3 reject v4 rather than silently dropping the field. Later payload
   versions retain that boundary; the current write version and compatibility
   matrix are maintained in `docs/security/cryptography.md`. The SQLite schema
   did not change for the v4 payload-only migration.
   Compartments remain future work, with key separation requiring its own
   reviewed migration.
3. Per-item keys stay random per revision. Sharing wraps only the item key to
   the recipient device public key; never the root/compartment key.
4. Destroying a compartment/item key makes its blobs cryptographically
   inaccessible (secure-deletion principle). Cloud replicas are assumed.

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
`emergency` maps to the planned timer-coordinated release path; the future
coordinator will enforce timing but cannot decrypt (documented limitation, no
fake time-lock crypto claims).

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
then evaluate policy. Timed-release coordination remains pending.

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
4. Grants/waiting-period policy engine — DONE locally in `vault-emergency` as the
   local fail-closed simulation/test harness (`evaluate`): owner-only
   default, explicit grants, approvals, waiting periods, private-forever and
   destruction winning over release. The policy is persisted per encrypted item;
   stable principal UUIDs, recipient-device registry, and browser planning UX are
   implemented. The local dual-key pairing/signing foundation plus native/WASM
   owner-side challenge/proof verification APIs are implemented. The shipped
   browser UI deliberately does not expose pairing until recipient-side durable
   private-key storage and a pairing responder exist; the release coordinator
   also remains future work.
   Waiting periods/durations therefore remain declarative.
5. Per-record legacy planning disposition — DONE locally as encrypted payload
   metadata with exact-revision client operations and reader UX. It is deliberately separate
   from the Trust Engine policy object until real release/deletion enforcement is
   implemented.
