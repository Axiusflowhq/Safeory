# Trust Engine + Key Hierarchy (V1 Spec, Pre-Code)

Status: design frozen before React screens. Code follows this doc, not the reverse.

Implementation status: the policy model (`AccessPolicy`/`AccessGrant`,
conditions, wait periods, durations, private-forever, destruction) with
fail-closed local evaluation, plus Shamir 2-of-3 style threshold sharing and
sealed recovery-share envelopes, is implemented and tested in
`vault-emergency` (pure core, no IPC yet). Grant persistence inside item
payloads, trusted-person UX, and the timed-release state machine are still
pending — no UI or server path can release anything today.

## Non-goals for V1

- No server-side decryption, no admin unlock, no whole-account legacy unlock.
- No automatic whole-vault AI access. No email/browser ingestion in V1.
- No password autofill, banking connections, marketplaces.

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
2. Phase 1 (this increment): all new Ownership kinds reuse the existing
   per-item envelope. No format bump. Compartments land as policy labels first,
   key separation second, with migration that re-wraps without deleting old
   records on failure.
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

Per-object policy (encrypted payload, evaluated in Rust core):

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
`emergency` maps to timer-coordinated release; the server enforces timing but
cannot decrypt (documented limitation, no fake time-lock crypto claims).

V1 enforcement order: owner-only + explicit per-item grants + waiting period +
deny/revoke wins over release. 2-of-3 threshold uses standard Shamir sharing
over the capsule key, not custom crypto. Library choice + audit happens before
`vault-sharing`/`vault-emergency` leave stub state.

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
4. Grants/waiting-period policy engine — DONE in `vault-emergency` as the
   local fail-closed simulation/test harness (`evaluate`): owner-only
   default, explicit grants, approvals, waiting periods, private-forever and
   destruction winning over release. Session/IPC wiring and the Durable
   Object release coordinator come after this.
