# Safeory Architecture Overview

Safeory's target is a zero-knowledge consumer product combining 1Password
Individual/Families-style credential management with Trustworthy-style
household organization, collaboration, continuity, and legacy planning. The
authoritative combined-product contract is
`docs/architecture/combined-product.md`; this overview describes the system
boundaries that support it.

## Security objective

Safeory is a local-first encrypted vault. Plaintext and usable vault keys stay on authorized user devices. Backend infrastructure stores ciphertext and the minimum metadata needed to authenticate devices, synchronize opaque objects, and coordinate emergency-access policy.

A stolen backend database and object store must be insufficient by themselves to directly recover readable vault contents.

## Layering

```text
React web app                    Browser extension
      \                           /
       \                         /
        +---- typed contracts ---+
                   |
                   v
              vault-wasm
          /        |        \
 vault-models  vault-crypto  vault-storage (browser MemStore)
      |            |               |
      +------------+---------------+
                   |
                   | ciphertext + minimum metadata only
                   v
             AWS production edge
          CloudFront / Route 53 / ACM
                   |
                   v
             Rust HTTP API
            |-- RDS PostgreSQL
            |-- Amazon S3
            |-- Cognito / SES
            `-- Valkey / CloudWatch
```

Dependency direction points inward toward portable Rust crates. Security-domain crates do not depend on React, browser UI types, a particular reverse proxy, object-store vendor, or cloud-provider SDK type.

## Product-domain boundaries

The target domain is deliberately broader than the currently implemented
single-owner vault:

```text
Account (sign-in, subscription, devices)
  -> Household (members, roles, collaborators, security events)
       -> Space (private/shared/travel/purpose key boundary)
            -> Item (independent revision and content key)
                 -> Attachment / reminder / history
```

Server roles authorize operations but do not make ciphertext readable. Content
access also requires a client-held space or item key. Private spaces are never
implicitly readable by household organizers. Full, partial, and legacy
collaboration map to explicit space/item key delivery rather than a boolean
account-wide access flag.

The current local vault migrates to one account, one household, and one private
space. The migration and independently rotatable space/compartment key hierarchy
must land before shared-family spaces, Travel Mode, or production collaboration
are considered complete.

## Local-first ownership

- Browser clients persist ciphertext snapshots locally: IndexedDB for the web
  session and browser-managed extension storage for the extension background vault.
- Sensitive item fields are serialized and encrypted inside the Rust/WASM
  boundary before browser persistence.
- `vault-storage` retains its SQLite implementation for native library utilities,
  tests, migration/backup formats, and future non-browser adapters; it is not a
  shipping client surface.
- Search is performed locally after unlock. Search indexes containing plaintext secrets are not persisted in Phase 0.
- Network synchronization is secondary and may be unavailable without preventing core local vault operation.

The browser build uses the same crypto/domain model through `vault-wasm`, with a
ciphertext-only `MemStore` snapshot persisted in IndexedDB. Browser snapshot
restore validates the shared storage schema/object-count/revision/encoded-size
bounds and duplicate object IDs before accepting the encrypted state. Local web
mutations are serialized through mutation -> snapshot -> IndexedDB CAS; if the
durable save fails after the WASM mutation, the session fails closed, locks,
poisons itself, clears plaintext-derived UI state, and requires reload from the
durable IndexedDB snapshot rather than continuing on divergent memory.

For ordinary same-tab browser reloads, the web client can preserve an already
unlocked session without persisting the master passphrase or raw root key. WASM
creates a fresh 256-bit session-resume secret and a root-key envelope under a
dedicated HKDF/AAD domain; the host keeps that reload capability in
`sessionStorage`, rotates it after a successful reload resume, and deletes it on
explicit lock. Non-reload navigations do not consume the capability. The
capability remains same-origin-JavaScript readable and is therefore treated as
bearer-equivalent while the tab session is unlocked.

The browser extension keeps the unlocked WASM vault in its background worker.
Untrusted page content receives only exact-origin credential summaries after a
trusted Safeory click. Discovery is throttled per tab+origin, and a short-lived
authorization bound to that same context is consumed once before the selected
credential is decrypted for fill.

## Initial vertical slice

```text
master passphrase
  -> Argon2id KEK
  -> unwrap random AccountRootKey
  -> derive item-wrap context key
  -> unwrap random per-item key
  -> decrypt authenticated item payload
```

Creation is the reverse path. The database receives only salts, nonces, ciphertexts, opaque IDs, revisions, and format metadata.

This is the implemented local unlock path. Before remotely stored wraps become a
production dependency, a reviewed ADR must add a high-entropy Account Secret or
equivalent device-enrollment factor to resist password-only offline attacks after
a server-data compromise. Cognito proves account identity; it does not replace
client-side key protection.

## Platform boundaries

`vault-platform` defines capabilities such as secure key storage, biometrics, filesystem, clipboard, clock, randomness, and network transport. Platform-specific implementations live outside the security-domain crates. Phase 0 uses the OS CSPRNG directly and does not yet persist root keys in OS secure storage.

## Backend shape (in implementation)

AWS is the production deployment target. `docker-compose.yml` remains a local
development/integration stack that mirrors the service boundaries without being
the production topology. The detailed AWS launch and scale-up plan is in
`docs/architecture/aws.md`.

- Rust HTTP API: authentication coordination, device registration, opaque sync
  metadata, emergency policy, trusted-person workflow, and presigned/object
  storage mediation where needed.
- RDS PostgreSQL: authoritative server-visible account, device, revision,
  idempotency, audit, and emergency-workflow state.
- Amazon S3: encrypted records, attachments, and other ciphertext blobs.
  Standard S3-compatible APIs remain the portability boundary used by the API;
  Garage is retained only in the local Docker integration stack.
- Cognito User Pools: hosted account identity/session/email-verification layer.
  Safeory device credentials and X25519 keys remain separate cryptographic
  device identity.
- Valkey: ephemeral rate-limit counters, retry queues, worker coordination, and
  short-lived job state. It may run on the launch API host and later move to
  ElastiCache. Durable security decisions stay in PostgreSQL.
- SES: account/security notifications with no vault content.
- CloudFront + Route 53 + ACM: public web/API edge, DNS, and TLS. The static web
  export is served from a private S3 origin; `/api/*` is routed to the API
  origin under the same public origin contract.
- ECR, IAM/Secrets Manager/SSM, and CloudWatch: versioned API images,
  short-lived service authorization/secrets, and operational visibility.

No backend component receives usable vault decryption keys or vault plaintext.
Opaque AWS-hosted synchronization is in implementation; this architecture
describes the intended server-visible contract and deployment boundaries, not a
claim that the complete sync/auth/device HTTP endpoint surface has shipped.

## Cross-cutting protocols still required

The following are architecture deliverables rather than UI tasks:

- versioned account/device/household/space bootstrap and key-envelope delivery;
- offline mutation, incremental sync, conflict, tombstone, attachment, and
  client-compatibility rules;
- remote revocation and space-key rotation;
- append-only minimal security events plus encrypted human-readable activity;
- invitation, SecureLink, trustee-request, approval, release, and expiry
  protocols;
- private-local versus opt-in cloud reminder scheduling;
- zero-knowledge-compatible ingestion, Inbox review, and local/private document
  extraction.

Their detailed target behavior lives in
`docs/architecture/combined-product.md`; the opaque object and household-key
distribution contract is expanded in `docs/architecture/sync.md`. Features that
depend on these protocols must not be represented as complete merely because
their local model or cryptographic primitive exists.
