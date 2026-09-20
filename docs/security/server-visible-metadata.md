# Server-Visible Metadata

Principle: if the backend does not need a field in plaintext to authenticate, route, synchronize, rate-limit, or coordinate a security workflow, encrypt it.

This rule is deployment-independent. Production is hosted on AWS: a Rust HTTP
API with Cognito account identity, RDS PostgreSQL, S3 ciphertext storage,
Valkey/worker coordination, SES, and CloudFront/Route 53/ACM. Using managed AWS
services does not make additional vault metadata safe to expose in plaintext.

Opaque AWS-hosted synchronization is currently **in implementation**. The
metadata classes below define the permitted server-visible contract; they do
not assert that the complete sync/auth/device API endpoint surface is finished.
Until those endpoints and protocol tests are complete, client-local vault data
remains authoritative for the implemented browser flows.

## Intended plaintext metadata

| Field class | Why required | Leakage |
| --- | --- | --- |
| Account ID | Authentication/routing | Account existence/activity correlation |
| Verified email | Login/security notifications | Email address |
| Device ID/status/public key | Authorization/revocation | Number/timing of devices |
| Household ID + opaque membership/role | Collaboration authorization | Household size, roles, and relationship timing |
| Space ID + opaque membership/version | Route key envelopes and enforce revocation | Number of spaces and membership graph |
| Opaque object ID | Sync routing/idempotency | Object count/activity |
| Object revision/tombstone | Conflict detection/deletion | Update timing/history shape |
| Ciphertext size | Storage/protocol framing | Approximate item size |
| Required timestamps | Sync ordering/rate controls | Activity timing |
| Trusted relationship opaque IDs | Route invitation/emergency workflows | Relationship existence |
| Emergency state/policy timing | Enforce request/wait/release workflow | Emergency relationship timing |
| Audit event type + opaque refs | Security history | Security-event timing/type |
| SecureLink ID, audience mode, expiry, revoked state | Enforce external-share access | Sharing timing and audience shape |
| Opt-in reminder next-delivery time + opaque ID | Schedule a generic wake/notification | Reminder existence and timing |

RDS PostgreSQL is the durable source of truth for these fields. Amazon S3
receives ciphertext blobs plus the minimum opaque object key/framing
metadata needed to store and retrieve them. Valkey may temporarily hold opaque
job IDs, rate-limit keys, retry counts, and deduplication tokens; it must not be
used as the only durable record of account authorization or emergency-policy
state. Cognito receives only account identity/session information needed for
hosted authentication. SES receives only the destination address and non-vault
notification content required to deliver a security/account message.

## Normally encrypted metadata

- Vault names.
- Item titles/categories when routing does not require them.
- Institution/provider names.
- Document names.
- Property names/locations.
- Trusted-person labels such as "wife" or "lawyer" when not operationally required.
- Emergency instructions and granted item/category descriptions.
- Household member display names and relationship labels.
- Space names, purposes, and travel-safe labels.
- Reminder title, recurrence rule, notes, linked item, and category.
- Inbox filenames, extracted fields, summaries, classifications, and filing
  suggestions.
- Human-readable activity details, item titles, and change descriptions.

## Explicit exclusions

The API, Cognito, RDS PostgreSQL, S3, Valkey, SES pipeline, CloudFront, and
their logs must never intentionally receive plaintext vault bodies, passwords,
recovery codes, attachment contents, emergency instructions, AccountRootKey,
per-item keys, or usable attachment keys. Ciphertext bodies may transit the API
or proxy when protocol design requires it, but request-body logging is disabled.

Browser-local hardening does not widen this server boundary: bounded `MemStore`
snapshot validation operates on ciphertext on the client, IndexedDB durability
poison/reload handling is client-local, and extension credential discovery/fill
authorization is enforced between the content script and extension background
worker. None of those controls require sending additional vault metadata to the
AWS backend.

## Reminder modes

Private-local reminders disclose no schedule or content. They work only through
authorized clients and cannot promise delivery while every client is offline.

Cloud-scheduled reminders are explicit opt-in. The service may receive only the
next delivery instant, opaque reminder ID, account/household routing ID,
delivery channel, and delivery state. Email/push text is generic and contains no
title, category, linked resource, date description, note, or field value. The
client decrypts the reminder after the user opens Safeory. Recurrence rules
remain encrypted; an authorized client advances the next delivery instant.

## Ingestion and processing

Local upload, browser capture, and client-side connector retrieval encrypt
before persistence. Ordinary SMTP forwarding is not zero knowledge because the
receiver observes message and attachment plaintext; it is excluded from the
default architecture. Any future disclosure-mode email or remote OCR/AI service
requires a separate ADR, explicit per-operation consent, provider/retention
documentation, and threat-model changes. It must not silently convert normally
encrypted metadata into server-visible fields.

## Household and sharing metadata

The server may know opaque household/space membership and role/capability codes
needed to authorize operations. It must not receive household names, space
names, relationship labels, item selection descriptions, or decrypted activity.
SecureLinks use encrypted immutable copies or revisions; the service may enforce
audience, expiry, rate limits, and revocation without receiving content or the
owner's live item key.

Any addition to server-visible metadata requires a threat-model update explaining why the field cannot remain encrypted.
