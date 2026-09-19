# Server-Visible Metadata

Principle: if the backend does not need a field in plaintext to authenticate, route, synchronize, rate-limit, or coordinate a security workflow, encrypt it.

This rule is deployment-independent. The primary backend is self-hosted: a Rust
HTTP API with PostgreSQL, S3-compatible ciphertext storage, Valkey, SMTP, and a
TLS reverse proxy. Running the stack on operator-owned hardware does not make
additional vault metadata safe to expose in plaintext.

## Intended plaintext metadata

| Field class | Why required | Leakage |
| --- | --- | --- |
| Account ID | Authentication/routing | Account existence/activity correlation |
| Verified email | Login/security notifications | Email address |
| Device ID/status/public key | Authorization/revocation | Number/timing of devices |
| Opaque object ID | Sync routing/idempotency | Object count/activity |
| Object revision/tombstone | Conflict detection/deletion | Update timing/history shape |
| Ciphertext size | Storage/protocol framing | Approximate item size |
| Required timestamps | Sync ordering/rate controls | Activity timing |
| Trusted relationship opaque IDs | Route invitation/emergency workflows | Relationship existence |
| Emergency state/policy timing | Enforce request/wait/release workflow | Emergency relationship timing |
| Audit event type + opaque refs | Security history | Security-event timing/type |

PostgreSQL is the durable source of truth for these fields. S3-compatible
storage receives ciphertext blobs plus the minimum opaque object key/framing
metadata needed to store and retrieve them. Valkey may temporarily hold opaque
job IDs, rate-limit keys, retry counts, and deduplication tokens; it must not be
used as the only durable record of account authorization or emergency-policy
state. SMTP receives only the destination address and non-vault notification
content required to deliver a security/account message.

## Normally encrypted metadata

- Vault names.
- Item titles/categories when routing does not require them.
- Institution/provider names.
- Document names.
- Property names/locations.
- Trusted-person labels such as "wife" or "lawyer" when not operationally required.
- Emergency instructions and granted item/category descriptions.

## Explicit exclusions

The API, PostgreSQL, object store, Valkey, SMTP pipeline, reverse proxy, and
their logs must never intentionally receive plaintext vault bodies, passwords,
recovery codes, attachment contents, emergency instructions, AccountRootKey,
per-item keys, or usable attachment keys. Ciphertext bodies may transit the API
or proxy when protocol design requires it, but request-body logging is disabled.

Any addition to server-visible metadata requires a threat-model update explaining why the field cannot remain encrypted.
