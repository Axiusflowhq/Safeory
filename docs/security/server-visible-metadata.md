# Server-Visible Metadata

Principle: if the backend does not need a field in plaintext to authenticate, route, synchronize, rate-limit, or coordinate a security workflow, encrypt it.

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

## Normally encrypted metadata

- Vault names.
- Item titles/categories when routing does not require them.
- Institution/provider names.
- Document names.
- Property names/locations.
- Trusted-person labels such as "wife" or "lawyer" when not operationally required.
- Emergency instructions and granted item/category descriptions.

## Explicit exclusions

The backend must never intentionally receive plaintext vault bodies, passwords, recovery codes, attachment contents, emergency instructions, AccountRootKey, per-item keys, or usable attachment keys.

Any addition to server-visible metadata requires a threat-model update explaining why the field cannot remain encrypted.
