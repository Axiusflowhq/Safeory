# Safeory API

`safeory-api` is the first Docker-oriented self-hosted HTTP service. It owns
server-visible coordination metadata only. Vault plaintext, passphrases,
recovery secrets, usable vault keys, and decryption logic do not belong here.

## Configuration

The service reads configuration only from environment variables:

- `DATABASE_URL` — PostgreSQL connection URL.
- `VALKEY_URL` — Valkey connection URL using the Redis protocol.
- `BIND_ADDR` — socket address to listen on, for example `0.0.0.0:8080`.
- `ACCOUNT_REGISTRATION_TOKEN` — high-entropy bootstrap authority for creating
  the first account/device; at least 32 bytes.
- `S3_ENDPOINT` — S3-compatible endpoint (Garage is `http://garage:3900` in Compose).
- `S3_REGION` — S3 region (`garage` for the bundled deployment).
- `S3_BUCKET` — ciphertext-object bucket.
- `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` — server-only object-store credentials.
- `RUST_LOG` — optional tracing filter.

## Health endpoints

- `GET /health/live` checks only that the HTTP process is running.
- `GET /health/ready` performs bounded live checks against PostgreSQL, Valkey,
  and the S3-compatible object store. It returns HTTP 503 until all required
  dependencies respond.

## Protocol compatibility

- `GET /v1/compatibility` returns the canonical `vault-sync` compatibility
  advertisement. Protocol, opaque-object header, and key-envelope versions are
  negotiated independently; clients must fail before sync when no supported
  intersection exists.

## Database

Migrations live in `apps/api/migrations`. Compose applies them in filename order
through the one-shot `api-migrate` service before starting the API. PostgreSQL
contains only server-visible account/device/sync metadata; ciphertext object
bodies live in the S3-compatible store.

## Opaque sync transport

The first sync surface is intentionally narrow: bootstrap an account/first
device, add or revoke same-account devices, list changed opaque objects, and
revision-fenced PUT/GET of ciphertext bytes. A PUT carries the canonical
`OpaqueMutationV1` as compact JSON in the bounded `x-safeory-mutation` header
and the ciphertext as its `application/octet-stream` body. The service binds
the authenticated account, path object ID, body size, and body SHA-256 to that
mutation before upload. Accepted operation IDs and their exact canonical input
hashes are persisted atomically with publication: an identical retry returns
the original result, while reuse for different input returns HTTP 409.

Device bearer credentials contain
256 bits of random material and are returned once; PostgreSQL stores only a
domain-separated SHA-256 hash. X25519 device public keys are key-agreement
metadata and are not HTTP authentication credentials.

The server does not parse vault records or encrypted tombstones. Account scope
comes only from the authenticated device, never from a client-supplied account
ID. Object IDs, revisions, sizes, hashes, and change cursors are server-visible;
titles, kinds, fields, notes, vault keys, passphrases, recovery secrets, and
tombstone meaning remain encrypted/client-side.

List responses expose the persisted canonical opaque-object header plus change
cursor and ETag; they do not reconstruct version or routing metadata from
parallel API-specific fields.

`GET/PUT /v1/households/{household_id}/topology` retrieves or publishes the
bounded canonical server-visible authorization topology. Initial publication is
restricted to a revision-zero single-account topology managed by the calling
device. Updates require current manage authority and exactly the next revision;
an exact retry of the currently stored topology succeeds idempotently. All
referenced accounts and devices must exist, match, and remain active.
Household/space object list, download, and upload paths evaluate this topology.
The change feed advances across filtered unauthorized changes so clients cannot
loop on objects they are not permitted to discover.

This endpoint set is not yet the complete combined-product protocol. Shared
cross-account object routing, key-envelope distribution, conflict,
revocation, attachment, SecureLink, reminder, Travel Mode, and compatibility
contract is documented in `docs/architecture/sync.md`. Implementations must not
invent incompatible behavior outside that contract without an ADR and matching
threat-model/server-metadata updates.
