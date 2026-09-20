# Contracts package

Shared browser contracts for ciphertext persistence, durable vault sessions,
device-key storage, and sync compatibility. The compatibility client validates
the bounded API advertisement and fails before sync when protocol, opaque-object
header, or key-envelope versions do not intersect. The authenticated sync
client strictly validates canonical opaque headers and mutations, verifies
ciphertext size and SHA-256 before upload and after download, bounds metadata
responses, and maps revision/idempotency failures without exposing device
credentials to insecure non-local HTTP origins. The same client bootstraps
accounts, registers additional client-generated
device identities with both encryption and signing public keys, validates the
one-time credential response, and revokes devices without treating public keys
as HTTP credentials. It also validates the bounded active-device inventory and
the server-enforced enrollment ceiling, and distinguishes identifier collisions
and the transactional last-active-device revocation fence. Device bearer persistence encrypts each token under a
non-extractable browser key with API/account/device-bound AES-GCM metadata; the
credential store reconnects `SyncClient` with that persisted device identity so
inventory responses cannot substitute the calling device. The outbox and cursor databases never contain credentials. A bounded IndexedDB outbox
durably queues canonical mutations and ciphertext without persisting device
credentials; successful writes are acknowledged separately so interrupted
flushes retry through operation-ID idempotency. The pull coordinator downloads
and verifies bounded pages, invokes an idempotent durable-acceptance callback,
and compare-and-swap checkpoints each change cursor only after acceptance.
`DurableSyncCoordinator` serializes bounded pull-then-push cycles so remote
revisions reach durable application acceptance before queued local writes are
attempted, while a failed cycle cannot poison later retries.
Canonical browser parsers for the account, household, membership, space, and
single-owner migration contracts mirror `vault-sync` bounds and fail closed on
unknown fields, inconsistent routing references, or invalid access topology.
The matching browser/Rust scope evaluator binds the authenticated account and
device to account, household, or space routes and keeps read, write, and manage
authority distinct; successful routing authorization never implies key access.
Both implementations load the same canonical topology fixture in their test
suites so JSON wire-shape drift fails CI on either side.

The browser wrapping key provides encrypted-at-rest storage and prevents direct
key export. It is not an OS keystore and cannot defend a live session against
fully compromised same-origin code; native hardware-backed isolation remains a
separate platform milestone.
