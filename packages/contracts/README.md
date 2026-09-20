# Contracts package

Shared browser contracts for ciphertext persistence, durable vault sessions,
device-key storage, and sync compatibility. The compatibility client validates
the bounded API advertisement and fails before sync when protocol, opaque-object
header, or key-envelope versions do not intersect. The authenticated sync
client strictly validates canonical opaque headers and mutations, verifies
ciphertext size and SHA-256 before upload and after download, bounds metadata
responses, and maps revision/idempotency failures without exposing device
credentials to insecure non-local HTTP origins. A bounded IndexedDB outbox
durably queues canonical mutations and ciphertext without persisting device
credentials; successful writes are acknowledged separately so interrupted
flushes retry through operation-ID idempotency. The pull coordinator downloads
and verifies bounded pages, invokes an idempotent durable-acceptance callback,
and compare-and-swap checkpoints each change cursor only after acceptance.
Canonical browser parsers for the account, household, membership, space, and
single-owner migration contracts mirror `vault-sync` bounds and fail closed on
unknown fields, inconsistent routing references, or invalid access topology.
The matching browser/Rust scope evaluator binds the authenticated account and
device to account, household, or space routes and keeps read, write, and manage
authority distinct; successful routing authorization never implies key access.
Both implementations load the same canonical topology fixture in their test
suites so JSON wire-shape drift fails CI on either side.
