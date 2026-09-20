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
