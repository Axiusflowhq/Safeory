# Contracts package

Shared browser contracts for ciphertext persistence, durable vault sessions,
device-key storage, and sync compatibility. The compatibility client validates
the bounded API advertisement and fails before sync when protocol, opaque-object
header, or key-envelope versions do not intersect. The authenticated sync
client strictly validates canonical opaque headers and mutations, verifies
ciphertext size and SHA-256 before upload and after download, bounds metadata
responses, and maps revision/idempotency failures without exposing device
credentials to insecure non-local HTTP origins.
