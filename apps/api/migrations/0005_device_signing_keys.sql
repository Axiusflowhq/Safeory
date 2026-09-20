-- Browser device identities bind both their X25519 encryption key and Ed25519
-- signing key to a client-generated device UUID before server registration.

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS signing_public_key BYTEA;

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_signing_public_key_size;
ALTER TABLE devices
    ADD CONSTRAINT devices_signing_public_key_size
    CHECK (signing_public_key IS NULL OR octet_length(signing_public_key) = 32);
