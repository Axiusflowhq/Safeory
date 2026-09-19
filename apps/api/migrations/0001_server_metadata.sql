-- Safeory server-visible metadata only.
-- Vault plaintext, passphrases, recovery secrets, usable keys, and ciphertext
-- payload bodies do not belong in this schema.

CREATE TABLE IF NOT EXISTS accounts (
    account_id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
    device_id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS devices_account_id_idx ON devices(account_id);

CREATE TABLE IF NOT EXISTS ciphertext_objects (
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    object_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 0),
    ciphertext_size_bytes BIGINT NOT NULL CHECK (ciphertext_size_bytes >= 0),
    ciphertext_sha256 BYTEA NOT NULL CHECK (octet_length(ciphertext_sha256) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, object_id)
);

CREATE INDEX IF NOT EXISTS ciphertext_objects_account_revision_idx
    ON ciphertext_objects(account_id, revision);
