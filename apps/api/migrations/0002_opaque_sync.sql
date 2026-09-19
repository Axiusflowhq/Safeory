-- Minimal opaque encrypted-sync metadata.
-- Ciphertext bodies remain in S3-compatible object storage, never PostgreSQL.

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS sync_cursor BIGINT NOT NULL DEFAULT 0;

ALTER TABLE accounts
    DROP CONSTRAINT IF EXISTS accounts_sync_cursor_nonnegative;
ALTER TABLE accounts
    ADD CONSTRAINT accounts_sync_cursor_nonnegative CHECK (sync_cursor >= 0);

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS device_public_key BYTEA;
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS auth_token_sha256 BYTEA;

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_public_key_size;
ALTER TABLE devices
    ADD CONSTRAINT devices_public_key_size
    CHECK (device_public_key IS NULL OR octet_length(device_public_key) = 32);

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_auth_token_hash_size;
ALTER TABLE devices
    ADD CONSTRAINT devices_auth_token_hash_size
    CHECK (auth_token_sha256 IS NULL OR octet_length(auth_token_sha256) = 32);

CREATE UNIQUE INDEX IF NOT EXISTS devices_auth_token_sha256_idx
    ON devices(auth_token_sha256)
    WHERE auth_token_sha256 IS NOT NULL;

ALTER TABLE ciphertext_objects
    ADD COLUMN IF NOT EXISTS change_seq BIGINT;
ALTER TABLE ciphertext_objects
    ADD COLUMN IF NOT EXISTS storage_key TEXT;

-- No API existed that could create ciphertext_objects before this migration.
-- Fail closed if an operator manually populated incomplete rows rather than
-- inventing storage pointers or cursor values.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ciphertext_objects
        WHERE change_seq IS NULL OR storage_key IS NULL OR storage_key = ''
    ) THEN
        RAISE EXCEPTION 'ciphertext_objects contains pre-sync rows that require manual migration';
    END IF;
END
$$;

ALTER TABLE ciphertext_objects
    ALTER COLUMN change_seq SET NOT NULL;
ALTER TABLE ciphertext_objects
    ALTER COLUMN storage_key SET NOT NULL;

ALTER TABLE ciphertext_objects
    DROP CONSTRAINT IF EXISTS ciphertext_objects_change_seq_positive;
ALTER TABLE ciphertext_objects
    ADD CONSTRAINT ciphertext_objects_change_seq_positive CHECK (change_seq > 0);
ALTER TABLE ciphertext_objects
    DROP CONSTRAINT IF EXISTS ciphertext_objects_storage_key_nonempty;
ALTER TABLE ciphertext_objects
    ADD CONSTRAINT ciphertext_objects_storage_key_nonempty CHECK (storage_key <> '');

CREATE UNIQUE INDEX IF NOT EXISTS ciphertext_objects_account_change_seq_idx
    ON ciphertext_objects(account_id, change_seq);
