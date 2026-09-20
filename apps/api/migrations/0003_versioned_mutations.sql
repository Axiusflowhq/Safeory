-- Adopt the canonical vault-sync object header and mutation operation ID.
-- Existing pre-contract objects cannot be assigned honest class/scope/version
-- metadata by the server, so operators must migrate them with an authorized
-- client instead of the migration inventing security-sensitive values.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'ciphertext_objects'
          AND column_name = 'object_header_json'
    ) AND EXISTS (SELECT 1 FROM ciphertext_objects) THEN
        RAISE EXCEPTION 'ciphertext_objects contains pre-contract rows; migrate them with an authorized client before applying 0003';
    END IF;
END
$$;

ALTER TABLE ciphertext_objects
    ADD COLUMN IF NOT EXISTS object_header_json TEXT;

ALTER TABLE ciphertext_objects
    ALTER COLUMN object_header_json SET NOT NULL;

ALTER TABLE ciphertext_objects
    DROP CONSTRAINT IF EXISTS ciphertext_objects_header_nonempty;
ALTER TABLE ciphertext_objects
    ADD CONSTRAINT ciphertext_objects_header_nonempty
    CHECK (object_header_json <> '' AND octet_length(object_header_json) <= 8192);

CREATE TABLE IF NOT EXISTS sync_operations (
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    operation_id UUID NOT NULL,
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    object_id UUID NOT NULL,
    object_header_json TEXT NOT NULL
        CHECK (object_header_json <> '' AND octet_length(object_header_json) <= 8192),
    storage_key TEXT NOT NULL CHECK (storage_key <> ''),
    change_seq BIGINT NOT NULL CHECK (change_seq > 0),
    created BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, operation_id)
);

CREATE INDEX IF NOT EXISTS sync_operations_account_created_idx
    ON sync_operations(account_id, created_at);
