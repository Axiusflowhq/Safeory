-- Pending approved-device enrollment is intentionally separate from `devices`.
-- A bearer in this table can only activate its matching enrollment; ordinary
-- sync authentication continues to query active rows in `devices` exclusively.

CREATE TABLE IF NOT EXISTS device_enrollments (
    request_id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    approved_by_device_id UUID NOT NULL REFERENCES devices(device_id),
    device_id UUID NOT NULL,
    device_public_key BYTEA NOT NULL CHECK (octet_length(device_public_key) = 32),
    signing_public_key BYTEA NOT NULL CHECK (octet_length(signing_public_key) = 32),
    auth_token_sha256 BYTEA NOT NULL CHECK (octet_length(auth_token_sha256) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK (activated_at IS NULL OR cancelled_at IS NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS device_enrollments_device_id_idx
    ON device_enrollments(device_id)
    WHERE activated_at IS NULL AND cancelled_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS device_enrollments_auth_token_sha256_idx
    ON device_enrollments(auth_token_sha256)
    WHERE activated_at IS NULL AND cancelled_at IS NULL;
CREATE INDEX IF NOT EXISTS device_enrollments_account_pending_idx
    ON device_enrollments(account_id, expires_at)
    WHERE activated_at IS NULL AND cancelled_at IS NULL;

CREATE TABLE IF NOT EXISTS device_enrollment_events (
    event_id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    request_id UUID NOT NULL REFERENCES device_enrollments(request_id) ON DELETE CASCADE,
    actor_device_id UUID NOT NULL REFERENCES devices(device_id),
    subject_device_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('activated', 'cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS device_enrollment_events_account_created_idx
    ON device_enrollment_events(account_id, created_at);
