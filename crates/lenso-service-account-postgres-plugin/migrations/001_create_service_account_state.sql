CREATE TABLE service_accounts (
    service_account_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT service_accounts_subject_unique UNIQUE (subject),
    CONSTRAINT service_accounts_organization_name_unique UNIQUE (organization_id, name_key),
    CHECK (char_length(service_account_id) BETWEEN 1 AND 128),
    CHECK (char_length(organization_id) BETWEEN 1 AND 256),
    CHECK (char_length(subject) BETWEEN 1 AND 256),
    CHECK (char_length(name) BETWEEN 1 AND 128),
    CHECK (char_length(name_key) BETWEEN 1 AND 128),
    CHECK (name = btrim(name)),
    CHECK (name_key = lower(name)),
    CHECK (
        (status = 'active' AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

CREATE INDEX service_accounts_organization_keyset_idx
    ON service_accounts (organization_id, service_account_id);

CREATE TABLE service_account_credentials (
    credential_id TEXT PRIMARY KEY,
    service_account_id TEXT NOT NULL REFERENCES service_accounts(service_account_id) ON DELETE CASCADE,
    verifier TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    CHECK (char_length(credential_id) BETWEEN 1 AND 128),
    CHECK (char_length(verifier) BETWEEN 32 AND 1024),
    CHECK (valid_from <= valid_until)
);

CREATE INDEX service_account_credentials_account_idx
    ON service_account_credentials (service_account_id, created_at DESC, credential_id);

CREATE TABLE service_account_commands (
    caller_instance TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    intent_hash BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('reserved', 'verifying', 'issuing', 'completed_success', 'completed_error')
    ),
    response_nonce BYTEA,
    response_ciphertext BYTEA,
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (caller_instance, operation, idempotency_key),
    CHECK (char_length(caller_instance) BETWEEN 1 AND 128),
    CHECK (char_length(operation) BETWEEN 1 AND 64),
    CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    CHECK (octet_length(intent_hash) = 32),
    CHECK (response_nonce IS NULL OR octet_length(response_nonce) = 12),
    CHECK (response_ciphertext IS NULL OR octet_length(response_ciphertext) <= 262144),
    CHECK (error_code IS NULL OR char_length(error_code) BETWEEN 1 AND 64),
    CHECK (
        (status = 'completed_success' AND response_nonce IS NOT NULL AND response_ciphertext IS NOT NULL AND error_code IS NULL AND completed_at IS NOT NULL)
        OR
        (status = 'completed_error' AND response_nonce IS NULL AND response_ciphertext IS NULL AND error_code IS NOT NULL AND completed_at IS NOT NULL)
        OR
        (status IN ('reserved', 'verifying', 'issuing') AND response_nonce IS NULL AND response_ciphertext IS NULL AND error_code IS NULL AND completed_at IS NULL)
    )
);

CREATE INDEX service_account_commands_retention_idx
    ON service_account_commands (completed_at, created_at);

CREATE TABLE service_account_exchange_limits (
    caller_instance TEXT PRIMARY KEY,
    window_started_at TIMESTAMPTZ NOT NULL,
    attempts BIGINT NOT NULL CHECK (attempts >= 0),
    locked_until TIMESTAMPTZ,
    CHECK (char_length(caller_instance) BETWEEN 1 AND 128)
);
