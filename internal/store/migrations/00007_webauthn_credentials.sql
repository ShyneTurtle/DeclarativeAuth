-- +goose Up
CREATE TABLE webauthn_credentials (
    credential_id  BYTEA PRIMARY KEY,
    username       TEXT NOT NULL,
    name           TEXT NOT NULL DEFAULT '',
    data           JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at   TIMESTAMPTZ
);
CREATE INDEX idx_webauthn_credentials_username ON webauthn_credentials(username);

-- Short-lived state for the in-flight register/login ceremony, between the
-- "start" call (which mints a challenge) and the "finish" call (which
-- verifies the authenticator's response against it). Stored in Postgres
-- rather than in-process memory so it works correctly behind a load
-- balancer across multiple replicas, consistent with password_reset_tokens
-- and sessions.
CREATE TABLE webauthn_ceremonies (
    id          TEXT PRIMARY KEY,
    data        JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_webauthn_ceremonies_expires_at ON webauthn_ceremonies(expires_at);

-- +goose Down
DROP TABLE webauthn_ceremonies;
DROP TABLE webauthn_credentials;
