-- +goose Up
-- Superseded by email-based MFA below before ever being wired to any
-- application code (see migration 00005) -- dropped rather than left as
-- permanent dead schema.
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS mfa_totp_secrets;

CREATE TABLE user_mfa_settings (
    username    TEXT PRIMARY KEY,
    enabled     BOOLEAN NOT NULL DEFAULT false,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mfa_email_challenges (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL,
    code_hash    TEXT NOT NULL,
    return_to    TEXT NOT NULL DEFAULT '/',
    attempts     INT NOT NULL DEFAULT 0,
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mfa_email_challenges_expires_at ON mfa_email_challenges(expires_at);

-- +goose Down
DROP TABLE mfa_email_challenges;
DROP TABLE user_mfa_settings;

CREATE TABLE mfa_totp_secrets (
    username          TEXT PRIMARY KEY,
    secret_encrypted  BYTEA NOT NULL,
    confirmed_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mfa_recovery_codes (
    id          BIGSERIAL PRIMARY KEY,
    username    TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_recovery_codes_username ON mfa_recovery_codes(username);
