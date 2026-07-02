-- +goose Up
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

-- +goose Down
DROP TABLE mfa_recovery_codes;
DROP TABLE mfa_totp_secrets;
