-- +goose Up
CREATE TABLE oidc_authorization_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    username              TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ
);
CREATE INDEX idx_oidc_authorization_codes_expires_at ON oidc_authorization_codes(expires_at);

-- +goose Down
DROP TABLE oidc_authorization_codes;
