-- +goose Up
CREATE TABLE oidc_revoked_tokens (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_oidc_revoked_tokens_expires_at ON oidc_revoked_tokens(expires_at);

-- +goose Down
DROP TABLE oidc_revoked_tokens;
