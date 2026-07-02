-- +goose Up
CREATE TABLE password_reset_tokens (
    token_hash  TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);
CREATE INDEX idx_reset_tokens_username ON password_reset_tokens(username);

-- +goose Down
DROP TABLE password_reset_tokens;
