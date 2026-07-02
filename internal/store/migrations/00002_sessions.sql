-- +goose Up
CREATE TABLE sessions (
    id                  UUID PRIMARY KEY,
    username            TEXT NOT NULL,
    refresh_token_hash  TEXT NOT NULL,
    client_id           TEXT,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    user_agent          TEXT,
    ip_address          INET
);
CREATE INDEX idx_sessions_username ON sessions(username);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- +goose Down
DROP TABLE sessions;
