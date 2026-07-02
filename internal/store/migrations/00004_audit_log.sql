-- +goose Up
CREATE TABLE login_audit (
    id           BIGSERIAL PRIMARY KEY,
    username     TEXT,
    event_type   TEXT NOT NULL,
    source_ip    INET,
    user_agent   TEXT,
    detail       TEXT,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_login_audit_username_time ON login_audit(username, occurred_at DESC);
CREATE INDEX idx_login_audit_event_type_time ON login_audit(event_type, occurred_at DESC);

-- +goose Down
DROP TABLE login_audit;
