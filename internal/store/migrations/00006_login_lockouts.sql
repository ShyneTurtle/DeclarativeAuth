-- +goose Up
CREATE TABLE login_lockouts (
    lockout_key       TEXT PRIMARY KEY,
    failure_count     INT NOT NULL DEFAULT 0,
    first_failure_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_failure_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until      TIMESTAMPTZ
);
CREATE INDEX idx_login_lockouts_locked_until ON login_lockouts(locked_until);

-- +goose Down
DROP TABLE login_lockouts;
