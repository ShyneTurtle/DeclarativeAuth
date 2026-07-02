-- +goose Up
CREATE TABLE credentials (
    username        TEXT PRIMARY KEY,
    password_hash   TEXT NOT NULL,
    password_set_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    must_reset      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE credentials;
