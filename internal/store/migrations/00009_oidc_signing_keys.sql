-- +goose Up
CREATE TABLE oidc_signing_keys (
    kid             TEXT PRIMARY KEY,
    algorithm       TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    is_current      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    retire_at       TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_oidc_signing_keys_one_current ON oidc_signing_keys (is_current) WHERE is_current;
CREATE INDEX idx_oidc_signing_keys_retire_at ON oidc_signing_keys(retire_at);

-- +goose Down
DROP TABLE oidc_signing_keys;
