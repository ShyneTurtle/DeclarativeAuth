-- +goose Up
-- Declarative groups have no row of their own anywhere in Postgres (they
-- live only in YAML) -- this table exists purely to give each one a stable,
-- persistent RID the first time a samba-privileged LDAP search needs to
-- render it as a sambaGroupMapping entry, the same way credentials.samba_rid
-- does for users. Pulls from the same samba_rid_seq users do, so a user and
-- a group can never end up sharing one SID.
CREATE TABLE samba_group_rids (
    group_name TEXT PRIMARY KEY,
    samba_rid  BIGINT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE samba_group_rids;
