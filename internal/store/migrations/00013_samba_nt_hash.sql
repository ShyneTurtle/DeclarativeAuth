-- +goose Up
-- RIDs start at 1000 (below that is conventionally reserved for
-- well-known/built-in SIDs on a Windows domain).
CREATE SEQUENCE samba_rid_seq START WITH 1000;

ALTER TABLE credentials ADD COLUMN nt_hash TEXT;
ALTER TABLE credentials ADD COLUMN samba_rid BIGINT UNIQUE;

-- +goose Down
ALTER TABLE credentials DROP COLUMN samba_rid;
ALTER TABLE credentials DROP COLUMN nt_hash;
DROP SEQUENCE samba_rid_seq;
