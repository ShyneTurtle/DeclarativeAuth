-- +goose Up
ALTER TABLE sessions ADD COLUMN scope TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE sessions DROP COLUMN scope;
