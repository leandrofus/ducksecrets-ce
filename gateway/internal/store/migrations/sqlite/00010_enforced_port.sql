-- +goose Up
ALTER TABLE dynamic_providers ADD COLUMN enforced_port INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE dynamic_providers DROP COLUMN enforced_port;
