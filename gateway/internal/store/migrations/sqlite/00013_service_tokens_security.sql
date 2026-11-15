-- +goose Up
ALTER TABLE service_tokens ADD COLUMN allowed_cidrs TEXT NOT NULL DEFAULT '';
ALTER TABLE service_tokens ADD COLUMN single_use BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE service_tokens ADD COLUMN burned_at DATETIME;

-- +goose Down
ALTER TABLE service_tokens DROP COLUMN allowed_cidrs;
ALTER TABLE service_tokens DROP COLUMN single_use;
ALTER TABLE service_tokens DROP COLUMN burned_at;
