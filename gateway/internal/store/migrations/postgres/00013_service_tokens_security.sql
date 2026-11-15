-- +goose Up
ALTER TABLE service_tokens ADD COLUMN allowed_cidrs TEXT NOT NULL DEFAULT '';
ALTER TABLE service_tokens ADD COLUMN single_use BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE service_tokens ADD COLUMN burned_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE service_tokens DROP COLUMN IF EXISTS allowed_cidrs;
ALTER TABLE service_tokens DROP COLUMN IF EXISTS single_use;
ALTER TABLE service_tokens DROP COLUMN IF EXISTS burned_at;
