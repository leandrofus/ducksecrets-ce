-- +goose Up
CREATE TABLE service_tokens (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    token_hash       TEXT NOT NULL UNIQUE,
    token_prefix     TEXT NOT NULL,
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_slug TEXT NOT NULL DEFAULT '*',
    path             TEXT NOT NULL DEFAULT '/',
    permissions      TEXT NOT NULL DEFAULT 'secrets.read',
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ,
    last_used_at     TIMESTAMPTZ
);

CREATE INDEX service_tokens_hash_idx ON service_tokens (token_hash);
CREATE INDEX service_tokens_proj_idx ON service_tokens (project_id, environment_slug);

-- +goose Down
DROP TABLE service_tokens;
