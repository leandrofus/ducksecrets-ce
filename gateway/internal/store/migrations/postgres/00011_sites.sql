-- +goose Up
CREATE TABLE sites (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    last_seen_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    UNIQUE(project_id, name)
);

CREATE INDEX sites_proj_idx ON sites (project_id);

ALTER TABLE dynamic_providers ADD COLUMN site_id TEXT REFERENCES sites(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE dynamic_providers DROP COLUMN site_id;
DROP TABLE IF EXISTS sites;
