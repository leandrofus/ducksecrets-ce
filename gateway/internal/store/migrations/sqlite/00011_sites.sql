-- +goose Up
CREATE TABLE sites (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    last_seen_at DATETIME,
    created_at   DATETIME NOT NULL,
    updated_at   DATETIME NOT NULL,
    UNIQUE(project_id, name)
);

CREATE INDEX sites_proj_idx ON sites (project_id);

ALTER TABLE dynamic_providers ADD COLUMN site_id TEXT REFERENCES sites(id) ON DELETE SET NULL;

-- +goose Down
-- SQLite disallows DROP COLUMN on a column with a REFERENCES clause, so rebuild dynamic_providers.
CREATE TABLE dynamic_providers_old (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_slug    TEXT NOT NULL,
    name                TEXT NOT NULL,
    engine              TEXT NOT NULL,
    config_encrypted    BLOB NOT NULL,
    config_nonce        BLOB NOT NULL,
    default_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    max_ttl_seconds     INTEGER NOT NULL DEFAULT 86400,
    role_template       TEXT NOT NULL DEFAULT '',
    created_at          DATETIME NOT NULL,
    updated_at          DATETIME NOT NULL,
    enforced_port       INTEGER NOT NULL DEFAULT 0,
    UNIQUE(project_id, environment_slug, name)
);
INSERT INTO dynamic_providers_old (id, project_id, environment_slug, name, engine, config_encrypted, config_nonce, default_ttl_seconds, max_ttl_seconds, role_template, created_at, updated_at, enforced_port)
SELECT id, project_id, environment_slug, name, engine, config_encrypted, config_nonce, default_ttl_seconds, max_ttl_seconds, role_template, created_at, updated_at, enforced_port FROM dynamic_providers;
DROP TABLE dynamic_providers;
ALTER TABLE dynamic_providers_old RENAME TO dynamic_providers;
CREATE INDEX dynamic_providers_proj_idx ON dynamic_providers (project_id, environment_slug);
DROP TABLE IF EXISTS sites;
