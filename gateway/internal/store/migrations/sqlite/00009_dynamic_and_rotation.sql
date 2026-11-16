-- +goose Up
CREATE TABLE dynamic_providers (
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
    UNIQUE(project_id, environment_slug, name)
);

CREATE INDEX dynamic_providers_proj_idx ON dynamic_providers (project_id, environment_slug);

CREATE TABLE dynamic_leases (
    id                    TEXT PRIMARY KEY,
    provider_id           TEXT NOT NULL REFERENCES dynamic_providers(id) ON DELETE CASCADE,
    username              TEXT NOT NULL,
    credentials_encrypted BLOB NOT NULL,
    credentials_nonce     BLOB NOT NULL,
    issued_to             TEXT NOT NULL DEFAULT '',
    expires_at            DATETIME NOT NULL,
    revoked_at            DATETIME,
    created_at            DATETIME NOT NULL
);

CREATE INDEX dynamic_leases_exp_idx ON dynamic_leases (expires_at, revoked_at);
CREATE INDEX dynamic_leases_prov_idx ON dynamic_leases (provider_id);

CREATE TABLE rotation_policies (
    id               TEXT PRIMARY KEY,
    secret_id        TEXT NOT NULL UNIQUE REFERENCES secrets(id) ON DELETE CASCADE,
    interval_seconds INTEGER NOT NULL DEFAULT 2592000,
    generator_type   TEXT NOT NULL DEFAULT 'password',
    generator_config TEXT NOT NULL DEFAULT '{}',
    verifier_type    TEXT NOT NULL DEFAULT 'none',
    verifier_config  TEXT NOT NULL DEFAULT '{}',
    last_rotated_at  DATETIME,
    next_rotation_at DATETIME NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    last_error       TEXT NOT NULL DEFAULT '',
    created_at       DATETIME NOT NULL,
    updated_at       DATETIME NOT NULL
);

CREATE INDEX rotation_policies_next_idx ON rotation_policies (status, next_rotation_at);

-- +goose Down
DROP TABLE rotation_policies;
DROP TABLE dynamic_leases;
DROP TABLE dynamic_providers;
