-- +goose Up
CREATE TABLE secrets (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_slug TEXT NOT NULL,
    path             TEXT NOT NULL DEFAULT '/',
    key              TEXT NOT NULL,
    value_encrypted  BYTEA NOT NULL,
    value_nonce      BYTEA NOT NULL,
    comment          TEXT NOT NULL DEFAULT '',
    version          INTEGER NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    UNIQUE (project_id, environment_slug, path, key)
);

CREATE INDEX secrets_env_idx ON secrets (project_id, environment_slug, path);

CREATE TABLE secret_versions (
    id              TEXT PRIMARY KEY,
    secret_id       TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    value_encrypted BYTEA NOT NULL,
    value_nonce     BYTEA NOT NULL,
    comment         TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL,
    created_by      TEXT NOT NULL DEFAULT '',
    UNIQUE (secret_id, version)
);

CREATE INDEX secret_versions_secret_idx ON secret_versions (secret_id, version DESC);

UPDATE roles SET permissions = permissions || ' projects.read projects.write environments.read environments.write secrets.read secrets.write' WHERE name = 'user' AND permissions NOT LIKE '%secrets.read%';

-- +goose Down
DROP TABLE secret_versions;
DROP TABLE secrets;
