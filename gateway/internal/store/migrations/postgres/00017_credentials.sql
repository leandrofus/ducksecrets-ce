-- +goose Up
CREATE TABLE credentials (
    id                TEXT PRIMARY KEY,
    project_id        TEXT REFERENCES projects(id) ON DELETE CASCADE,
    environment_slug  TEXT NOT NULL DEFAULT '',
    name              TEXT NOT NULL,
    kind              TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    summary           TEXT NOT NULL DEFAULT '',
    payload_encrypted BYTEA NOT NULL,
    payload_nonce     BYTEA NOT NULL,
    expires_at        TIMESTAMPTZ,
    created_by        TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX credentials_proj_idx ON credentials (project_id, environment_slug);
CREATE INDEX credentials_kind_idx ON credentials (kind);

-- +goose Down
DROP TABLE IF EXISTS credentials;
