-- +goose Up
-- Roles and their global permissions (space-separated names from
-- internal/auth/perms.go). admin always holds "*".
CREATE TABLE roles (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT NOT NULL DEFAULT '',
    builtin     BOOLEAN NOT NULL DEFAULT false
);
INSERT INTO roles (name, description, permissions, builtin) VALUES
    ('admin', 'Everything', '*', true),
    ('user', 'Reads and writes notes', 'notes.read notes.write', true);

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',     -- empty for users of other sources
    source        TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'pam')),
    role          TEXT NOT NULL DEFAULT 'user' REFERENCES roles (name) ON UPDATE CASCADE,
    disabled      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ
);

-- Only the sha256 of the cookie value is stored.
CREATE TABLE web_sessions (
    id_hash      TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX web_sessions_user ON web_sessions (user_id);

-- +goose Down
DROP TABLE web_sessions;
DROP TABLE users;
DROP TABLE roles;
