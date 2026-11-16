-- +goose Up
CREATE TABLE shares (
    id              TEXT PRIMARY KEY,
    ciphertext      BYTEA NOT NULL,
    nonce           BYTEA NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    max_views       INTEGER NOT NULL DEFAULT 1,
    view_count      INTEGER NOT NULL DEFAULT 0,
    has_passphrase  BOOLEAN NOT NULL DEFAULT FALSE,
    passphrase_salt BYTEA,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL,
    burned_at       TIMESTAMPTZ
);

CREATE INDEX shares_expires_idx ON shares (expires_at);
CREATE INDEX shares_creator_idx ON shares (created_by);

-- +goose Down
DROP TABLE shares;
