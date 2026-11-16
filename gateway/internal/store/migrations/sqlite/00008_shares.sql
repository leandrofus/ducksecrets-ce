-- +goose Up
CREATE TABLE shares (
    id              TEXT PRIMARY KEY,
    ciphertext      BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    expires_at      DATETIME NOT NULL,
    max_views       INTEGER NOT NULL DEFAULT 1,
    view_count      INTEGER NOT NULL DEFAULT 0,
    has_passphrase  BOOLEAN NOT NULL DEFAULT 0,
    passphrase_salt BLOB,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      DATETIME NOT NULL,
    burned_at       DATETIME
);

CREATE INDEX shares_expires_idx ON shares (expires_at);
CREATE INDEX shares_creator_idx ON shares (created_by);

-- +goose Down
DROP TABLE shares;
