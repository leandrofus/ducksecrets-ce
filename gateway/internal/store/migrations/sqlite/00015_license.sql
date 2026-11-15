-- +goose Up
CREATE TABLE system_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at DATETIME NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS system_settings;
