-- +goose Up
UPDATE roles
SET description = 'Projects, environments and secrets',
    permissions = TRIM(REPLACE(REPLACE(REPLACE(' ' || permissions || ' ', ' notes.read ', ' '), ' notes.write ', ' '), '  ', ' '))
WHERE name = 'user';

CREATE UNIQUE INDEX IF NOT EXISTS sites_token_hash_uidx ON sites (token_hash);

-- +goose Down
DROP INDEX IF EXISTS sites_token_hash_uidx;
