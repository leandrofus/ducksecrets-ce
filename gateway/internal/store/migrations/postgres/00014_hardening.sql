-- +goose Up
UPDATE roles
SET description = 'Projects, environments and secrets',
    permissions = TRIM(REPLACE(REPLACE(REPLACE(' ' || permissions || ' ', ' notes.read ', ' '), ' notes.write ', ' '), '  ', ' '))
WHERE name = 'user';

CREATE UNIQUE INDEX IF NOT EXISTS sites_token_hash_uidx ON sites (token_hash);

CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();

-- +goose Down
DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
DROP INDEX IF EXISTS sites_token_hash_uidx;
