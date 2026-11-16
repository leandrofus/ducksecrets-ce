-- +goose Up
ALTER TABLE project_policies ADD COLUMN can_view_creds BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE project_policies ADD COLUMN can_edit_creds BOOLEAN NOT NULL DEFAULT 0;

UPDATE project_policies SET can_view_creds = can_read, can_edit_creds = can_write;

UPDATE roles
SET permissions = permissions || ' credentials.read credentials.write'
WHERE name = 'user' AND permissions NOT LIKE '%credentials.read%';

-- +goose Down
