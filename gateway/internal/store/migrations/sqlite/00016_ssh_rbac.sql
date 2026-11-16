-- +goose Up
UPDATE roles
SET permissions = permissions || ' ssh.connect ssh.manage'
WHERE name = 'user' AND permissions NOT LIKE '%ssh.connect%';

-- +goose Down
