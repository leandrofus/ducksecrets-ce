-- name: ListSecrets :many
SELECT * FROM secrets
WHERE project_id = @project_id
  AND environment_slug = @environment_slug
  AND path = @path
ORDER BY key ASC;

-- name: ListSecretsAllPaths :many
SELECT * FROM secrets
WHERE project_id = @project_id
  AND environment_slug = @environment_slug
ORDER BY path ASC, key ASC;

-- name: GetSecret :one
SELECT * FROM secrets WHERE id = @id;

-- name: GetSecretByKey :one
SELECT * FROM secrets
WHERE project_id = @project_id
  AND environment_slug = @environment_slug
  AND path = @path
  AND key = @key;

-- name: CreateSecret :exec
INSERT INTO secrets (id, project_id, environment_slug, path, key, value_encrypted, value_nonce, comment, version, created_at, updated_at)
VALUES (@id, @project_id, @environment_slug, @path, @key, @value_encrypted, @value_nonce, @comment, @version, @now, @now);

-- name: UpdateSecret :exec
UPDATE secrets
SET value_encrypted = @value_encrypted,
    value_nonce = @value_nonce,
    comment = @comment,
    version = version + 1,
    updated_at = @now
WHERE id = @id;

-- name: RollbackSecret :exec
UPDATE secrets
SET value_encrypted = @value_encrypted,
    value_nonce = @value_nonce,
    comment = @comment,
    version = @version,
    updated_at = @now
WHERE id = @id;

-- name: DeleteSecret :execrows
DELETE FROM secrets WHERE id = @id;

-- name: CreateSecretVersion :exec
INSERT INTO secret_versions (id, secret_id, version, value_encrypted, value_nonce, comment, created_at, created_by)
VALUES (@id, @secret_id, @version, @value_encrypted, @value_nonce, @comment, @now, @created_by);

-- name: ListSecretVersions :many
SELECT * FROM secret_versions
WHERE secret_id = @secret_id
ORDER BY version DESC;

-- name: GetSecretVersion :one
SELECT * FROM secret_versions
WHERE secret_id = @secret_id AND version = @version;

-- name: DeleteSecretVersion :execrows
DELETE FROM secret_versions
WHERE secret_id = @secret_id AND version = @version;

-- name: CountSecrets :one
SELECT count(*) FROM secrets
WHERE project_id = @project_id AND environment_slug = @environment_slug;
