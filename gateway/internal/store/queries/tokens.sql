-- name: ListServiceTokensByProject :many
SELECT * FROM service_tokens
WHERE project_id = @project_id
ORDER BY created_at DESC;

-- name: GetServiceToken :one
SELECT * FROM service_tokens
WHERE id = @id;

-- name: GetServiceTokenByHash :one
SELECT * FROM service_tokens
WHERE token_hash = @token_hash;

-- name: CreateServiceToken :exec
INSERT INTO service_tokens (id, name, token_hash, token_prefix, project_id, environment_slug, path, permissions, allowed_cidrs, single_use, burned_at, created_by, created_at, expires_at, last_used_at)
VALUES (@id, @name, @token_hash, @token_prefix, @project_id, @environment_slug, @path, @permissions, @allowed_cidrs, @single_use, NULL, @created_by, @now, @expires_at, NULL);

-- name: TouchServiceToken :exec
UPDATE service_tokens
SET last_used_at = @now
WHERE id = @id;

-- name: BurnServiceToken :execrows
UPDATE service_tokens
SET burned_at = @now
WHERE id = @id
  AND single_use = TRUE
  AND burned_at IS NULL;

-- name: DeleteServiceToken :execrows
DELETE FROM service_tokens
WHERE id = @id;
