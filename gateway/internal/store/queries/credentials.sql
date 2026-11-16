-- name: ListAllCredentials :many
SELECT * FROM credentials
ORDER BY updated_at DESC;

-- name: ListProjectCredentials :many
SELECT * FROM credentials
WHERE project_id = @project_id
ORDER BY updated_at DESC;

-- name: GetCredential :one
SELECT * FROM credentials
WHERE id = @id;

-- name: CreateCredential :exec
INSERT INTO credentials (id, project_id, environment_slug, name, kind, description, summary, payload_encrypted, payload_nonce, expires_at, created_by, created_at, updated_at)
VALUES (@id, @project_id, @environment_slug, @name, @kind, @description, @summary, @payload_encrypted, @payload_nonce, @expires_at, @created_by, @now, @now);

-- name: UpdateCredential :exec
UPDATE credentials
SET project_id = @project_id,
    environment_slug = @environment_slug,
    name = @name,
    kind = @kind,
    description = @description,
    summary = @summary,
    payload_encrypted = @payload_encrypted,
    payload_nonce = @payload_nonce,
    expires_at = @expires_at,
    updated_at = @now
WHERE id = @id;

-- name: DeleteCredential :execrows
DELETE FROM credentials
WHERE id = @id;

-- name: CountCredentials :one
SELECT count(*) FROM credentials;
