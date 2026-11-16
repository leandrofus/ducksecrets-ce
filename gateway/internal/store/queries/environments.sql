-- name: ListEnvironmentsByProject :many
SELECT * FROM environments
WHERE project_id = @project_id
ORDER BY position ASC, name ASC;

-- name: GetEnvironment :one
SELECT * FROM environments
WHERE id = @id;

-- name: GetEnvironmentBySlug :one
SELECT * FROM environments
WHERE project_id = @project_id AND slug = @slug;

-- name: CreateEnvironment :exec
INSERT INTO environments (id, project_id, name, slug, position, created_at)
VALUES (@id, @project_id, @name, @slug, @position, @now);

-- name: DeleteEnvironment :execrows
DELETE FROM environments
WHERE id = @id;

-- name: DeleteEnvironmentsByProject :exec
DELETE FROM environments
WHERE project_id = @project_id;
