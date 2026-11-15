-- name: ListProjects :many
SELECT * FROM projects ORDER BY name ASC;

-- name: GetProject :one
SELECT * FROM projects WHERE id = @id;

-- name: GetProjectBySlug :one
SELECT * FROM projects WHERE slug = @slug;

-- name: CreateProject :exec
INSERT INTO projects (id, name, slug, description, created_at, updated_at)
VALUES (@id, @name, @slug, @description, @now, @now);

-- name: UpdateProject :exec
UPDATE projects
SET name = @name, description = @description, updated_at = @now
WHERE id = @id;

-- name: DeleteProject :execrows
DELETE FROM projects WHERE id = @id;

-- name: CountProjects :one
SELECT count(*) FROM projects;
