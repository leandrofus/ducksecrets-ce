-- name: CreateProjectPolicy :one
INSERT INTO project_policies (
    id, project_id, subject_type, subject_id, environment_slug,
    can_read, can_write, can_admin, starts_at, expires_at,
    description, created_by, created_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10,
    $11, $12, $13
)
RETURNING *;

-- name: GetProjectPolicy :one
SELECT * FROM project_policies
WHERE id = $1;

-- name: ListProjectPolicies :many
SELECT * FROM project_policies
WHERE project_id = $1
ORDER BY created_at ASC;

-- name: UpdateProjectPolicy :one
UPDATE project_policies
SET environment_slug = $2,
    can_read = $3,
    can_write = $4,
    can_admin = $5,
    starts_at = $6,
    expires_at = $7,
    description = $8
WHERE id = $1
RETURNING *;

-- name: DeleteProjectPolicy :exec
DELETE FROM project_policies
WHERE id = $1;

-- name: ActivePoliciesForUserOnProject :many
SELECT * FROM project_policies
WHERE project_id = $1
  AND (
    (subject_type = 'user' AND subject_id = $2)
    OR (subject_type = 'role' AND subject_id = $3)
  )
  AND (starts_at IS NULL OR starts_at <= $4)
  AND (expires_at IS NULL OR expires_at > $4);

-- name: ListProjectIDsWithAccessForUser :many
SELECT DISTINCT project_id FROM project_policies
WHERE (
    (subject_type = 'user' AND subject_id = $1)
    OR (subject_type = 'role' AND subject_id = $2)
  )
  AND (starts_at IS NULL OR starts_at <= $3)
  AND (expires_at IS NULL OR expires_at > $3);
