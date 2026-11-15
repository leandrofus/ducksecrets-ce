-- name: ListRotationPoliciesByProject :many
SELECT r.*, s.key AS secret_key, s.path AS secret_path
FROM rotation_policies r
JOIN secrets s ON s.id = r.secret_id
WHERE s.project_id = @project_id
  AND s.environment_slug = @environment_slug
ORDER BY r.created_at DESC;

-- name: GetRotationPolicyBySecret :one
SELECT * FROM rotation_policies
WHERE secret_id = @secret_id;

-- name: GetRotationPolicy :one
SELECT * FROM rotation_policies
WHERE id = @id;

-- name: CreateRotationPolicy :exec
INSERT INTO rotation_policies (id, secret_id, interval_seconds, generator_type, generator_config, verifier_type, verifier_config, last_rotated_at, next_rotation_at, status, last_error, created_at, updated_at)
VALUES (@id, @secret_id, @interval_seconds, @generator_type, @generator_config, @verifier_type, @verifier_config, NULL, @next_rotation_at, @status, '', @now, @now);

-- name: UpdateRotationPolicy :exec
UPDATE rotation_policies
SET interval_seconds = @interval_seconds,
    generator_type = @generator_type,
    generator_config = @generator_config,
    verifier_type = @verifier_type,
    verifier_config = @verifier_config,
    status = @status,
    updated_at = @now
WHERE id = @id;

-- name: RecordRotationSuccess :exec
UPDATE rotation_policies
SET last_rotated_at = @last_rotated_at,
    next_rotation_at = @next_rotation_at,
    status = 'active',
    last_error = '',
    updated_at = @now
WHERE id = @id;

-- name: RecordRotationFailure :exec
UPDATE rotation_policies
SET status = 'error',
    last_error = @last_error,
    updated_at = @now
WHERE id = @id;

-- name: DeleteRotationPolicy :execrows
DELETE FROM rotation_policies
WHERE id = @id;

-- name: ListPendingRotations :many
SELECT r.*, s.project_id, s.environment_slug, s.path, s.key
FROM rotation_policies r
JOIN secrets s ON s.id = r.secret_id
WHERE r.status = 'active'
  AND r.next_rotation_at <= @now
ORDER BY r.next_rotation_at ASC
LIMIT 50;
