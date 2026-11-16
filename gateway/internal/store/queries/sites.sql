-- name: CreateSite :exec
INSERT INTO sites (id, project_id, name, token_hash, token_prefix, description, created_at, updated_at)
VALUES (@id, @project_id, @name, @token_hash, @token_prefix, @description, @now, @now);

-- name: GetSite :one
SELECT * FROM sites
WHERE id = @id;

-- name: GetSiteByName :one
SELECT * FROM sites
WHERE project_id = @project_id
  AND name = @name;

-- name: GetSiteByTokenHash :one
SELECT * FROM sites
WHERE token_hash = @token_hash;

-- name: ListSites :many
SELECT * FROM sites
WHERE project_id = @project_id
ORDER BY name ASC;

-- name: UpdateSiteLastSeen :exec
UPDATE sites
SET last_seen_at = @now,
    updated_at = @now
WHERE id = @id;

-- name: DeleteSite :execrows
DELETE FROM sites
WHERE id = @id;

-- name: CountAllSites :one
SELECT count(*) FROM sites;
