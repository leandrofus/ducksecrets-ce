-- name: ListDynamicProviders :many
SELECT * FROM dynamic_providers
WHERE project_id = @project_id
  AND environment_slug = @environment_slug
ORDER BY name ASC;

-- name: GetDynamicProvider :one
SELECT * FROM dynamic_providers
WHERE id = @id;

-- name: GetDynamicProviderByName :one
SELECT * FROM dynamic_providers
WHERE project_id = @project_id
  AND environment_slug = @environment_slug
  AND name = @name;

-- name: CreateDynamicProvider :exec
INSERT INTO dynamic_providers (id, project_id, environment_slug, name, engine, config_encrypted, config_nonce, default_ttl_seconds, max_ttl_seconds, role_template, enforced_port, site_id, created_at, updated_at)
VALUES (@id, @project_id, @environment_slug, @name, @engine, @config_encrypted, @config_nonce, @default_ttl_seconds, @max_ttl_seconds, @role_template, @enforced_port, @site_id, @now, @now);

-- name: UpdateDynamicProvider :exec
UPDATE dynamic_providers
SET name = @name,
    config_encrypted = @config_encrypted,
    config_nonce = @config_nonce,
    default_ttl_seconds = @default_ttl_seconds,
    max_ttl_seconds = @max_ttl_seconds,
    role_template = @role_template,
    enforced_port = @enforced_port,
    site_id = @site_id,
    updated_at = @now
WHERE id = @id;

-- name: DeleteDynamicProvider :execrows
DELETE FROM dynamic_providers
WHERE id = @id;

-- name: CreateDynamicLease :exec
INSERT INTO dynamic_leases (id, provider_id, username, credentials_encrypted, credentials_nonce, issued_to, expires_at, revoked_at, created_at)
VALUES (@id, @provider_id, @username, @credentials_encrypted, @credentials_nonce, @issued_to, @expires_at, NULL, @now);

-- name: GetDynamicLease :one
SELECT * FROM dynamic_leases
WHERE id = @id;

-- name: ListActiveLeasesByProvider :many
SELECT * FROM dynamic_leases
WHERE provider_id = @provider_id
  AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: RevokeDynamicLease :exec
UPDATE dynamic_leases
SET revoked_at = @revoked_at
WHERE id = @id;

-- name: RenewDynamicLease :exec
UPDATE dynamic_leases
SET expires_at = @expires_at
WHERE id = @id
  AND revoked_at IS NULL;

-- name: ListExpiredUnrevokedLeases :many
SELECT * FROM dynamic_leases
WHERE revoked_at IS NULL
  AND expires_at <= @now
ORDER BY expires_at ASC
LIMIT 100;

-- name: DeleteExpiredLeases :execrows
DELETE FROM dynamic_leases
WHERE revoked_at IS NOT NULL
  AND revoked_at < @cutoff;
