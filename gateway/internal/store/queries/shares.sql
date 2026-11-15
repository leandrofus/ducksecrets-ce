-- name: CreateShare :exec
INSERT INTO shares (id, ciphertext, nonce, expires_at, max_views, view_count, has_passphrase, passphrase_salt, created_by, created_at, burned_at)
VALUES (@id, @ciphertext, @nonce, @expires_at, @max_views, 0, @has_passphrase, @passphrase_salt, @created_by, @now, NULL);

-- name: GetShareMetadata :one
SELECT id, expires_at, max_views, view_count, has_passphrase, passphrase_salt, created_by, created_at, burned_at
FROM shares
WHERE id = @id;

-- name: GetShareForReveal :one
SELECT id, ciphertext, nonce, expires_at, max_views, view_count, has_passphrase, passphrase_salt, created_by, created_at, burned_at
FROM shares
WHERE id = @id;

-- name: IncrementShareView :exec
UPDATE shares
SET view_count = view_count + 1
WHERE id = @id;

-- name: ConsumeShareView :execrows
UPDATE shares
SET view_count = view_count + 1
WHERE id = @id
  AND burned_at IS NULL
  AND view_count < max_views
  AND expires_at > @now;

-- name: BurnShare :exec
UPDATE shares
SET burned_at = @burned_at,
    ciphertext = @empty_ciphertext,
    nonce = @empty_nonce
WHERE id = @id;

-- name: DeleteShare :execrows
DELETE FROM shares
WHERE id = @id;

-- name: ListSharesByCreator :many
SELECT id, expires_at, max_views, view_count, has_passphrase, passphrase_salt, created_by, created_at, burned_at
FROM shares
WHERE created_by = @created_by
ORDER BY created_at DESC;

-- name: DeleteExpiredShares :execrows
DELETE FROM shares
WHERE expires_at < @now OR (burned_at IS NOT NULL AND burned_at < @burned_cutoff);
