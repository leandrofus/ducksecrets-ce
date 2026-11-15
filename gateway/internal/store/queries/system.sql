-- name: GetSystemSetting :one
SELECT * FROM system_settings
WHERE key = @key;

-- name: UpsertSystemSetting :exec
INSERT INTO system_settings (key, value, updated_at)
VALUES (@key, @value, @updated_at)
ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = EXCLUDED.updated_at;

-- name: DeleteSystemSetting :exec
DELETE FROM system_settings
WHERE key = @key;
