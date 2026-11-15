package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// MigrationReport summarizes the row count migrated per table.
type MigrationReport struct {
	Tables    map[string]int64 `json:"tables"`
	TotalRows int64            `json:"total_rows"`
	Engine    string           `json:"engine"`
}

var migrateMu sync.Mutex

// TestPostgresConnection verifies that the PostgreSQL database is reachable and accepts connections.
func TestPostgresConnection(ctx context.Context, dsn string) error {
	if !IsPostgres(dsn) {
		return fmt.Errorf("invalid PostgreSQL URL: must start with postgres:// or postgresql://")
	}
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("connecting to postgres: %w", err)
	}
	defer sqldb.Close()

	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := sqldb.PingContext(ctxTimeout); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return nil
}

// MigrateToPostgres copies all data from the current SQLite store to target PostgreSQL,
// verifies row counts, and hot-swaps the active store connection.
func (s *Store) MigrateToPostgres(ctx context.Context, pgDSN string) (*MigrationReport, error) {
	migrateMu.Lock()
	defer migrateMu.Unlock()

	if s.IsPostgresDB() {
		return nil, fmt.Errorf("database is already running on PostgreSQL")
	}
	if !IsPostgres(pgDSN) {
		return nil, fmt.Errorf("invalid target PostgreSQL connection URL")
	}

	// 1. Open and migrate PostgreSQL schema up
	targetStore, err := openPostgres(pgDSN)
	if err != nil {
		return nil, fmt.Errorf("initializing postgres target schema: %w", err)
	}
	targetDB := targetStore.backend.Load().db

	report := &MigrationReport{
		Tables: make(map[string]int64),
		Engine: "postgres",
	}

	// Freeze live queries/writes only for the snapshot copy + commit + backend swap
	// so no in-flight SQLite writes are lost and there is no data race on hot-swap.
	var oldDB *sql.DB
	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		oldB := s.backend.Load()
		if oldB.postgres {
			return fmt.Errorf("database is already running on PostgreSQL")
		}
		oldDB = oldB.db

		tx, err := targetDB.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("starting target postgres transaction: %w", err)
		}
		defer tx.Rollback()

		// Refuse migrating into a target PostgreSQL database that already has immutable audit events,
		// and clean all non-audit tables so re-trying onto an empty/partially seeded target succeeds.
		var auditExists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM audit_events)`).Scan(&auditExists); err != nil {
			return fmt.Errorf("checking target audit_events: %w", err)
		}
		if auditExists {
			return fmt.Errorf("target PostgreSQL audit_events is non-empty and append-only; use an empty target database")
		}
		truncateQuery := `
			TRUNCATE TABLE
				project_policies,
				rotation_policies,
				dynamic_leases,
				dynamic_providers,
				sites,
				shares,
				service_tokens,
				secret_versions,
				secrets,
				environments,
				projects,
				grants,
				web_sessions,
				users,
				notes,
				system_settings
			CASCADE;
		`
		if _, err := tx.ExecContext(ctx, truncateQuery); err != nil {
			return fmt.Errorf("cleaning target tables: %w", err)
		}

		// Helper for copying table rows
		copyTable := func(name string, selectSQL string, insertSQL string, scanAndExec func(rows *sql.Rows, stmt *sql.Stmt) error) error {
			rows, err := oldDB.QueryContext(ctx, selectSQL)
			if err != nil {
				return fmt.Errorf("reading from sqlite %s: %w", name, err)
			}
			defer rows.Close()

			stmt, err := tx.PrepareContext(ctx, insertSQL)
			if err != nil {
				return fmt.Errorf("preparing insert for %s: %w", name, err)
			}
			defer stmt.Close()

			var count int64
			for rows.Next() {
				if err := scanAndExec(rows, stmt); err != nil {
					return fmt.Errorf("copying row in %s: %w", name, err)
				}
				count++
			}
			if err := rows.Err(); err != nil {
				return err
			}
			report.Tables[name] = count
			report.TotalRows += count
			return nil
		}

		// 3. Roles
		err = copyTable("roles",
			"SELECT name, description, permissions, builtin FROM roles",
			`INSERT INTO roles (name, description, permissions, builtin) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, permissions = EXCLUDED.permissions, builtin = EXCLUDED.builtin`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var name, desc, perms string
				var builtin bool
				if err := rows.Scan(&name, &desc, &perms, &builtin); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, name, desc, perms, builtin)
				return err
			})
		if err != nil {
			return err
		}

		// 4. Users
		err = copyTable("users",
			"SELECT id, username, display_name, password_hash, source, role, disabled, created_at, updated_at, last_login_at FROM users",
			`INSERT INTO users (id, username, display_name, password_hash, source, role, disabled, created_at, updated_at, last_login_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, username, displayName, pwHash, source, role string
				var disabled bool
				var createdAt, updatedAt time.Time
				var lastLoginAt sql.NullTime
				if err := rows.Scan(&id, &username, &displayName, &pwHash, &source, &role, &disabled, &createdAt, &updatedAt, &lastLoginAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, username, displayName, pwHash, source, role, disabled, createdAt, updatedAt, lastLoginAt)
				return err
			})
		if err != nil {
			return err
		}

		// 5. Web Sessions
		err = copyTable("web_sessions",
			"SELECT id_hash, user_id, ip, user_agent, created_at, last_seen_at, expires_at FROM web_sessions",
			`INSERT INTO web_sessions (id_hash, user_id, ip, user_agent, created_at, last_seen_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var idHash, userID, ip, ua string
				var createdAt, lastSeenAt, expiresAt time.Time
				if err := rows.Scan(&idHash, &userID, &ip, &ua, &createdAt, &lastSeenAt, &expiresAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, idHash, userID, ip, ua, createdAt, lastSeenAt, expiresAt)
				return err
			})
		if err != nil {
			return err
		}

		// 6. Grants
		err = copyTable("grants",
			"SELECT id, subject_type, subject_id, object_type, object_id, permission, created_at FROM grants",
			`INSERT INTO grants (id, subject_type, subject_id, object_type, object_id, permission, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, subType, subID, objType, objID, perm string
				var createdAt time.Time
				if err := rows.Scan(&id, &subType, &subID, &objType, &objID, &perm, &createdAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, subType, subID, objType, objID, perm, createdAt)
				return err
			})
		if err != nil {
			return err
		}

		// 7. Audit Events
		err = copyTable("audit_events",
			"SELECT seq, actor_id, actor_username, actor_ip, action, target_type, target_id, details, prev_hash, hash, created_at FROM audit_events ORDER BY seq ASC",
			`INSERT INTO audit_events (seq, actor_id, actor_username, actor_ip, action, target_type, target_id, details, prev_hash, hash, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var seq int64
				var actorID, actorUser, actorIP, action, targetType, targetID, details, prevHash, hash string
				var createdAt time.Time
				if err := rows.Scan(&seq, &actorID, &actorUser, &actorIP, &action, &targetType, &targetID, &details, &prevHash, &hash, &createdAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, seq, actorID, actorUser, actorIP, action, targetType, targetID, details, prevHash, hash, createdAt)
				return err
			})
		if err != nil {
			return err
		}

		// 8. Projects
		err = copyTable("projects",
			"SELECT id, name, slug, description, created_at, updated_at FROM projects",
			`INSERT INTO projects (id, name, slug, description, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, name, slug, desc string
				var createdAt, updatedAt time.Time
				if err := rows.Scan(&id, &name, &slug, &desc, &createdAt, &updatedAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, name, slug, desc, createdAt, updatedAt)
				return err
			})
		if err != nil {
			return err
		}

		// 9. Environments
		err = copyTable("environments",
			"SELECT id, project_id, name, slug, position, created_at FROM environments",
			`INSERT INTO environments (id, project_id, name, slug, position, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, projectID, name, slug string
				var pos int32
				var createdAt time.Time
				if err := rows.Scan(&id, &projectID, &name, &slug, &pos, &createdAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, projectID, name, slug, pos, createdAt)
				return err
			})
		if err != nil {
			return err
		}

		// 9b. Service Tokens
		err = copyTable("service_tokens",
			"SELECT id, name, token_hash, token_prefix, project_id, environment_slug, path, permissions, allowed_cidrs, single_use, burned_at, created_by, created_at, expires_at, last_used_at FROM service_tokens",
			`INSERT INTO service_tokens (id, name, token_hash, token_prefix, project_id, environment_slug, path, permissions, allowed_cidrs, single_use, burned_at, created_by, created_at, expires_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, name, tokenHash, tokenPrefix, projectID, envSlug, path, perms, allowedCidrs, createdBy string
				var singleUse bool
				var createdAt time.Time
				var burnedAt, expiresAt, lastUsedAt sql.NullTime
				if err := rows.Scan(&id, &name, &tokenHash, &tokenPrefix, &projectID, &envSlug, &path, &perms, &allowedCidrs, &singleUse, &burnedAt, &createdBy, &createdAt, &expiresAt, &lastUsedAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, name, tokenHash, tokenPrefix, projectID, envSlug, path, perms, allowedCidrs, singleUse, burnedAt, createdBy, createdAt, expiresAt, lastUsedAt)
				return err
			})
		if err != nil {
			return err
		}

		// 10. Secrets
		err = copyTable("secrets",
			"SELECT id, project_id, environment_slug, path, key, value_encrypted, value_nonce, comment, version, created_at, updated_at FROM secrets",
			`INSERT INTO secrets (id, project_id, environment_slug, path, key, value_encrypted, value_nonce, comment, version, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, projectID, envSlug, path, key, comment string
				var valEnc, valNonce []byte
				var version int32
				var createdAt, updatedAt time.Time
				if err := rows.Scan(&id, &projectID, &envSlug, &path, &key, &valEnc, &valNonce, &comment, &version, &createdAt, &updatedAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, projectID, envSlug, path, key, valEnc, valNonce, comment, version, createdAt, updatedAt)
				return err
			})
		if err != nil {
			return err
		}

		// 11. Secret Versions
		err = copyTable("secret_versions",
			"SELECT id, secret_id, version, value_encrypted, value_nonce, comment, created_at, created_by FROM secret_versions",
			`INSERT INTO secret_versions (id, secret_id, version, value_encrypted, value_nonce, comment, created_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, secretID, comment, createdBy string
				var version int32
				var valEnc, valNonce []byte
				var createdAt time.Time
				if err := rows.Scan(&id, &secretID, &version, &valEnc, &valNonce, &comment, &createdAt, &createdBy); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, secretID, version, valEnc, valNonce, comment, createdAt, createdBy)
				return err
			})
		if err != nil {
			return err
		}

		// 12. Notes (if any)
		err = copyTable("notes",
			"SELECT id, title, body, pinned, created_at, updated_at FROM notes",
			`INSERT INTO notes (id, title, body, pinned, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, title, body string
				var pinned bool
				var createdAt, updatedAt time.Time
				if err := rows.Scan(&id, &title, &body, &pinned, &createdAt, &updatedAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, title, body, pinned, createdAt, updatedAt)
				return err
			})
		if err != nil {
			return err
		}

		// 13. Shares
		err = copyTable("shares",
			"SELECT id, ciphertext, nonce, expires_at, max_views, view_count, has_passphrase, passphrase_salt, created_by, created_at, burned_at FROM shares",
			`INSERT INTO shares (id, ciphertext, nonce, expires_at, max_views, view_count, has_passphrase, passphrase_salt, created_by, created_at, burned_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, createdBy string
				var ciphertext, nonce, passphraseSalt []byte
				var expiresAt, createdAt time.Time
				var maxViews, viewCount int32
				var hasPassphrase bool
				var burnedAt sql.NullTime
				if err := rows.Scan(&id, &ciphertext, &nonce, &expiresAt, &maxViews, &viewCount, &hasPassphrase, &passphraseSalt, &createdBy, &createdAt, &burnedAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, ciphertext, nonce, expiresAt, maxViews, viewCount, hasPassphrase, passphraseSalt, createdBy, createdAt, burnedAt)
				return err
			})
		if err != nil {
			return err
		}

		// 14. Network Sites
		err = copyTable("sites",
			"SELECT id, project_id, name, token_hash, token_prefix, description, last_seen_at, created_at, updated_at FROM sites",
			`INSERT INTO sites (id, project_id, name, token_hash, token_prefix, description, last_seen_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, projectID, name, tokenHash, tokenPrefix, description string
				var lastSeenAt sql.NullTime
				var createdAt, updatedAt time.Time
				if err := rows.Scan(&id, &projectID, &name, &tokenHash, &tokenPrefix, &description, &lastSeenAt, &createdAt, &updatedAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, projectID, name, tokenHash, tokenPrefix, description, lastSeenAt, createdAt, updatedAt)
				return err
			})
		if err != nil {
			return err
		}

		// 15. Dynamic Providers
		err = copyTable("dynamic_providers",
			"SELECT id, project_id, environment_slug, name, engine, config_encrypted, config_nonce, default_ttl_seconds, max_ttl_seconds, role_template, enforced_port, site_id, created_at, updated_at FROM dynamic_providers",
			`INSERT INTO dynamic_providers (id, project_id, environment_slug, name, engine, config_encrypted, config_nonce, default_ttl_seconds, max_ttl_seconds, role_template, enforced_port, site_id, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, projectID, envSlug, name, engine, roleTemplate string
				var siteID sql.NullString
				var cfgEnc, cfgNonce []byte
				var defTTL, maxTTL, enforcedPort int32
				var createdAt, updatedAt time.Time
				if err := rows.Scan(&id, &projectID, &envSlug, &name, &engine, &cfgEnc, &cfgNonce, &defTTL, &maxTTL, &roleTemplate, &enforcedPort, &siteID, &createdAt, &updatedAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, projectID, envSlug, name, engine, cfgEnc, cfgNonce, defTTL, maxTTL, roleTemplate, enforcedPort, siteID, createdAt, updatedAt)
				return err
			})
		if err != nil {
			return err
		}

		// 16. Dynamic Leases
		err = copyTable("dynamic_leases",
			"SELECT id, provider_id, username, credentials_encrypted, credentials_nonce, issued_to, expires_at, revoked_at, created_at FROM dynamic_leases",
			`INSERT INTO dynamic_leases (id, provider_id, username, credentials_encrypted, credentials_nonce, issued_to, expires_at, revoked_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, providerID, username, issuedTo string
				var credsEnc, credsNonce []byte
				var expiresAt, createdAt time.Time
				var revokedAt sql.NullTime
				if err := rows.Scan(&id, &providerID, &username, &credsEnc, &credsNonce, &issuedTo, &expiresAt, &revokedAt, &createdAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, providerID, username, credsEnc, credsNonce, issuedTo, expiresAt, revokedAt, createdAt)
				return err
			})
		if err != nil {
			return err
		}

		// 17. Rotation Policies
		err = copyTable("rotation_policies",
			"SELECT id, secret_id, interval_seconds, generator_type, generator_config, verifier_type, verifier_config, last_rotated_at, next_rotation_at, status, last_error, created_at, updated_at FROM rotation_policies",
			`INSERT INTO rotation_policies (id, secret_id, interval_seconds, generator_type, generator_config, verifier_type, verifier_config, last_rotated_at, next_rotation_at, status, last_error, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, secretID, genType, genConfig, verType, verConfig, status, lastError string
				var intervalSec int32
				var lastRotated sql.NullTime
				var nextRotated, createdAt, updatedAt time.Time
				if err := rows.Scan(&id, &secretID, &intervalSec, &genType, &genConfig, &verType, &verConfig, &lastRotated, &nextRotated, &status, &lastError, &createdAt, &updatedAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, secretID, intervalSec, genType, genConfig, verType, verConfig, lastRotated, nextRotated, status, lastError, createdAt, updatedAt)
				return err
			})
		if err != nil {
			return err
		}

		// 18. Project Policies
		err = copyTable("project_policies",
			"SELECT id, project_id, subject_type, subject_id, environment_slug, can_read, can_write, can_admin, starts_at, expires_at, description, created_by, created_at FROM project_policies",
			`INSERT INTO project_policies (id, project_id, subject_type, subject_id, environment_slug, can_read, can_write, can_admin, starts_at, expires_at, description, created_by, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var id, projectID, subjectType, subjectID, envSlug, description string
				var canRead, canWrite, canAdmin bool
				var startsAt, expiresAt sql.NullTime
				var createdBy sql.NullString
				var createdAt time.Time
				if err := rows.Scan(&id, &projectID, &subjectType, &subjectID, &envSlug, &canRead, &canWrite, &canAdmin, &startsAt, &expiresAt, &description, &createdBy, &createdAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, id, projectID, subjectType, subjectID, envSlug, canRead, canWrite, canAdmin, startsAt, expiresAt, description, createdBy, createdAt)
				return err
			})
		if err != nil {
			return err
		}

		// 19. System Settings (persisted license, etc.)
		err = copyTable("system_settings",
			"SELECT key, value, updated_at FROM system_settings",
			`INSERT INTO system_settings (key, value, updated_at)
		 VALUES ($1, $2, $3)`,
			func(rows *sql.Rows, stmt *sql.Stmt) error {
				var key, val string
				var updatedAt time.Time
				if err := rows.Scan(&key, &val, &updatedAt); err != nil {
					return err
				}
				_, err := stmt.ExecContext(ctx, key, val, updatedAt)
				return err
			})
		if err != nil {
			return err
		}

		// Commit PostgreSQL transaction while SQLite writes are paused
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing target transaction: %w", err)
		}

		// Hot swap atomically under write lock
		s.backend.Store(&storeBackend{db: targetDB, postgres: true})
		s.DB = targetDB
		s.Postgres = true
		return nil
	}()
	if err != nil {
		targetStore.Close()
		return nil, err
	}

	// Close old SQLite DB in background after allowing any in-flight Row.Scan to finish
	go func() {
		time.Sleep(2 * time.Second)
		if err := oldDB.Close(); err != nil {
			slog.Warn("closing old sqlite db after migration", "err", err)
		}
	}()

	slog.Info("database successfully migrated from sqlite to postgres", "total_rows", report.TotalRows)
	return report, nil
}
