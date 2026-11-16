package dynamic

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresConfig struct {
	ConnectionURL string `json:"connection_url"`
}

type PostgresDriver struct{}

func init() {
	RegisterDriver(&PostgresDriver{})
}

func (d *PostgresDriver) Engine() string {
	return "postgres"
}

func (d *PostgresDriver) ValidateConfig(configJSON []byte) error {
	var cfg PostgresConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing postgres config: %w", err)
	}
	if cfg.ConnectionURL == "" {
		return fmt.Errorf("connection_url is required")
	}
	if !strings.HasPrefix(cfg.ConnectionURL, "postgres://") && !strings.HasPrefix(cfg.ConnectionURL, "postgresql://") {
		return fmt.Errorf("connection_url must start with postgres:// or postgresql://")
	}
	return nil
}

func (d *PostgresDriver) Test(ctx context.Context, configJSON []byte) error {
	var cfg PostgresConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return err
	}
	db, err := sql.Open("pgx", cfg.ConnectionURL)
	if err != nil {
		return fmt.Errorf("connecting to target postgres: %w", err)
	}
	defer db.Close()

	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return db.PingContext(ctxTimeout)
}

func escapePGLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (d *PostgresDriver) IssueLease(ctx context.Context, configJSON []byte, roleTemplate, username, password string, ttl time.Duration) (*LeaseCredentials, error) {
	if err := validateLeaseUsername(username); err != nil {
		return nil, err
	}
	if strings.ContainsRune(password, 0) {
		return nil, fmt.Errorf("password contains invalid NUL byte")
	}
	if roleTemplate != "" {
		if err := validateSQLRoleTemplate(roleTemplate); err != nil {
			return nil, err
		}
	}

	var cfg PostgresConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", cfg.ConnectionURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	defer db.Close()

	quotedRole := pgx.Identifier{username}.Sanitize()
	expiryStr := time.Now().Add(ttl).UTC().Format("2006-01-02 15:04:05 UTC")

	// 1. Create temporary role with sanitized identifier and escaped password literal
	createQuery := fmt.Sprintf(`CREATE ROLE %s WITH LOGIN PASSWORD %s VALID UNTIL %s;`,
		quotedRole, escapePGLiteral(password), escapePGLiteral(expiryStr))

	if _, err := db.ExecContext(ctx, createQuery); err != nil {
		return nil, fmt.Errorf("creating postgres role %s: %w", username, err)
	}

	// 2. Apply privileges / roleTemplate
	if roleTemplate != "" {
		statements := strings.Split(roleTemplate, ";")
		for _, rawStmt := range statements {
			stmt := strings.TrimSpace(rawStmt)
			if stmt == "" {
				continue
			}
			stmt = strings.ReplaceAll(stmt, "{{name}}", quotedRole)
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				_, _ = db.ExecContext(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s;`, quotedRole))
				return nil, fmt.Errorf("applying role template statement %q: %w", stmt, err)
			}
		}
	} else {
		defaultStmts := []string{
			fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, quotedRole),
			fmt.Sprintf(`GRANT SELECT ON ALL TABLES IN SCHEMA public TO %s`, quotedRole),
		}
		for _, stmt := range defaultStmts {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				_, _ = db.ExecContext(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s;`, quotedRole))
				return nil, fmt.Errorf("applying default postgres grants: %w", err)
			}
		}
	}

	// Build lease connection URL
	leaseURL := cfg.ConnectionURL
	if u, err := url.Parse(cfg.ConnectionURL); err == nil {
		u.User = url.UserPassword(username, password)
		leaseURL = u.String()
	}

	return &LeaseCredentials{
		Username:   username,
		Password:   password,
		ConnString: leaseURL,
		Engine:     d.Engine(),
	}, nil
}

func (d *PostgresDriver) RevokeLease(ctx context.Context, configJSON []byte, username string) error {
	if err := validateLeaseUsername(username); err != nil {
		return err
	}
	var cfg PostgresConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return err
	}
	db, err := sql.Open("pgx", cfg.ConnectionURL)
	if err != nil {
		return fmt.Errorf("connecting to postgres: %w", err)
	}
	defer db.Close()

	// 1. Terminate active sessions with parameterized username
	_, _ = db.ExecContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1`, username)

	// 2. Check role existence via parameter binding, then drop with pgx.Identifier sanitization
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, username).Scan(&exists); err != nil {
		return fmt.Errorf("checking postgres role %s: %w", username, err)
	}
	if !exists {
		return nil
	}

	quotedRole := pgx.Identifier{username}.Sanitize()
	for _, q := range []string{
		fmt.Sprintf(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %s`, quotedRole),
		fmt.Sprintf(`DROP OWNED BY %s`, quotedRole),
		fmt.Sprintf(`DROP ROLE %s`, quotedRole),
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("revoking postgres role %s: %w", username, err)
		}
	}

	return nil
}
