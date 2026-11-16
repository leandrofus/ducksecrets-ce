package dynamic

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type MySQLConfig struct {
	DSN string `json:"dsn"` // e.g. "root:secret@tcp(127.0.0.1:3306)/app"
}

type MySQLDriver struct{}

func init() {
	RegisterDriver(&MySQLDriver{})
}

func (d *MySQLDriver) Engine() string {
	return "mysql"
}

func (d *MySQLDriver) ValidateConfig(configJSON []byte) error {
	var cfg MySQLConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing mysql config: %w", err)
	}
	if cfg.DSN == "" {
		return fmt.Errorf("dsn is required (e.g. user:pass@tcp(host:3306)/dbname)")
	}
	return nil
}

func escapeMySQLLiteral(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`'`, `\'`,
		`"`, `\"`,
		"\n", `\n`,
		"\r", `\r`,
		"\x1a", `\Z`,
	)
	return "'" + r.Replace(s) + "'"
}

func buildMySQLLeaseDSN(baseDSN, username, password string) string {
	if idx := strings.LastIndex(baseDSN, "@"); idx != -1 {
		return fmt.Sprintf("%s:%s%s", username, password, baseDSN[idx:])
	}
	return baseDSN
}

func (d *MySQLDriver) Test(ctx context.Context, configJSON []byte) error {
	var cfg MySQLConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return err
	}
	db, err := sql.Open("mysql", cfg.DSN)
	if err != nil {
		return fmt.Errorf("connecting to mysql: %w", err)
	}
	defer db.Close()

	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return db.PingContext(ctxTimeout)
}

func (d *MySQLDriver) IssueLease(ctx context.Context, configJSON []byte, roleTemplate, username, password string, ttl time.Duration) (*LeaseCredentials, error) {
	// MySQL usernames are capped at 32 chars
	if err := validateLeaseUsername(username); err != nil || len(username) > 32 {
		return nil, fmt.Errorf("unsafe or overlong mysql username %q", username)
	}
	if strings.ContainsRune(password, 0) {
		return nil, fmt.Errorf("password contains invalid NUL byte")
	}
	if roleTemplate != "" {
		if err := validateSQLRoleTemplate(roleTemplate); err != nil {
			return nil, err
		}
	}

	var cfg MySQLConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("connecting to mysql: %w", err)
	}
	defer db.Close()

	quotedUser := escapeMySQLLiteral(username) + "@'%'"
	createUserQuery := fmt.Sprintf("CREATE USER %s IDENTIFIED BY %s;", quotedUser, escapeMySQLLiteral(password))
	if _, err := db.ExecContext(ctx, createUserQuery); err != nil {
		return nil, fmt.Errorf("creating mysql user: %w", err)
	}

	if roleTemplate != "" {
		for _, stmt := range strings.Split(roleTemplate, ";") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			stmt = strings.ReplaceAll(stmt, "{{name}}", quotedUser)
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				_, _ = db.ExecContext(context.Background(), fmt.Sprintf("DROP USER IF EXISTS %s;", quotedUser))
				return nil, fmt.Errorf("applying mysql role template statement %q: %w", stmt, err)
			}
		}
	} else {
		if _, err := db.ExecContext(ctx, fmt.Sprintf("GRANT SELECT ON *.* TO %s;", quotedUser)); err != nil {
			_, _ = db.ExecContext(context.Background(), fmt.Sprintf("DROP USER IF EXISTS %s;", quotedUser))
			return nil, fmt.Errorf("applying default mysql grants: %w", err)
		}
	}
	_, _ = db.ExecContext(ctx, "FLUSH PRIVILEGES;")

	return &LeaseCredentials{
		Username:   username,
		Password:   password,
		ConnString: buildMySQLLeaseDSN(cfg.DSN, username, password),
		Engine:     d.Engine(),
	}, nil
}

func (d *MySQLDriver) RevokeLease(ctx context.Context, configJSON []byte, username string) error {
	if err := validateLeaseUsername(username); err != nil || len(username) > 32 {
		return fmt.Errorf("unsafe mysql username %q", username)
	}
	var cfg MySQLConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return err
	}
	db, err := sql.Open("mysql", cfg.DSN)
	if err != nil {
		return fmt.Errorf("connecting to mysql: %w", err)
	}
	defer db.Close()

	dropQuery := fmt.Sprintf("DROP USER IF EXISTS %s@'%%';", escapeMySQLLiteral(username))
	if _, err := db.ExecContext(ctx, dropQuery); err != nil {
		return fmt.Errorf("dropping mysql user: %w", err)
	}
	_, _ = db.ExecContext(ctx, "FLUSH PRIVILEGES;")
	return nil
}
