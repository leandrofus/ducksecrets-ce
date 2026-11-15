package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// TestPostgresEnv names a PostgreSQL database the test suites run against
// instead of SQLite (make test-postgres sets it).
const TestPostgresEnv = "DUCKSECRETS_TEST_POSTGRES"

// OpenTemp opens an empty database for tests: a SQLite file in dir, or,
// with DUCKSECRETS_TEST_POSTGRES set, a fresh schema in that database. close
// removes it.
func OpenTemp(dir string) (s *Store, close func(), err error) {
	base := os.Getenv(TestPostgresEnv)
	if base == "" {
		s, err := Open(filepath.Join(dir, "t.db"))
		if err != nil {
			return nil, nil, err
		}
		return s, func() { s.Close() }, nil
	}
	schema := "t_" + strings.ReplaceAll(NewID(), "-", "")
	dsn, err := appendPostgresSearchPath(base, schema)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid %s: %w", TestPostgresEnv, err)
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		return nil, nil, err
	}
	defer admin.Close()
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		return nil, nil, err
	}
	dropSchema := func() {
		if a, err := sql.Open("pgx", base); err == nil {
			_, _ = a.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
			_ = a.Close()
		}
	}
	if s, err = Open(dsn); err != nil {
		dropSchema()
		return nil, nil, fmt.Errorf("opening schema %s: %w", schema, err)
	}
	return s, func() {
		_ = s.Close()
		dropSchema()
	}, nil
}

func appendPostgresSearchPath(base, schema string) (string, error) {
	switch {
	case strings.HasPrefix(base, "postgres://") || strings.HasPrefix(base, "postgresql://"):
		u, err := url.Parse(base)
		if err != nil {
			return "", err
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String(), nil
	case isPostgresKV(base):
		fields := strings.Fields(base)
		out := make([]string, 0, len(fields)+1)
		for _, f := range fields {
			if strings.HasPrefix(f, "search_path=") {
				continue
			}
			out = append(out, f)
		}
		out = append(out, "search_path="+schema)
		return strings.Join(out, " "), nil
	default:
		return "", errors.New("expected postgres:// URL or libpq key=value PostgreSQL DSN")
	}
}
