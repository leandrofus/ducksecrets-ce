// Package store is the persistence layer: SQLite (one node, nothing to run)
// or PostgreSQL (several gateways sharing one database), with goose
// migrations per engine and sqlc-generated queries in package db that run
// unchanged on both.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrations embed.FS

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type storeBackend struct {
	db       *sql.DB
	postgres bool
}

type Store struct {
	DB *sql.DB
	Q  *db.Queries
	// Postgres: the database is PostgreSQL (else SQLite).
	Postgres bool

	mu      sync.RWMutex
	backend atomic.Pointer[storeBackend]
}

type storeDBTX struct {
	s *Store
}

func (d *storeDBTX) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	d.s.mu.RLock()
	defer d.s.mu.RUnlock()
	return d.s.backend.Load().db.ExecContext(ctx, query, args...)
}

func (d *storeDBTX) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	d.s.mu.RLock()
	defer d.s.mu.RUnlock()
	return d.s.backend.Load().db.PrepareContext(ctx, query)
}

func (d *storeDBTX) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	d.s.mu.RLock()
	defer d.s.mu.RUnlock()
	return d.s.backend.Load().db.QueryContext(ctx, query, args...)
}

func (d *storeDBTX) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	d.s.mu.RLock()
	defer d.s.mu.RUnlock()
	return d.s.backend.Load().db.QueryRowContext(ctx, query, args...)
}

func newStore(sqldb *sql.DB, postgres bool) *Store {
	s := &Store{DB: sqldb, Postgres: postgres}
	s.backend.Store(&storeBackend{db: sqldb, postgres: postgres})
	s.Q = db.New(&storeDBTX{s: s})
	return s
}

// IsPostgresDB reports safely whether the active store backend is PostgreSQL.
func (s *Store) IsPostgresDB() bool {
	if b := s.backend.Load(); b != nil {
		return b.postgres
	}
	return s.Postgres
}

// PingContext checks database liveness against the active store backend.
func (s *Store) PingContext(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backend.Load().db.PingContext(ctx)
}

// IsPostgres reports whether a DUCKSECRETS_DB value names a PostgreSQL database,
// supporting both URI DSNs (postgres:// / postgresql://) and libpq key=value strings.
func IsPostgres(dsn string) bool {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return true
	}
	return isPostgresKV(dsn)
}

func isPostgresKV(dsn string) bool {
	fields := strings.Fields(dsn)
	if len(fields) < 2 {
		return false
	}
	var hasHost, hasConnAttr bool
	for _, f := range fields {
		k, _, ok := strings.Cut(f, "=")
		if !ok {
			return false
		}
		switch k {
		case "host", "hostaddr":
			hasHost = true
		case "dbname", "user", "password", "port", "sslmode", "service":
			hasConnAttr = true
		}
	}
	return hasHost && hasConnAttr
}

// Open opens the database and migrates it: a postgres:// URL, or the path
// of a SQLite file (created if needed).
func Open(dsn string) (*Store, error) {
	if IsPostgres(dsn) {
		return openPostgres(dsn)
	}
	return openSQLite(dsn)
}

func openPostgres(dsn string) (*Store, error) {
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(20)
	sqldb.SetConnMaxIdleTime(5 * time.Minute)
	if err := migrate(sqldb, "postgres", "migrations/postgres"); err != nil {
		sqldb.Close()
		return nil, err
	}
	return newStore(sqldb, true), nil
}

func openSQLite(path string) (*Store, error) {
	isFile := path != ":memory:" && !strings.HasPrefix(path, "file:")
	if isFile {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("creating sqlite directory: %w", err)
			}
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("creating sqlite database file: %w", err)
		}
		_ = f.Close()
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("securing sqlite permissions: %w", err)
		}
	}

	// _txlock=immediate: write transactions take the lock up front, so two
	// writers never deadlock upgrading from a read lock.
	// _time_format=sqlite: store times as "2006-01-02 15:04:05.999999999-07:00",
	// which SQLite's date functions parse; the driver default (time.String())
	// is opaque to julianday().
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_txlock=immediate&_time_format=sqlite"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(1)
	if err := migrate(sqldb, "sqlite3", "migrations/sqlite"); err != nil {
		sqldb.Close()
		return nil, err
	}
	if isFile {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if _, statErr := os.Stat(path + suffix); statErr == nil {
				_ = os.Chmod(path+suffix, 0o600)
			}
		}
	}
	return newStore(sqldb, false), nil
}

func migrate(sqldb *sql.DB, dialect, dir string) error {
	p, err := goose.NewProvider(goose.Dialect(dialect), sqldb, mustSub(dir))
	if err != nil {
		return err
	}
	if _, err := p.Up(context.Background()); err != nil {
		return fmt.Errorf("migrating: %w", err)
	}
	return nil
}

func mustSub(dir string) fs.FS {
	f, err := fs.Sub(migrations, dir)
	if err != nil {
		panic(err)
	}
	return f
}

// writeLock is the advisory lock every PostgreSQL write transaction takes:
// writes are serialized, as SQLite does (_txlock=immediate), so anything
// read then appended inside a transaction (the audit chain) never forks,
// even across gateways sharing the database.
const writeLock = 0x6475636b // "duck"

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.backend.Load(); b != nil {
		return b.db.Close()
	}
	return s.DB.Close()
}

// Tx runs fn in a transaction, committing if it returns nil.
func (s *Store) Tx(ctx context.Context, fn func(q *db.Queries) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.backend.Load()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if b.postgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, writeLock); err != nil {
			return err
		}
	}
	if err := fn(db.New(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

// NewID returns a time-ordered UUIDv7.
func NewID() string { return uuid.Must(uuid.NewV7()).String() }

// Now is the timestamp every row gets: UTC, to the microsecond, which both
// SQLite and PostgreSQL store exactly (audit hashes cover it).
func Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// TS formats t like stored timestamps, for the queries that compare them
// with julianday().
func TS(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.999999999-07:00") }

func NullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func NullTime(t time.Time) sql.NullTime { return sql.NullTime{Time: t.UTC(), Valid: !t.IsZero()} }

// Classify maps driver errors to ErrNotFound / ErrConflict, keeping the
// original message.
func Classify(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	}
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "FOREIGN KEY constraint failed") {
		return fmt.Errorf("%w: %s", ErrConflict, msg)
	}
	// PostgreSQL: worded like SQLite's, which callers look for.
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return fmt.Errorf("%w: UNIQUE constraint failed: %s", ErrConflict, pe.ConstraintName)
		case "23503":
			return fmt.Errorf("%w: FOREIGN KEY constraint failed: %s", ErrConflict, pe.ConstraintName)
		}
	}
	return err
}
