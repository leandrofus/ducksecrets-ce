package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

func TestStoreBackendSynchronization(t *testing.T) {
	s, closeDB, err := OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()

	ctx := context.Background()
	if err := s.PingContext(ctx); err != nil {
		t.Fatalf("PingContext: %v", err)
	}

	if _, err := s.MigrateToPostgres(ctx, "sqlite://invalid"); err == nil {
		t.Fatal("expected MigrateToPostgres to reject non-postgres URL")
	}

	var wg sync.WaitGroup
	errs := make(chan error, 40)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Q.CountUsers(ctx); err != nil {
				errs <- err
				return
			}
			if err := s.PingContext(ctx); err != nil {
				errs <- err
				return
			}
			_ = s.IsPostgresDB()
		}()
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Tx(ctx, func(q *db.Queries) error {
				_, err := q.CountUsers(ctx)
				return err
			})
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent store error: %v", err)
	}
}

func TestOpenSQLiteSecurePermissions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sub", "secrets.db")
	s, err := openSQLite(dbPath)
	if err != nil {
		t.Fatalf("openSQLite: %v", err)
	}
	defer s.Close()

	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("sqlite file permissions = %04o, want 0600", perm)
	}
}

func TestIsPostgresAndTempDSN(t *testing.T) {
	for _, tc := range []struct {
		dsn  string
		want bool
	}{
		{"postgres://user:pass@127.0.0.1:5432/duck?sslmode=disable", true},
		{"postgresql://user@localhost/duck", true},
		{"host=127.0.0.1 user=ducksecrets dbname=ducksecrets sslmode=disable", true},
		{"host=127.0.0.1 port=5432 user=duck", true},
		{"ducksecrets.db", false},
		{"/var/lib/ducksecrets/host=1.db", false},
	} {
		if got := IsPostgres(tc.dsn); got != tc.want {
			t.Errorf("IsPostgres(%q) = %v, want %v", tc.dsn, got, tc.want)
		}
	}

	urlDSN, err := appendPostgresSearchPath("postgres://u:p@127.0.0.1:5432/db?sslmode=disable", "t_123")
	if err != nil {
		t.Fatalf("appendPostgresSearchPath URL: %v", err)
	}
	if !strings.Contains(urlDSN, "search_path=t_123") || !strings.Contains(urlDSN, "sslmode=disable") {
		t.Fatalf("unexpected URL DSN: %s", urlDSN)
	}

	kvDSN, err := appendPostgresSearchPath("host=127.0.0.1 user=u dbname=db search_path=old", "t_456")
	if err != nil {
		t.Fatalf("appendPostgresSearchPath KV: %v", err)
	}
	if strings.Contains(kvDSN, "search_path=old") || !strings.Contains(kvDSN, "search_path=t_456") {
		t.Fatalf("unexpected KV DSN: %s", kvDSN)
	}
	if !IsPostgres(kvDSN) {
		t.Fatalf("expected modified KV DSN to remain recognized by IsPostgres: %s", kvDSN)
	}

	if _, err := appendPostgresSearchPath("not-a-postgres-dsn", "t_789"); err == nil {
		t.Fatal("expected invalid DSN to be rejected")
	}

	t.Setenv(TestPostgresEnv, "not-a-postgres-dsn")
	tmpDir := t.TempDir()
	if _, _, err := OpenTemp(tmpDir); err == nil {
		t.Fatal("expected OpenTemp with invalid DUCKSECRETS_TEST_POSTGRES to fail")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "t.db")); err == nil {
		t.Fatal("OpenTemp must not create a local SQLite file when DUCKSECRETS_TEST_POSTGRES is set")
	}
}

func TestMigrationsTxClassifyAndDownSQLite(t *testing.T) {
	s, closeDB, err := OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()

	ctx := context.Background()

	// Hardening migration 00014 removes legacy notes.* permissions from role 'user'.
	role, err := s.Q.GetRole(ctx, "user")
	if err != nil {
		t.Fatalf("GetRole(user): %v", err)
	}
	if strings.Contains(role.Permissions, "notes.") {
		t.Fatalf("role user still contains legacy notes permissions: %q", role.Permissions)
	}
	if !strings.Contains(role.Permissions, "secrets.read") {
		t.Fatalf("role user missing secrets.read: %q", role.Permissions)
	}

	// Verify Classify on ErrNotFound and ErrConflict + Tx rollback/commit behavior.
	if err := Classify(sql.ErrNoRows); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Classify(ErrNoRows) = %v, want ErrNotFound", err)
	}
	now := Now()
	p1ID := NewID()
	if err := s.Q.CreateProject(ctx, db.CreateProjectParams{
		ID: p1ID, Slug: "proj-a", Name: "Project A", Now: now,
	}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	err = s.Q.CreateProject(ctx, db.CreateProjectParams{
		ID: NewID(), Slug: "proj-a", Name: "Dup", Now: now,
	})
	if !errors.Is(Classify(err), ErrConflict) {
		t.Fatalf("Classify(dup slug) = %v, want ErrConflict", err)
	}

	// Verify sites_token_hash_uidx enforces uniqueness across sites.
	if err := s.Q.CreateSite(ctx, db.CreateSiteParams{
		ID: NewID(), ProjectID: p1ID, Name: "site-1", TokenHash: "same-hash", TokenPrefix: "dks_1", Now: now,
	}); err != nil {
		t.Fatalf("CreateSite 1: %v", err)
	}
	if err := s.Q.CreateSite(ctx, db.CreateSiteParams{
		ID: NewID(), ProjectID: p1ID, Name: "site-2", TokenHash: "same-hash", TokenPrefix: "dks_2", Now: now,
	}); !errors.Is(Classify(err), ErrConflict) {
		t.Fatalf("CreateSite 2 with duplicate token_hash = %v, want ErrConflict", Classify(err))
	}

	// Verify Tx rolls back on error.
	sentinel := errors.New("rollback me")
	if err := s.Tx(ctx, func(q *db.Queries) error {
		if err := q.CreateProject(ctx, db.CreateProjectParams{
			ID: NewID(), Slug: "proj-rb", Name: "Rollback", Now: now,
		}); err != nil {
			return err
		}
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("Tx error = %v, want sentinel", err)
	}
	if _, err := s.Q.GetProjectBySlug(ctx, "proj-rb"); !errors.Is(Classify(err), ErrNotFound) {
		t.Fatalf("expected rolled-back project not to exist, got %v", err)
	}

	// On SQLite, verify Down migrations through 00011_sites.sql succeed cleanly.
	if !s.IsPostgresDB() {
		p, err := goose.NewProvider(goose.Dialect("sqlite3"), s.DB, mustSub("migrations/sqlite"))
		if err != nil {
			t.Fatalf("goose.NewProvider: %v", err)
		}
		if _, err := p.DownTo(ctx, 10); err != nil {
			t.Fatalf("DownTo(10): %v", err)
		}
	}
}

func TestMigrateToPostgresLive(t *testing.T) {
	pgURL := os.Getenv(TestPostgresEnv)
	if pgURL == "" {
		t.Skip("DUCKSECRETS_TEST_POSTGRES not set")
	}

	ctx := context.Background()

	// Exercise OpenTemp with a libpq key=value DSN against live PostgreSQL.
	u, err := url.Parse(pgURL)
	if err != nil {
		t.Fatalf("parse %s: %v", TestPostgresEnv, err)
	}
	pw, _ := u.User.Password()
	kvParts := []string{
		"host=" + u.Hostname(),
		"user=" + u.User.Username(),
		"dbname=" + strings.TrimPrefix(u.Path, "/"),
	}
	if port := u.Port(); port != "" {
		kvParts = append(kvParts, "port="+port)
	}
	if pw != "" {
		kvParts = append(kvParts, "password="+pw)
	}
	if ssl := u.Query().Get("sslmode"); ssl != "" {
		kvParts = append(kvParts, "sslmode="+ssl)
	}
	t.Run("key_value_open_temp", func(t *testing.T) {
		t.Setenv(TestPostgresEnv, strings.Join(kvParts, " "))
		kvStore, closeKV, err := OpenTemp(t.TempDir())
		if err != nil {
			t.Fatalf("OpenTemp KV DSN: %v", err)
		}
		defer closeKV()
		if !kvStore.IsPostgresDB() {
			t.Fatal("expected IsPostgresDB() == true for libpq key=value DSN")
		}
		if err := kvStore.PingContext(ctx); err != nil {
			t.Fatalf("PingContext KV DSN: %v", err)
		}
	})

	// Seed a SQLite database with rows including grants and audit_events, then migrate to Postgres.
	s, err := Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatalf("open sqlite source: %v", err)
	}
	defer func() {
		// Allow MigrateToPostgres's background closer to run, or close remaining active store.
		_ = s.Close()
	}()

	now := Now()
	pID := NewID()
	if err := s.Q.CreateProject(ctx, db.CreateProjectParams{
		ID: pID, Slug: "migrated-proj", Name: "Migrated Project", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO grants (id, subject_type, subject_id, object_type, object_id, permission, created_at) VALUES (?, 'role', 'user', 'project', ?, 'secrets.read', ?)`,
		NewID(), pID, TS(now),
	); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if err := s.Q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		Seq: 1, ActorUsername: "admin", ActorIP: "127.0.0.1", Action: "project.create",
		TargetType: "project", TargetID: pID, Details: "{}", PrevHash: "0000", Hash: "hash1", CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed audit event: %v", err)
	}
	if err := s.Q.UpsertSystemSetting(ctx, db.UpsertSystemSettingParams{
		Key: "license_token", Value: "dkl1.test.payload", UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed system setting: %v", err)
	}

	schema := "t_mig_" + strings.ReplaceAll(NewID(), "-", "")
	targetDSN, err := appendPostgresSearchPath(pgURL, schema)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", pgURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}()

	report, err := s.MigrateToPostgres(ctx, targetDSN)
	if err != nil {
		t.Fatalf("MigrateToPostgres: %v", err)
	}
	if !s.IsPostgresDB() {
		t.Fatal("expected IsPostgresDB() == true after migration")
	}
	if report.Tables["projects"] != 1 || report.Tables["grants"] != 1 || report.Tables["audit_events"] != 1 || report.Tables["system_settings"] != 1 {
		t.Fatalf("unexpected migrated table counts: %+v", report.Tables)
	}
	gotProj, err := s.Q.GetProjectBySlug(ctx, "migrated-proj")
	if err != nil || gotProj.ID != pID {
		t.Fatalf("GetProjectBySlug after migration = %+v, err=%v", gotProj, err)
	}
	// Let the background SQLite handle close before TempDir cleanup.
	time.Sleep(2100 * time.Millisecond)
}
