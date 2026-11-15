package dynamic

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDriverRegistry(t *testing.T) {
	expectedDrivers := []string{"postgres", "mysql", "redis", "pam"}
	for _, name := range expectedDrivers {
		d, err := GetDriver(name)
		if err != nil {
			t.Fatalf("expected driver %q to be registered, got error: %v", name, err)
		}
		if d == nil {
			t.Fatalf("driver %q is nil", name)
		}
	}

	_, err := GetDriver("unknown_engine_123")
	if err == nil {
		t.Fatal("expected error for unregistered driver, got nil")
	}
}

func TestGenerateRandomCredentials(t *testing.T) {
	u1, p1, err := GenerateRandomCredentials("duck_d_")
	if err != nil {
		t.Fatalf("failed to generate credentials: %v", err)
	}

	if !strings.HasPrefix(u1, "duck_d_") {
		t.Fatalf("username %q missing prefix", u1)
	}
	if len(u1) < 12 {
		t.Fatalf("username %q too short", u1)
	}
	if len(p1) != 40 {
		t.Fatalf("password length %d, want 40", len(p1))
	}

	u2, p2, _ := GenerateRandomCredentials("duck_d_")
	if u1 == u2 || p1 == p2 {
		t.Fatalf("credentials should be random and distinct: (%s, %s) vs (%s, %s)", u1, p1, u2, p2)
	}
}

func TestPAMDriver_Simulated(t *testing.T) {
	d, err := GetDriver("pam")
	if err != nil {
		t.Fatal(err)
	}

	configJSON := []byte(`{
		"host": "10.0.0.1",
		"port": 22,
		"mode": "simulated",
		"groups": "duck-devs"
	}`)

	ctx := context.Background()

	// Test connection
	if err := d.Test(ctx, configJSON); err != nil {
		t.Fatalf("simulated test connection failed: %v", err)
	}

	// Issue lease
	creds, err := d.IssueLease(ctx, configJSON, "sudo", "duck_testuser", "securepass123", 1*time.Hour)
	if err != nil {
		t.Fatalf("simulated issue lease failed: %v", err)
	}
	if creds.Username != "duck_testuser" {
		t.Fatalf("expected username duck_testuser, got %s", creds.Username)
	}
	if creds.Engine != "pam" {
		t.Fatalf("expected engine pam, got %s", creds.Engine)
	}
	if !strings.Contains(creds.ConnString, "ssh duck_testuser@10.0.0.1") {
		t.Fatalf("unexpected conn string: %s", creds.ConnString)
	}

	// Revoke lease
	if err := d.RevokeLease(ctx, configJSON, "duck_testuser"); err != nil {
		t.Fatalf("simulated revoke lease failed: %v", err)
	}
}

func TestPostgresDriver_ParseConfig(t *testing.T) {
	d, err := GetDriver("postgres")
	if err != nil {
		t.Fatal(err)
	}

	// Invalid config
	err = d.ValidateConfig([]byte(`{"host": ""}`))
	if err == nil {
		t.Fatal("expected error for empty host")
	}

	// Unreachable target returns error
	err = d.Test(context.Background(), []byte(`{"host": "127.0.0.1", "port": 54329, "database": "test", "username": "admin", "password": "x"}`))
	if err == nil {
		t.Fatal("expected connection error for unreachable host")
	}
}

func TestMySQLDriver_ParseConfig(t *testing.T) {
	d, err := GetDriver("mysql")
	if err != nil {
		t.Fatal(err)
	}

	// Invalid config
	err = d.ValidateConfig([]byte(`{"host": ""}`))
	if err == nil {
		t.Fatal("expected error for empty host")
	}

	// Unreachable target returns error
	err = d.Test(context.Background(), []byte(`{"host": "127.0.0.1", "port": 33069, "database": "test", "username": "admin", "password": "x"}`))
	if err == nil {
		t.Fatal("expected connection error for unreachable host")
	}
}

func TestRedisDriver_ParseConfig(t *testing.T) {
	d, err := GetDriver("redis")
	if err != nil {
		t.Fatal(err)
	}

	// Invalid config
	err = d.ValidateConfig([]byte(`{"host": ""}`))
	if err == nil {
		t.Fatal("expected error for empty host")
	}

	// Unreachable target returns error
	err = d.Test(context.Background(), []byte(`{"host": "127.0.0.1", "port": 63799}`))
	if err == nil {
		t.Fatal("expected connection error for unreachable host")
	}
}

func TestPAMInputValidation(t *testing.T) {
	d, err := GetDriver("pam")
	if err != nil {
		t.Fatal(err)
	}

	// Reject shell metacharacters in default_shell and groups
	if err := d.ValidateConfig([]byte(`{"mode":"local","default_shell":"/bin/bash;id"}`)); err == nil {
		t.Fatal("expected error for invalid default_shell")
	}
	if err := d.ValidateConfig([]byte(`{"mode":"local","groups":"sudo;rm -rf /"}`)); err == nil {
		t.Fatal("expected error for invalid groups")
	}
	if err := d.ValidateConfig([]byte(`{"mode":"invalid_mode"}`)); err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if err := d.ValidateConfig([]byte(`{"mode":"simulated","host":"127.0.0.1"}`)); err != nil {
		t.Fatalf("expected simulated config to validate, got: %v", err)
	}

	// RevokeLease rejects malformed usernames in local/command modes before invoking any command
	if err := d.RevokeLease(context.Background(), []byte(`{"mode":"command","revoke_cmd":"true"}`), "bad;user"); err == nil {
		t.Fatal("expected error for unsafe username in command mode")
	}
	if err := d.RevokeLease(context.Background(), []byte(`{"mode":"local"}`), "-rf"); err == nil {
		t.Fatal("expected error for leading hyphen username in local mode")
	}
}

func TestDynamicSQLAndRESPValidation(t *testing.T) {
	// validateLeaseUsername
	if err := validateLeaseUsername("duck_d_123abc"); err != nil {
		t.Fatalf("expected valid username, got %v", err)
	}
	for _, bad := range []string{"", "1bad", "bad;drop", "bad'user", "bad user", strings.Repeat("a", 64)} {
		if err := validateLeaseUsername(bad); err == nil {
			t.Fatalf("expected error for username %q", bad)
		}
	}

	// validateSQLRoleTemplate
	validTemplates := []string{
		"GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		"GRANT SELECT ON *.* TO {{name}};",
		"REVOKE ALL PRIVILEGES ON *.* FROM {{name}};",
	}
	for _, tmpl := range validTemplates {
		if err := validateSQLRoleTemplate(tmpl); err != nil {
			t.Fatalf("expected valid template %q, got %v", tmpl, err)
		}
	}
	badTemplates := []string{
		"GRANT SELECT ON *.* TO {{name}}; DROP TABLE secrets;",
		"SELECT 1; -- comment",
		"GRANT SELECT ON *.* TO {{name}} /* comment */",
		"DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$;",
		"GRANT SELECT ON 'bad' TO {{name}}",
	}
	for _, tmpl := range badTemplates {
		if err := validateSQLRoleTemplate(tmpl); err == nil {
			t.Fatalf("expected error for unsafe template %q", tmpl)
		}
	}

	// MySQL escaping and DSN password with '@'
	escaped := escapeMySQLLiteral("p'a\\s\ns\r\"")
	if escaped != `'p\'a\\s\ns\r\"'` {
		t.Fatalf("unexpected MySQL literal escape: %s", escaped)
	}
	dsn := buildMySQLLeaseDSN("admin:sec@ret@tcp(127.0.0.1:3306)/appdb?tls=true", "duck_u1", "p@ss:1")
	if dsn != "duck_u1:p@ss:1@tcp(127.0.0.1:3306)/appdb?tls=true" {
		t.Fatalf("unexpected MySQL lease DSN: %s", dsn)
	}

	// Postgres IssueLease rejects SQL injection in username or roleTemplate before connecting
	pg, _ := GetDriver("postgres")
	if _, err := pg.IssueLease(context.Background(), []byte(`{"host":"127.0.0.1","port":5432,"database":"d","username":"u","password":"p"}`), "DROP TABLE users;", "duck_ok", "pw", time.Minute); err == nil {
		t.Fatal("expected postgres IssueLease to reject DROP template")
	}
	if _, err := pg.IssueLease(context.Background(), []byte(`{"host":"127.0.0.1","port":5432,"database":"d","username":"u","password":"p"}`), "", "bad;role", "pw", time.Minute); err == nil {
		t.Fatal("expected postgres IssueLease to reject malformed username")
	}

	// MySQL IssueLease rejects overlong username (>32 chars) and bad roleTemplate
	my, _ := GetDriver("mysql")
	if _, err := my.IssueLease(context.Background(), []byte(`{"host":"127.0.0.1","port":3306,"database":"d","username":"u","password":"p"}`), "", strings.Repeat("a", 33), "pw", time.Minute); err == nil {
		t.Fatal("expected mysql IssueLease to reject >32 char username")
	}
	if _, err := my.IssueLease(context.Background(), []byte(`{"host":"127.0.0.1","port":3306,"database":"d","username":"u","password":"p"}`), "DELETE FROM mysql.user;", "duck_ok", "pw", time.Minute); err == nil {
		t.Fatal("expected mysql IssueLease to reject DELETE template")
	}

	// Redis RESP multi-bulk writer & CRLF / TLS parsing
	var sb strings.Builder
	if err := writeRESPCommand(&sb, "ACL", "SETUSER", "duck_u", "on", ">pa ss"); err != nil {
		t.Fatalf("writeRESPCommand failed: %v", err)
	}
	wantRESP := "*5\r\n$3\r\nACL\r\n$7\r\nSETUSER\r\n$6\r\nduck_u\r\n$2\r\non\r\n$6\r\n>pa ss\r\n"
	if sb.String() != wantRESP {
		t.Fatalf("unexpected RESP wire format:\ngot:  %q\nwant: %q", sb.String(), wantRESP)
	}
	addr, useTLS, err := parseRedisAddress("rediss://redis.internal:6380")
	if err != nil || !useTLS || addr != "redis.internal:6380" {
		t.Fatalf("unexpected parseRedisAddress result: addr=%q tls=%v err=%v", addr, useTLS, err)
	}
	rd, _ := GetDriver("redis")
	if _, err := rd.IssueLease(context.Background(), []byte(`{"host":"127.0.0.1","port":6379}`), "~*\r\nFLUSHALL", "duck_u", "pw", time.Minute); err == nil {
		t.Fatal("expected redis IssueLease to reject CRLF in roleTemplate")
	}
	if _, err := rd.IssueLease(context.Background(), []byte(`{"host":"127.0.0.1","port":6379}`), "", "duck_u", "bad pass", time.Minute); err == nil {
		t.Fatal("expected redis IssueLease to reject space in password")
	}
}
