package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDaemonLifecycleAndKeys(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "daemon.db")

	cfg := config{
		listen: "127.0.0.1:0",
		db:     dbPath,
		admin:  "rootadmin",
	}
	t.Setenv("DUCKSECRETS_ADMIN_PASSWORD", "Str0ng!DaemonPass1")
	t.Setenv("DUCKSECRETS_ADMIN_PASSWORD_RESET", "1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- runContext(ctx, cfg, ready)
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("daemon exited before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for daemon startup")
	}

	resp, err := http.Get("http://" + addr + "/api/v1/health")
	if err != nil {
		t.Fatalf("GET health: %v", err)
	}
	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		resp.Body.Close()
		t.Fatalf("decode health: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || health["status"] != "ok" {
		t.Fatalf("unexpected health response %d: %v", resp.StatusCode, health)
	}

	for _, suffix := range []string{".audit-key", ".encryption-key"} {
		p := dbPath + suffix
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s perm = %04o, want 0600", p, fi.Mode().Perm())
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(decoded) != 32 {
			t.Fatalf("%s did not contain a valid 32-byte hex key (len=%d err=%v)", p, len(decoded), err)
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("clean shutdown returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for daemon shutdown")
	}
}

func TestConfigHelpersAndErrors(t *testing.T) {
	t.Setenv("DUCKSECRETS_UNIT_KEY", "custom-val")
	if got := env("UNIT_KEY", "default"); got != "custom-val" {
		t.Fatalf("env = %q, want custom-val", got)
	}
	if got := env("MISSING_UNIT_KEY", "fallback"); got != "fallback" {
		t.Fatalf("env = %q, want fallback", got)
	}

	if _, err := loadAuditKey(config{db: "postgres://u:p@127.0.0.1:5432/db"}); err == nil {
		t.Fatal("expected postgres without audit key to error")
	}
	if _, err := loadEncryptionKey(config{db: "postgres://u:p@127.0.0.1:5432/db"}); err == nil {
		t.Fatal("expected postgres without encryption key to error")
	}

	hexKey := hex.EncodeToString(make([]byte, 32))
	k1, err := loadAuditKey(config{auditKey: hexKey})
	if err != nil || len(k1) != 32 {
		t.Fatalf("loadAuditKey explicit: %v", err)
	}
	k2, err := loadEncryptionKey(config{encryptionKey: hexKey})
	if err != nil || len(k2) != 32 {
		t.Fatalf("loadEncryptionKey explicit: %v", err)
	}

	if err := runContext(context.Background(), config{
		db:      filepath.Join(t.TempDir(), "bad.db"),
		proxies: "not-a-cidr",
	}, nil); err == nil {
		t.Fatal("expected invalid trusted-proxies to fail fast")
	}
}

func TestDaemonSelfSignedHTTPSAndFirstLoginSetup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "daemon.db")
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	t.Setenv("DUCKSECRETS_ADMIN_PASSWORD", "")
	cfg := config{
		listen:  "127.0.0.1:0",
		db:      dbPath,
		admin:   "admin",
		tlsMode: "self-signed",
		tlsCert: certPath,
		tlsKey:  keyPath,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- runContext(ctx, cfg, ready)
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("daemon exited before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for daemon startup")
	}

	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected generated TLS file %s: %v", p, err)
		}
	}

	httpsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test self-signed cert
		},
	}
	resp, err := httpsClient.Get("https://" + addr + "/api/v1/auth/setup")
	if err != nil {
		t.Fatalf("GET /api/v1/auth/setup over HTTPS: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var st struct {
		NeedsSetup bool `json:"needs_setup"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if !st.NeedsSetup {
		t.Fatalf("expected needs_setup=true on empty DB without DUCKSECRETS_ADMIN_PASSWORD")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("clean shutdown returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for daemon shutdown")
	}
}
