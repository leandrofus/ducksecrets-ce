package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

func TestShareData_RoundTrip(t *testing.T) {
	plain := []byte("super-secret-api-key-1234567890!@#$%^&*()")

	// 1. Without passphrase
	c64, n64, keyUrlSafe, s64, err := encryptShareData(plain, "")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if s64 != "" {
		t.Fatalf("expected empty salt without passphrase, got %s", s64)
	}

	decrypted, err := decryptShareData(c64, n64, keyUrlSafe, "", s64)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("expected %q, got %q", plain, decrypted)
	}

	// 2. With passphrase
	passphrase := "duck-vault-passphrase"
	c64Pass, n64Pass, keyPass, s64Pass, err := encryptShareData(plain, passphrase)
	if err != nil {
		t.Fatalf("encrypt with passphrase failed: %v", err)
	}
	if s64Pass == "" {
		t.Fatalf("expected non-empty salt with passphrase")
	}

	decryptedPass, err := decryptShareData(c64Pass, n64Pass, keyPass, passphrase, s64Pass)
	if err != nil {
		t.Fatalf("decrypt with passphrase failed: %v", err)
	}
	if !bytes.Equal(decryptedPass, plain) {
		t.Fatalf("expected %q, got %q", plain, decryptedPass)
	}

	// 3. Decrypt with wrong passphrase fails
	if _, err := decryptShareData(c64Pass, n64Pass, keyPass, "wrong-pass", s64Pass); err == nil {
		t.Fatalf("expected error when decrypting with wrong passphrase")
	}

	// 4. Decrypt with missing passphrase fails
	if _, err := decryptShareData(c64Pass, n64Pass, keyPass, "", s64Pass); err == nil {
		t.Fatalf("expected error when decrypting with missing passphrase")
	}

	// 5. Whitespace-only passphrase behaves identically to empty passphrase (no salt generated)
	_, _, _, s64WS, err := encryptShareData(plain, "   \t ")
	if err != nil {
		t.Fatalf("encrypt with whitespace passphrase failed: %v", err)
	}
	if s64WS != "" {
		t.Fatalf("expected empty salt for whitespace-only passphrase, got %q", s64WS)
	}
}

func TestCLIHelpers_EnvOriginExportExecAndWrap(t *testing.T) {
	// resolveProjectEnv keeps config/env value when flag is empty
	cfg := cliConfig{Project: "payments", Env: "prod"}
	resolveProjectEnv(&cfg, "", "")
	if cfg.Project != "payments" || cfg.Env != "prod" {
		t.Fatalf("expected preserved project/env, got %+v", cfg)
	}
	resolveProjectEnv(&cfg, "", "staging")
	if cfg.Env != "staging" {
		t.Fatalf("expected explicit flag override to staging, got %q", cfg.Env)
	}

	// sameOriginURL blocks cross-origin bearer token leakage
	if !sameOriginURL("https://vault.example.com", "https://vault.example.com/path") {
		t.Fatal("expected same-origin URLs to match")
	}
	if sameOriginURL("https://vault.example.com", "https://evil.example.com/#/share/1") {
		t.Fatal("expected different hosts not to match sameOriginURL")
	}
	if sameOriginURL("https://vault.example.com", "http://vault.example.com") {
		t.Fatal("expected different schemes not to match sameOriginURL")
	}

	// formatExportSecrets is deterministic, quotes values, and escapes \r/\n
	secrets := map[string]string{
		"Z_KEY": "line1\r\nline2",
		"A_KEY": `hello "world" \x`,
	}
	dotenv, err := formatExportSecrets(secrets, "dotenv")
	if err != nil {
		t.Fatal(err)
	}
	wantDotenv := "A_KEY=\"hello \\\"world\\\" \\\\x\"\nZ_KEY=\"line1\\r\\nline2\"\n"
	if dotenv != wantDotenv {
		t.Fatalf("unexpected dotenv output:\ngot:  %q\nwant: %q", dotenv, wantDotenv)
	}

	// buildExecClientCmd keeps passwords out of CLI args and avoids StrictHostKeyChecking=no by default
	myCmd := buildExecClientCmd("mysql", "u1", "s3cr3t", "appdb", 3307, false)
	if slices.Contains(myCmd.Args, "-ps3cr3t") || !slices.Contains(myCmd.Env, "MYSQL_PWD=s3cr3t") {
		t.Fatalf("mysql cmd leaked password in args or missed MYSQL_PWD: args=%v", myCmd.Args)
	}
	redCmd := buildExecClientCmd("redis", "u1", "rpass", "", 6379, false)
	if slices.Contains(redCmd.Args, "-a") || !slices.Contains(redCmd.Env, "REDISCLI_AUTH=rpass") {
		t.Fatalf("redis cmd leaked password in args or missed REDISCLI_AUTH: args=%v", redCmd.Args)
	}
	pgCmd := buildExecClientCmd("postgres", "u1", "pgpass", "mydb", 5432, false)
	if strings.Contains(strings.Join(pgCmd.Args, " "), "pgpass") || !slices.Contains(pgCmd.Env, "PGPASSWORD=pgpass") {
		t.Fatalf("postgres cmd leaked password in args or missed PGPASSWORD: args=%v", pgCmd.Args)
	}
	sshCmd := buildExecClientCmd("pam", "u1", "", "", 2222, false)
	if !slices.Contains(sshCmd.Args, "StrictHostKeyChecking=accept-new") || slices.Contains(sshCmd.Args, "StrictHostKeyChecking=no") {
		t.Fatalf("expected StrictHostKeyChecking=accept-new by default, got args=%v", sshCmd.Args)
	}

	// wrap Dockerfile rejects newline/injection and checks SHA-256 + HTTPS URLs
	if _, err := buildWrapDockerfile("alpine:latest\nRUN id", "", "", "", "", []string{"/bin/sh"}, nil); err == nil {
		t.Fatal("expected error for newline injection in srcImage")
	}
	if _, err := buildWrapDockerfile("alpine:latest", "", "", "", "app\nRUN evil", []string{"/bin/sh"}, nil); err == nil {
		t.Fatal("expected error for newline injection in USER")
	}
	if err := isTrustedDownloadURL("http://198.51.100.1/download/ducksecrets", false); err == nil {
		t.Fatal("expected plain HTTP remote download to be rejected by default")
	}
	if err := isTrustedDownloadURL("https://vault.example.com/download/ducksecrets", false); err != nil {
		t.Fatalf("expected HTTPS download URL to be allowed: %v", err)
	}
	payload := []byte("elf-binary-test")
	sum := sha256.Sum256(payload)
	if err := verifyBinarySHA256(payload, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("expected valid sha256 check to pass: %v", err)
	}
	if err := verifyBinarySHA256(payload, strings.Repeat("0", 64)); err == nil {
		t.Fatal("expected mismatched sha256 to fail")
	}
}
