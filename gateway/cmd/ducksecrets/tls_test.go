package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCLI_BuildTLSConfigAndClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Default client without custom TLS config should fail on self-signed httptest cert.
	defaultClient, err := newHTTPClient(cliConfig{}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := defaultClient.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatalf("expected default client to reject self-signed server cert")
	}

	// Custom --ca-cert PEM should verify and succeed.
	certPath := filepath.Join(t.TempDir(), "server.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	caClient, err := newHTTPClient(cliConfig{CACert: certPath}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := caClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("ca-cert client failed: %v", err)
	}
	resp.Body.Close()

	// SHA-256 leaf fingerprint pinning should succeed on match and fail on mismatch.
	sum := sha256.Sum256(srv.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])

	fpClient, err := newHTTPClient(cliConfig{TLSFingerprint: fp}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := fpClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("fingerprint client failed: %v", err)
	}
	resp2.Body.Close()

	badFPClient, err := newHTTPClient(cliConfig{TLSFingerprint: stringsRepeat0()}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp3, err := badFPClient.Get(srv.URL); err == nil {
		resp3.Body.Close()
		t.Fatalf("expected mismatched TLS fingerprint to fail")
	}

	// Explicit --insecure should allow connecting.
	insecureClient, err := newHTTPClient(cliConfig{InsecureTLS: true}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp4, err := insecureClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("insecure client failed: %v", err)
	}
	resp4.Body.Close()

	// Installer-managed cli.json defaults apply when ServerURL matches and ignore unrelated servers.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	cliJSONDir := filepath.Join(tmpHome, ".ducksecrets")
	if err := os.MkdirAll(cliJSONDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cliJSON := `{"server_url":"` + srv.URL + `","ca_cert":"` + certPath + `","tls_fingerprint":"` + fp + `"}`
	if err := os.WriteFile(filepath.Join(cliJSONDir, "cli.json"), []byte(cliJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded := loadConfig()
	if loaded.ServerURL != srv.URL || loaded.CACert != certPath || loaded.TLSFingerprint != fp {
		t.Fatalf("expected loadConfig to pick up cli.json trust defaults, got %+v", loaded)
	}
	loadedClient, err := newHTTPClient(loaded, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp5, err := loadedClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("cli.json pinned client failed: %v", err)
	}
	resp5.Body.Close()

	// Switching DUCKSECRETS_SERVER to another URL must NOT inherit the pinned cert from cli.json.
	t.Setenv("DUCKSECRETS_SERVER", "https://other.example:5179")
	otherCfg := loadConfig()
	if otherCfg.CACert != "" || otherCfg.TLSFingerprint != "" {
		t.Fatalf("expected other server NOT to inherit cli.json cert/fingerprint, got %+v", otherCfg)
	}
}

func stringsRepeat0() string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}
