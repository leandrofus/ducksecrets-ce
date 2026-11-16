package server

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/leandrofus/ducksecrets/gateway/internal/audit"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/events"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/tlsutil"
)

func TestTLSCertificateUploadAndSelfSignedAPI(t *testing.T) {
	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()

	vault, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	certDir := t.TempDir()
	tlsMgr := tlsutil.NewManager(true, tlsutil.ModeSelfSigned, filepath.Join(certDir, "tls.crt"), filepath.Join(certDir, "tls.key"), nil)
	if _, err := tlsMgr.LoadOrInitFiles(filepath.Join(certDir, "tls.crt"), filepath.Join(certDir, "tls.key")); err != nil {
		t.Fatal(err)
	}

	trusted, err := ParseProxies("127.0.0.1/8")
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{
		Store:          st,
		Auth:           &auth.Service{Store: st},
		Audit:          &audit.Log{Store: st, Key: []byte("k")},
		Events:         events.New(),
		Vault:          vault,
		TLS:            tlsMgr,
		TrustedProxies: trusted,
		Version:        "test",
	}
	if _, err := srv.Auth.Bootstrap(context.Background(), "admin", "admin-password"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	admin := newClient(t, ts)
	admin.login("admin", "admin-password")
	admin.must(201, "POST", "/users", map[string]any{
		"username": "devuser",
		"password": "DevUser!123456",
		"role":     "user",
	}, nil)
	user := newClient(t, ts)
	user.login("devuser", "DevUser!123456")

	// Non-admin must be denied.
	user.must(403, "GET", "/system/tls", nil, nil)

	// Admin reads initial self-signed status + reverse proxy count.
	var initial tlsStatusDTO
	admin.must(200, "GET", "/system/tls", nil, &initial)
	if !initial.TLSActive || !initial.HasCert || initial.Mode != tlsutil.ModeSelfSigned || initial.TrustedProxiesCount != 1 {
		t.Fatalf("unexpected initial TLS status: %+v", initial)
	}

	// Uploading invalid PEM is rejected.
	admin.must(400, "PUT", "/system/tls", map[string]any{
		"cert_pem": "-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----",
		"key_pem":  "-----BEGIN PRIVATE KEY-----\nbad\n-----END PRIVATE KEY-----",
	}, nil)

	// Valid custom cert+key swaps live with zero restart required.
	certPEM, keyPEM, customInfo, err := tlsutil.GenerateSelfSigned([]string{"secrets.example.com"}, 90)
	if err != nil {
		t.Fatal(err)
	}
	var uploaded tlsStatusDTO
	admin.must(200, "PUT", "/system/tls", map[string]any{
		"cert_pem": string(certPEM),
		"key_pem":  string(keyPEM),
	}, &uploaded)
	if uploaded.Mode != tlsutil.ModeCustom || uploaded.FingerprintSHA256 != customInfo.FingerprintSHA256 || uploaded.RestartRequired {
		t.Fatalf("unexpected uploaded TLS status: %+v", uploaded)
	}

	// Reset reverts back to fresh self-signed certificate.
	var reverted tlsStatusDTO
	admin.must(200, "DELETE", "/system/tls", nil, &reverted)
	if reverted.Mode != tlsutil.ModeSelfSigned || reverted.FingerprintSHA256 == customInfo.FingerprintSHA256 {
		t.Fatalf("expected regenerated self-signed cert, got %+v", reverted)
	}
}
