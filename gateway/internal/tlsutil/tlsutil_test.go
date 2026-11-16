package tlsutil

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestGenerateLoadAndHotSwapTLS(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	mgr := NewManager(true, ModeSelfSigned, certPath, keyPath, []string{"vault.local"})
	created, err := mgr.LoadOrInitFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrInitFiles failed: %v", err)
	}
	if !created {
		t.Fatalf("expected created=true on empty dir")
	}
	st := mgr.Status()
	if !st.HasCert || !st.Cert.SelfSigned || st.Mode != ModeSelfSigned {
		t.Fatalf("unexpected status: %+v", st)
	}
	firstFP := st.Cert.FingerprintSHA256

	// Calling LoadOrInitFiles again should reuse the existing files.
	created2, err := mgr.LoadOrInitFiles(certPath, keyPath)
	if err != nil || created2 {
		t.Fatalf("expected reuse (created=false), got created=%v err=%v", created2, err)
	}

	// Serve HTTPS using GetCertificate, then hot-swap cert with SetCustom.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = mgr.TLSConfig()
	srv.StartTLS()
	defer srv.Close()

	cert2, key2, info2, err := GenerateSelfSigned([]string{"custom.internal"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.SetCustom(cert2, key2); err != nil {
		t.Fatalf("SetCustom failed: %v", err)
	}
	st2 := mgr.Status()
	if st2.Mode != ModeCustom || st2.Cert.FingerprintSHA256 != info2.FingerprintSHA256 || st2.Cert.FingerprintSHA256 == firstFP {
		t.Fatalf("hot swap did not activate new certificate: %+v", st2)
	}

	// Invalid PEM must be rejected cleanly.
	if _, err := mgr.SetCustom([]byte("not-a-cert"), key2); err == nil {
		t.Fatalf("expected error on invalid PEM")
	}
}
