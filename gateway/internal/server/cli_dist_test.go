package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/leandrofus/ducksecrets/gateway/internal/tlsutil"
)

func TestCLIDistribution_InstallScript(t *testing.T) {
	ts := newTestServer(t)

	res, err := http.Get(ts.URL + "/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /install.sh, got %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	content := string(body)

	if !strings.HasPrefix(content, "#!/bin/sh") {
		t.Fatalf("expected script to start with #!/bin/sh, got: %s", content[:50])
	}
	if !strings.Contains(content, "/download/ducksecrets") {
		t.Fatalf("expected script to reference /download/ducksecrets")
	}
	if !strings.Contains(content, "DUCKSECRETS_SITE_ID") || !strings.Contains(content, "DUCKSECRETS_SITE_TOKEN") {
		t.Fatalf("expected script to support DUCKSECRETS_SITE_ID and DUCKSECRETS_SITE_TOKEN")
	}
	if !strings.Contains(content, "ducksecrets-site-") || !strings.Contains(content, "systemctl") {
		t.Fatalf("expected script to support systemd service installation")
	}

	shCheck := exec.Command("sh", "-n")
	shCheck.Stdin = strings.NewReader(content)
	if out, err := shCheck.CombinedOutput(); err != nil {
		t.Fatalf("generated install.sh failed sh -n syntax check: %v\n%s", err, string(out))
	}

	// Also check /api/v1/install.sh
	res2, err := http.Get(ts.URL + "/api/v1/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/v1/install.sh, got %d", res2.StatusCode)
	}
}

func TestCLIDistribution_InstallScriptSelfSignedTLS(t *testing.T) {
	certPEM, keyPEM, info, err := tlsutil.GenerateSelfSigned([]string{"127.0.0.1"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	mgr := tlsutil.NewManager(true, tlsutil.ModeSelfSigned, "", "", []string{"127.0.0.1"})
	if _, err := mgr.LoadPEM(tlsutil.ModeSelfSigned, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	srv := &Server{
		TLS:       mgr,
		PublicURL: "https://100.83.173.113:5179",
	}

	req := httptest.NewRequest(http.MethodGet, "https://100.83.173.113:5179/install.sh", nil)
	rec := httptest.NewRecorder()
	if err := srv.installScript(rec, req, principal{}); err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("expected embedded PEM certificate in install.sh for self-signed server")
	}
	if !strings.Contains(body, info.FingerprintSHA256) {
		t.Fatalf("expected TLS SHA-256 fingerprint %q in install.sh", info.FingerprintSHA256)
	}
	if !strings.Contains(body, `--cacert "$TMP_CERT"`) {
		t.Fatalf("expected curl --cacert in install.sh")
	}
	if !strings.Contains(body, "cli.json") || !strings.Contains(body, "server.crt") {
		t.Fatalf("expected install.sh to persist cli.json and server.crt for self-signed servers")
	}

	shCheck := exec.Command("sh", "-n")
	shCheck.Stdin = strings.NewReader(body)
	if out, err := shCheck.CombinedOutput(); err != nil {
		t.Fatalf("self-signed install.sh failed sh -n syntax check: %v\n%s", err, string(out))
	}
}
