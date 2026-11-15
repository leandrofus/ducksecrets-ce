package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
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
