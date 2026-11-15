package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.1.0", "v0.2.0", -1},
		{"0.2.0", "v0.2.0", 0},
		{"v0.2.0-rc.1", "v0.2.0", -1},
		{"v0.2.0", "v0.2.0-rc.1", 1},
		{"dev", "v0.2.0", -1},
		{"v0.3.0", "v0.2.9", 1},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func newFakeReleaseServer(t *testing.T, tag, assetName string, binaryBytes []byte, checksumOverride string) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(binaryBytes)
	hexSum := hex.EncodeToString(sum[:])
	if checksumOverride != "" {
		hexSum = checksumOverride
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/leandrofus/ducksecrets-ce/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name":     tag,
				"html_url":     srv.URL + "/releases/tag/" + tag,
				"published_at": "2026-11-15T00:00:00Z",
				"assets": []map[string]any{
					{
						"name":                 assetName,
						"browser_download_url": srv.URL + "/download/" + assetName,
					},
					{
						"name":                 "SHA256SUMS",
						"browser_download_url": srv.URL + "/download/SHA256SUMS",
					},
				},
			})
		case "/download/SHA256SUMS":
			fmt.Fprintf(w, "%s  %s\n", hexSum, assetName)
		case "/download/" + assetName:
			_, _ = w.Write(binaryBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestApplySuccessAndNoopWhenCurrent(t *testing.T) {
	assetName := ExpectedAssetName("ducksecrets", "linux", "amd64")
	newPayload := []byte("new-binary-v0.2.0")
	srv := newFakeReleaseServer(t, "v0.2.0", assetName, newPayload, "")

	dir := t.TempDir()
	binPath := filepath.Join(dir, "ducksecrets")
	if err := os.WriteFile(binPath, []byte("old-binary-v0.1.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := Apply(context.Background(), Options{
		BinaryName:     "ducksecrets",
		CurrentVersion: "v0.1.0",
		APIBase:        srv.URL,
		TargetPath:     binPath,
		OS:             "linux",
		Arch:           "amd64",
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if !res.Updated || !res.UpdateAvailable || res.LatestVersion != "v0.2.0" {
		t.Fatalf("unexpected ApplyResult: %+v", res)
	}
	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newPayload) {
		t.Fatalf("binary content = %q, want %q", got, newPayload)
	}

	// Running again at v0.2.0 should be a no-op without modifying the file.
	res2, err := Apply(context.Background(), Options{
		BinaryName:     "ducksecrets",
		CurrentVersion: "v0.2.0",
		APIBase:        srv.URL,
		TargetPath:     binPath,
		OS:             "linux",
		Arch:           "amd64",
	})
	if err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}
	if res2.Updated || res2.UpdateAvailable {
		t.Fatalf("expected no-op on same version, got %+v", res2)
	}
}

func TestApplyRejectsChecksumMismatch(t *testing.T) {
	assetName := ExpectedAssetName("ducksecretsd", "linux", "amd64")
	srv := newFakeReleaseServer(t, "v0.2.0", assetName, []byte("tampered"), strings.Repeat("a", 64))

	dir := t.TempDir()
	binPath := filepath.Join(dir, "ducksecretsd")
	orig := []byte("original-binary")
	if err := os.WriteFile(binPath, orig, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Apply(context.Background(), Options{
		BinaryName:     "ducksecretsd",
		CurrentVersion: "v0.1.0",
		APIBase:        srv.URL,
		TargetPath:     binPath,
		OS:             "linux",
		Arch:           "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("expected SHA-256 mismatch error, got %v", err)
	}
	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(orig) {
		t.Fatalf("original binary was modified on checksum error")
	}
}
