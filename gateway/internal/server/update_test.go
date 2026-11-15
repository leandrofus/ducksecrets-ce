package server

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
	"runtime"
	"testing"

	"github.com/leandrofus/ducksecrets/gateway/internal/audit"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/events"
	"github.com/leandrofus/ducksecrets/gateway/internal/selfupdate"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
)

func TestSystemUpdateEndpoints(t *testing.T) {
	assetName := selfupdate.ExpectedAssetName("ducksecretsd", runtime.GOOS, runtime.GOARCH)
	payload := []byte("ducksecretsd-v0.2.0-release")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])

	var releaseSrv *httptest.Server
	releaseSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/leandrofus/ducksecrets-ce/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name":     "v0.2.0",
				"html_url":     releaseSrv.URL + "/releases/tag/v0.2.0",
				"published_at": "2026-11-15T00:00:00Z",
				"assets": []map[string]any{
					{"name": assetName, "browser_download_url": releaseSrv.URL + "/download/" + assetName},
					{"name": "SHA256SUMS", "browser_download_url": releaseSrv.URL + "/download/SHA256SUMS"},
				},
			})
		case "/download/SHA256SUMS":
			fmt.Fprintf(w, "%s  %s\n", hexSum, assetName)
		case "/download/" + assetName:
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer releaseSrv.Close()

	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()

	vault, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	targetBin := filepath.Join(t.TempDir(), "ducksecretsd")
	if err := os.WriteFile(targetBin, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Store:            st,
		Auth:             &auth.Service{Store: st},
		Audit:            &audit.Log{Store: st, Key: []byte("k")},
		Events:           events.New(),
		Vault:            vault,
		Version:          "0.1.0",
		UpdateAPIBase:    releaseSrv.URL,
		UpdateTargetPath: targetBin,
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

	// Non-admin must be forbidden.
	user.must(403, "GET", "/system/update", nil, nil)

	// Admin check returns latest release metadata.
	var stDTO updateStatusDTO
	admin.must(200, "GET", "/system/update", nil, &stDTO)
	if !stDTO.UpdateAvailable || stDTO.LatestVersion != "v0.2.0" || stDTO.ExpectedSHA256 != hexSum {
		t.Fatalf("unexpected UpdateStatus: %+v", stDTO)
	}

	// Admin applies update -> swaps target binary & records audit.
	var applied applyUpdateResponse
	admin.must(200, "POST", "/system/update", map[string]any{}, &applied)
	if !applied.OK || !applied.Updated || !applied.RestartRequired || applied.NewVersion != "v0.2.0" {
		t.Fatalf("unexpected ApplyUpdateResponse: %+v", applied)
	}
	got, err := os.ReadFile(targetBin)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("updated binary = %q, want %q", got, payload)
	}
}
