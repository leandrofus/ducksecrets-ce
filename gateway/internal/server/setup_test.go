package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leandrofus/ducksecrets/gateway/internal/audit"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/events"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
)

func TestFirstLoginAdminSetup(t *testing.T) {
	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()

	vault, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Store:        st,
		Auth:         &auth.Service{Store: st},
		Audit:        &audit.Log{Store: st, Key: []byte("k")},
		Events:       events.New(),
		Vault:        vault,
		DefaultAdmin: "admin",
		Version:      "test",
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := newClient(t, ts)

	// Fresh DB reports needs_setup: true.
	var status setupStatusDTO
	c.must(200, "GET", "/auth/setup", nil, &status)
	if !status.NeedsSetup || status.DefaultUsername != "admin" {
		t.Fatalf("unexpected setup status: %+v", status)
	}

	// Weak password is rejected.
	c.must(400, "POST", "/auth/setup", map[string]any{
		"username": "rootadmin",
		"password": "short",
	}, nil)

	// Valid password creates initial admin and opens an authenticated session.
	var created userDTO
	c.must(201, "POST", "/auth/setup", map[string]any{
		"username": "rootadmin",
		"password": "StrongFirstLogin!123",
	}, &created)
	if created.Username != "rootadmin" || created.Role != "admin" {
		t.Fatalf("unexpected setup user: %+v", created)
	}

	// Session cookie is active right away.
	var me meDTO
	c.must(200, "GET", "/auth/me", nil, &me)
	if me.User.Username != "rootadmin" {
		t.Fatalf("unexpected /auth/me user: %+v", me.User)
	}

	// Subsequent status and setup calls are locked.
	c.must(200, "GET", "/auth/setup", nil, &status)
	if status.NeedsSetup {
		t.Fatalf("expected needs_setup=false after completion")
	}
	c.must(409, "POST", "/auth/setup", map[string]any{
		"username": "attacker",
		"password": "AnotherStrongPassword!1",
	}, nil)
	_ = http.MethodPost
}
