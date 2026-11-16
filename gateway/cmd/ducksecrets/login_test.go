package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCLI_LoginWithCredentialsAndSessionAuth(t *testing.T) {
	const wantSession = "sess_tok_abc123"

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Ducksecrets-Request") != "1" {
			t.Fatalf("expected X-Ducksecrets-Request header")
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Username != "alice" || req.Password != "secret123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "ducksecrets_session", Value: wantSession, Path: "/"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"username":"alice"}`))
	})
	mux.HandleFunc("GET /api/v1/projects/default/sites", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("ducksecrets_session")
		if err != nil || c.Value != wantSession {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	cfg := cliConfig{ServerURL: srv.URL, InsecureTLS: true}
	tok, err := loginWithCredentials(cfg, "alice", "secret123")
	if err != nil {
		t.Fatalf("loginWithCredentials failed: %v", err)
	}
	if tok != wantSession {
		t.Fatalf("expected session %q, got %q", wantSession, tok)
	}

	// Verify wrong password fails cleanly
	if _, err := loginWithCredentials(cfg, "alice", "wrong"); err == nil {
		t.Fatalf("expected error on wrong password")
	}

	// Verify authedRequest sends ducksecrets_session cookie so /sites succeeds
	cfg.Token = tok
	resp, err := authedRequest(cfg, "GET", "/api/v1/projects/default/sites", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from authenticated endpoint, got %d", resp.StatusCode)
	}
}
