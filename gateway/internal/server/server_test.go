package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/leandrofus/ducksecrets/gateway/internal/audit"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/events"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
)

// The suites run on SQLite, and on PostgreSQL with DUCKSECRETS_TEST_POSTGRES
// (make test-postgres).

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDB)
	srv := &Server{Store: st, Version: "test"}
	srv.Auth = &auth.Service{Store: st}
	if _, err := srv.Auth.Bootstrap(context.Background(), "admin", "admin-password"); err != nil {
		t.Fatal(err)
	}
	srv.Audit = &audit.Log{Store: st, Key: []byte("k")}
	srv.Events = events.New()
	v, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	srv.Vault = v
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func newClient(t *testing.T, ts *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: ts.URL + "/api/v1", http: &http.Client{Jar: jar}}
}

// do sends a JSON request and decodes the response into out (when not nil);
// it returns the status.
func (c *client) do(method, path string, body, out any) int {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("X-Ducksecrets-Request", "1")
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func (c *client) must(want int, method, path string, body, out any) {
	c.t.Helper()
	if got := c.do(method, path, body, out); got != want {
		c.t.Fatalf("%s %s: status %d, want %d", method, path, got, want)
	}
}

func (c *client) login(user, pw string) {
	c.t.Helper()
	c.must(200, "POST", "/auth/login", map[string]string{"username": user, "password": pw}, nil)
}

func TestHealth(t *testing.T) {
	c := newClient(t, newTestServer(t))
	var h healthDTO
	c.must(200, "GET", "/health", nil, &h)
	if h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	c.must(404, "GET", "/nope", nil, nil)
}

func TestCSRFHeaderRequired(t *testing.T) {
	ts := newTestServer(t)
	res, err := http.Post(ts.URL+"/api/v1/projects", "application/json", strings.NewReader(`{"name":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d without the CSRF header", res.StatusCode)
	}
}

func TestUsersAndPermissions(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.must(401, "POST", "/auth/login", map[string]string{"username": "admin", "password": "wrong"}, nil)
	admin.login("admin", "admin-password")
	var me meDTO
	admin.must(200, "GET", "/auth/me", nil, &me)
	if me.User.Role != "admin" || !auth.Has(me.Permissions, auth.PermUsersManage) {
		t.Fatalf("me %+v", me)
	}
	var ana userDTO
	admin.must(400, "POST", "/users", map[string]any{"username": "ana", "password": "short"}, nil)
	admin.must(201, "POST", "/users", map[string]any{"username": "ana", "password": "ana-password"}, &ana)
	admin.must(409, "POST", "/users", map[string]any{"username": "ana", "password": "ana-password"}, nil)
	admin.must(409, "DELETE", "/users/"+me.User.ID, nil, nil)

	user := newClient(t, ts)
	user.login("ana", "ana-password")
	user.must(403, "GET", "/users", nil, nil)
	user.must(201, "POST", "/projects", map[string]any{"name": "mine"}, nil)

	// Disabling a user ends their sessions.
	admin.must(200, "PATCH", "/users/"+ana.ID, map[string]any{"disabled": true}, nil)
	user.must(401, "GET", "/projects", nil, nil)

	// Password change keeps the session that made it.
	admin.must(204, "PUT", "/auth/me/password", map[string]string{"current": "admin-password", "password": "new-admin-password"}, nil)
	admin.must(200, "GET", "/auth/me", nil, nil)
	admin.must(204, "POST", "/auth/logout", nil, nil)
	admin.must(401, "GET", "/auth/me", nil, nil)
	admin.login("admin", "new-admin-password")
}

func TestRolesAndGrants(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	// A role that can only read, and a user holding it.
	admin.must(400, "POST", "/roles", map[string]any{"name": "reader", "permissions": []string{"nope"}}, nil)
	admin.must(201, "POST", "/roles", map[string]any{"name": "reader", "permissions": []string{}}, nil)
	var bob userDTO
	admin.must(201, "POST", "/users", map[string]any{"username": "bob", "password": "bob-password", "role": "reader"}, &bob)
	admin.must(409, "DELETE", "/roles/reader", nil, nil) // held by bob
	admin.must(409, "PATCH", "/roles/admin", map[string]any{"permissions": []string{}}, nil)

	var a, b projectDTO
	admin.must(201, "POST", "/projects", map[string]any{"name": "shared"}, &a)
	admin.must(201, "POST", "/projects", map[string]any{"name": "secret"}, &b)

	bc := newClient(t, ts)
	bc.login("bob", "bob-password")
	var list projectListDTO
	bc.must(200, "GET", "/projects", nil, &list)
	if len(list.Items) != 0 {
		t.Fatalf("bob sees %d projects without grants", len(list.Items))
	}
	bc.must(403, "GET", "/projects/"+a.ID, nil, nil)

	// Grant read on one project to bob, write to his role.
	var g grantDTO
	admin.must(201, "POST", "/grants", map[string]any{"subject_type": "user", "subject_id": bob.ID, "object_type": "project", "object_id": a.ID, "permission": "projects.read"}, &g)
	bc.must(200, "GET", "/projects", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != a.ID {
		t.Fatalf("bob sees %+v", list)
	}
	bc.must(403, "PATCH", "/projects/"+a.ID, map[string]any{"name": "x"}, nil)
	// bob cannot pass on what he does not hold
	bc.must(403, "POST", "/grants", map[string]any{"subject_type": "role", "subject_id": "reader", "object_type": "project", "object_id": a.ID, "permission": "projects.write"}, nil)
	admin.must(201, "POST", "/grants", map[string]any{"subject_type": "role", "subject_id": "reader", "object_type": "project", "object_id": a.ID, "permission": "projects.write"}, nil)
	bc.must(200, "PATCH", "/projects/"+a.ID, map[string]any{"name": "renamed"}, nil)
	bc.must(403, "GET", "/projects/"+b.ID, nil, nil)

	var gs []grantDTO
	admin.must(200, "GET", "/grants?object_type=project&object_id="+a.ID, nil, &gs)
	if len(gs) != 2 {
		t.Fatalf("grants %+v", gs)
	}
	admin.must(204, "DELETE", "/grants/"+g.ID, nil, nil)
	admin.must(200, "DELETE", "/projects/"+a.ID, nil, nil) // takes its grants along
	admin.must(200, "GET", "/grants?object_type=project&object_id="+a.ID, nil, &gs)
	if len(gs) != 0 {
		t.Fatalf("grants after delete %+v", gs)
	}
}

func TestAuditChain(t *testing.T) {
	c := newClient(t, newTestServer(t))
	c.login("admin", "admin-password")
	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{"name": "Audit Test"}, &prj)
	c.must(200, "DELETE", "/projects/"+prj.ID, nil, nil)
	var evs paginatedAuditEvents
	c.must(200, "GET", "/audit", nil, &evs)
	if len(evs.Items) < 2 || evs.Items[0].Action != "project.delete" {
		t.Fatalf("audit %+v", evs)
	}
	var v audit.Verification
	c.must(200, "GET", "/audit/verify", nil, &v)
	if !v.Valid {
		t.Fatalf("verify %+v", v)
	}
}

func TestWebSocket(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, strings.Replace(c.base, "http", "ws", 1)+"/ws", &websocket.DialOptions{HTTPClient: c.http})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	time.Sleep(50 * time.Millisecond) // let the server subscribe
	c.must(201, "POST", "/projects", map[string]any{"name": "live"}, nil)
	var ev events.Event
	if err := wsjson.Read(ctx, conn, &ev); err != nil || ev.Type != "project.changed" {
		t.Fatalf("event %+v %v", ev, err)
	}
}

func TestProjectsAndEnvironments(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	// 1. Create a project
	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name":        "Infrastructure & Services",
		"description": "Core production clusters",
	}, &prj)

	if prj.Name != "Infrastructure & Services" || prj.Slug != "infrastructure-services" {
		t.Fatalf("unexpected project: %+v", prj)
	}

	// 2. Verify default environments were created automatically
	var envs []environmentDTO
	c.must(200, "GET", "/projects/"+prj.ID+"/environments", nil, &envs)
	if len(envs) != 3 {
		t.Fatalf("expected 3 default environments, got %d", len(envs))
	}
	expectedSlugs := []string{"dev", "staging", "prod"}
	for i, e := range envs {
		if e.Slug != expectedSlugs[i] {
			t.Errorf("expected env %d to be %s, got %s", i, expectedSlugs[i], e.Slug)
		}
	}

	// 3. Create a custom environment
	var customEnv environmentDTO
	c.must(201, "POST", "/projects/"+prj.ID+"/environments", map[string]any{
		"name":     "QA Testing",
		"slug":     "qa",
		"position": 3,
	}, &customEnv)
	if customEnv.Slug != "qa" {
		t.Fatalf("unexpected custom env: %+v", customEnv)
	}

	// 4. List projects
	var list projectListDTO
	c.must(200, "GET", "/projects", nil, &list)
	if list.Total < 1 {
		t.Fatalf("expected at least 1 project in list, got %d", list.Total)
	}

	// 5. Update project
	var updated projectDTO
	c.must(200, "PATCH", "/projects/"+prj.ID, map[string]any{
		"name": "Infrastructure Core",
	}, &updated)
	if updated.Name != "Infrastructure Core" {
		t.Fatalf("expected updated name 'Infrastructure Core', got %s", updated.Name)
	}

	// 6. Delete custom environment
	var deletedEnv environmentDTO
	c.must(200, "DELETE", "/projects/"+prj.ID+"/environments/"+customEnv.ID, nil, &deletedEnv)
	if deletedEnv.ID != customEnv.ID {
		t.Fatalf("expected deleted env %s, got %s", customEnv.ID, deletedEnv.ID)
	}

	// 7. Delete project (cascades to remaining environments)
	var deletedPrj projectDTO
	c.must(200, "DELETE", "/projects/"+prj.ID, nil, &deletedPrj)
	if deletedPrj.ID != prj.ID {
		t.Fatalf("expected deleted project %s, got %s", prj.ID, deletedPrj.ID)
	}

	// 8. Verify project is gone
	c.must(404, "GET", "/projects/"+prj.ID, nil, nil)
}

func TestSecretsVault(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	// 1. Create a project
	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Backend Vault App",
		"slug": "vault-app",
	}, &prj)

	// 2. Create secret
	var sec secretDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":     "DATABASE_URL",
		"value":   "postgres://user:pass@localhost:5432/db",
		"comment": "Primary db connection",
	}, &sec)

	if sec.Key != "DATABASE_URL" {
		t.Fatalf("expected key DATABASE_URL, got %s", sec.Key)
	}
	if sec.Value != "postgres://user:pass@localhost:5432/db" {
		t.Fatalf("expected decrypted value on creation, got %s", sec.Value)
	}
	if sec.Version != 1 {
		t.Fatalf("expected version 1, got %d", sec.Version)
	}

	// 3. List secrets without reveal: verify masked
	var secList secretListDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), nil, &secList)
	if secList.Total != 1 {
		t.Fatalf("expected 1 secret, got %d", secList.Total)
	}
	if secList.Items[0].Value != MaskedSecretValue {
		t.Fatalf("expected masked secret, got %s", secList.Items[0].Value)
	}

	// 4. List secrets with reveal=1: verify decrypted
	var secListRevealed secretListDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets?reveal=1", prj.ID), nil, &secListRevealed)
	if secListRevealed.Items[0].Value != "postgres://user:pass@localhost:5432/db" {
		t.Fatalf("expected revealed secret, got %s", secListRevealed.Items[0].Value)
	}

	// 5. Get secret by ID: verify decrypted
	var secGet secretDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, sec.ID), nil, &secGet)
	if secGet.Value != "postgres://user:pass@localhost:5432/db" {
		t.Fatalf("expected decrypted secret on get, got %s", secGet.Value)
	}

	// 6. Update secret: update value and comment
	var secUpdated secretDTO
	c.must(200, "PATCH", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, sec.ID), map[string]any{
		"value":   "postgres://user:newpassword@localhost:5432/db",
		"comment": "Rotated db password",
	}, &secUpdated)

	if secUpdated.Version != 2 {
		t.Fatalf("expected version 2, got %d", secUpdated.Version)
	}
	if secUpdated.Value != "postgres://user:newpassword@localhost:5432/db" {
		t.Fatalf("expected updated value, got %s", secUpdated.Value)
	}

	// 7. Check version history
	var verList secretVersionListDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/versions?reveal=1", prj.ID, sec.ID), nil, &verList)
	if verList.Total != 2 {
		t.Fatalf("expected 2 versions, got %d", verList.Total)
	}
	if verList.Items[0].Version != 2 || verList.Items[1].Version != 1 {
		t.Fatalf("unexpected versions order: %+v", verList.Items)
	}
	if verList.Items[1].Value != "postgres://user:pass@localhost:5432/db" {
		t.Fatalf("expected historic version 1 to have original value, got %s", verList.Items[1].Value)
	}

	// 8. Rollback to version 1
	var secRolledBack secretDTO
	c.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rollback", prj.ID, sec.ID), map[string]any{
		"version": 1,
	}, &secRolledBack)
	if secRolledBack.Version != 3 {
		t.Fatalf("expected version 3 after rollback, got %d", secRolledBack.Version)
	}
	if secRolledBack.Value != "postgres://user:pass@localhost:5432/db" {
		t.Fatalf("expected rolled back value to equal version 1, got %s", secRolledBack.Value)
	}

	// 9. Export as JSON
	var jsonExport map[string]string
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/export?format=json", prj.ID), nil, &jsonExport)
	if jsonExport["DATABASE_URL"] != "postgres://user:pass@localhost:5432/db" {
		t.Fatalf("expected exported DATABASE_URL, got %v", jsonExport)
	}

	// 10. Delete secret
	c.must(204, "DELETE", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, sec.ID), nil, nil)

	// 11. Verify secret is gone
	c.must(404, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, sec.ID), nil, nil)
}

func TestServiceTokens(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	// 1. Create a project and secret
	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Tokenized App",
		"slug": "token-app",
	}, &prj)

	var sec secretDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "STRIPE_KEY",
		"value": "sk_test_1234567890",
	}, &sec)

	// 2. Create service token
	var createdTk createdServiceTokenDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/tokens", prj.ID), map[string]any{
		"name":             "CI Runner",
		"environment_slug": "dev",
		"permissions":      "secrets.read",
	}, &createdTk)

	if !strings.HasPrefix(createdTk.RawToken, "duck_st_") {
		t.Fatalf("expected raw token prefix duck_st_, got %s", createdTk.RawToken)
	}

	// 3. List tokens
	var tokens []serviceTokenDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/tokens", prj.ID), nil, &tokens)
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token in list, got %d", len(tokens))
	}
	if tokens[0].Name != "CI Runner" {
		t.Fatalf("unexpected token name: %s", tokens[0].Name)
	}

	// 4. Test unauthenticated client using Bearer token directly
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/projects/%s/environments/dev/secrets/export?format=json", ts.URL+"/api/v1", prj.ID), nil)
	req.Header.Set("Authorization", "Bearer "+createdTk.RawToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		t.Fatalf("expected 200 with service token, got %d", res.StatusCode)
	}

	var exported map[string]string
	json.NewDecoder(res.Body).Decode(&exported)
	if exported["STRIPE_KEY"] != "sk_test_1234567890" {
		t.Fatalf("expected exported STRIPE_KEY, got %v", exported)
	}

	// 5. Test invalid token
	reqBad, _ := http.NewRequest("GET", fmt.Sprintf("%s/projects/%s/environments/dev/secrets/export?format=json", ts.URL+"/api/v1", prj.ID), nil)
	reqBad.Header.Set("Authorization", "Bearer duck_st_invalidtoken1234567890")
	resBad, err := http.DefaultClient.Do(reqBad)
	if err != nil {
		t.Fatal(err)
	}
	resBad.Body.Close()
	if resBad.StatusCode != 401 {
		t.Fatalf("expected 401 with bad token, got %d", resBad.StatusCode)
	}

	// 6. Delete service token
	c.must(204, "DELETE", fmt.Sprintf("/projects/%s/tokens/%s", prj.ID, createdTk.ID), nil, nil)

	// 7. Verify revoked token returns 401
	resRevoked, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resRevoked.Body.Close()
	if resRevoked.StatusCode != 401 {
		t.Fatalf("expected 401 after revoking token, got %d", resRevoked.StatusCode)
	}
}

func TestDatabaseMigrationEndpoints(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	var info databaseInfoDTO
	c.must(200, "GET", "/system/database", nil, &info)
	if os.Getenv(store.TestPostgresEnv) != "" {
		if info.Engine != "postgres" {
			t.Fatalf("expected initial engine to be postgres, got %s", info.Engine)
		}
		if info.CanMigrate {
			t.Fatalf("expected can_migrate to be false when already on postgres")
		}
	} else {
		if info.Engine != "sqlite" {
			t.Fatalf("expected initial engine to be sqlite, got %s", info.Engine)
		}
		if !info.CanMigrate {
			t.Fatalf("expected can_migrate to be true")
		}
	}

	// Test invalid postgres URL
	var res testDatabaseResponse
	c.must(400, "POST", "/system/database/test", map[string]string{
		"postgres_url": "invalid://not-postgres",
	}, &res)
}

func TestEphemeralShares(t *testing.T) {
	ts := newTestServer(t)
	anon := newClient(t, ts)

	// 1. Create a 1-view burn-on-read ephemeral share (unauthenticated)
	c64 := "dGVzdC1jaXBoZXJ0ZXh0LXZhbHVl" // base64 for "test-ciphertext-value"
	n64 := "AQIDBAUGBwgJCgsM"             // base64 12 bytes
	var created shareCreatedDTO
	anon.must(201, "POST", "/shares", map[string]any{
		"ciphertext":  c64,
		"nonce":       n64,
		"ttl_seconds": 3600,
		"max_views":   1,
	}, &created)

	if !strings.HasPrefix(created.ID, "sh_") {
		t.Fatalf("expected share id to start with sh_, got %s", created.ID)
	}
	if created.MaxViews != 1 {
		t.Fatalf("expected max_views 1, got %d", created.MaxViews)
	}

	// 2. Read public metadata before consuming
	var meta shareMetadataDTO
	anon.must(200, "GET", "/shares/"+created.ID, nil, &meta)
	if meta.ID != created.ID {
		t.Fatalf("expected ID %s, got %s", created.ID, meta.ID)
	}
	if meta.ViewCount != 0 {
		t.Fatalf("expected view_count 0 before reveal, got %d", meta.ViewCount)
	}

	// 3. Reveal and burn the secret
	var reveal shareRevealDTO
	anon.must(200, "POST", "/shares/"+created.ID+"/reveal", nil, &reveal)
	if reveal.Ciphertext != c64 || reveal.Nonce != n64 {
		t.Fatalf("mismatched revealed payload: got ciphertext %s, nonce %s", reveal.Ciphertext, reveal.Nonce)
	}
	if !reveal.Burned {
		t.Fatalf("expected burned to be true on 1-view share")
	}

	// 4. Verify subsequent access returns 404
	if code := anon.do("GET", "/shares/"+created.ID, nil, nil); code != 404 {
		t.Fatalf("expected 404 after burning share, got %d", code)
	}
	if code := anon.do("POST", "/shares/"+created.ID+"/reveal", nil, nil); code != 404 {
		t.Fatalf("expected 404 after burning share, got %d", code)
	}

	// 5. Test multi-view share (max_views = 2)
	var multi shareCreatedDTO
	anon.must(201, "POST", "/shares", map[string]any{
		"ciphertext":  c64,
		"nonce":       n64,
		"ttl_seconds": 3600,
		"max_views":   2,
	}, &multi)

	var r1 shareRevealDTO
	anon.must(200, "POST", "/shares/"+multi.ID+"/reveal", nil, &r1)
	if r1.Burned || r1.ViewCount != 1 {
		t.Fatalf("first reveal: expected burned=false, view_count=1; got burned=%v, view_count=%d", r1.Burned, r1.ViewCount)
	}

	var r2 shareRevealDTO
	anon.must(200, "POST", "/shares/"+multi.ID+"/reveal", nil, &r2)
	if !r2.Burned || r2.ViewCount != 2 {
		t.Fatalf("second reveal: expected burned=true, view_count=2; got burned=%v, view_count=%d", r2.Burned, r2.ViewCount)
	}

	if code := anon.do("POST", "/shares/"+multi.ID+"/reveal", nil, nil); code != 404 {
		t.Fatalf("third reveal: expected 404, got %d", code)
	}

	// 6. Test authenticated user share creation, listing, and revocation
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	var authShare shareCreatedDTO
	admin.must(201, "POST", "/shares", map[string]any{
		"ciphertext":      c64,
		"nonce":           n64,
		"ttl_seconds":     1800,
		"max_views":       5,
		"has_passphrase":  true,
		"passphrase_salt": "c2FsdDE2Ynl0ZXNhbHQ=",
	}, &authShare)

	var myShares []shareMetadataDTO
	admin.must(200, "GET", "/shares", nil, &myShares)
	found := false
	for _, s := range myShares {
		if s.ID == authShare.ID {
			found = true
			if !s.HasPassphrase {
				t.Fatalf("expected has_passphrase to be true")
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected user's active shares to list created share")
	}

	// 7. Revoke share
	admin.must(204, "DELETE", "/shares/"+authShare.ID, nil, nil)
	if code := anon.do("GET", "/shares/"+authShare.ID, nil, nil); code != 404 {
		t.Fatalf("expected 404 after revoking share, got %d", code)
	}
}

func TestSecretInterpolation(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Interpolation Project",
		"slug": "interp-proj",
	}, &prj)

	// Create base secrets
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "DB_USER",
		"value": "app_dev",
	}, nil)
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "DB_PASSWORD",
		"value": "supersecretdevpass",
	}, nil)
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "DB_HOST",
		"value": "10.0.1.5:5432",
	}, nil)
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "DB_NAME",
		"value": "ecommerce_dev",
	}, nil)

	// Create compound DATABASE_URL referencing the other secrets
	var createdURL secretDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "DATABASE_URL",
		"value": "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME}",
	}, &createdURL)

	// 1. Verify export expands the variables
	var exported map[string]string
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/export?format=json", prj.ID), nil, &exported)
	expectedURL := "postgres://app_dev:supersecretdevpass@10.0.1.5:5432/ecommerce_dev"
	if exported["DATABASE_URL"] != expectedURL {
		t.Fatalf("expected exported DATABASE_URL to be %q, got %q", expectedURL, exported["DATABASE_URL"])
	}

	// 2. Verify list with reveal=1 returns expanded value and raw_value
	var list secretListDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets?reveal=1", prj.ID), nil, &list)
	var urlItem *secretDTO
	for i := range list.Items {
		if list.Items[i].Key == "DATABASE_URL" {
			urlItem = &list.Items[i]
			break
		}
	}
	if urlItem == nil {
		t.Fatalf("DATABASE_URL not found in secrets list")
	}
	if urlItem.Value != expectedURL {
		t.Fatalf("expected revealed Value %q, got %q", expectedURL, urlItem.Value)
	}
	if urlItem.RawValue != "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME}" {
		t.Fatalf("expected RawValue to preserve template, got %q", urlItem.RawValue)
	}

	// 3. Verify getSecret for single secret returns expanded value and raw_value
	var single secretDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, createdURL.ID), nil, &single)
	if single.Value != expectedURL {
		t.Fatalf("expected single get Value %q, got %q", expectedURL, single.Value)
	}
	if single.RawValue != "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME}" {
		t.Fatalf("expected single get RawValue %q, got %q", "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME}", single.RawValue)
	}
}

func TestSecretBulkImport(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Bulk Import Project",
		"slug": "bulk-import-proj",
	}, &prj)

	// Pre-create one secret
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "EXISTING_KEY",
		"value": "initial_val",
	}, nil)

	// Perform bulk import
	var res importSecretsResponse
	c.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/import", prj.ID), map[string]any{
		"overwrite": true,
		"secrets": []map[string]any{
			{"key": "EXISTING_KEY", "value": "updated_val"},
			{"key": "NEW_KEY_1", "value": "val1"},
			{"key": "NEW_KEY_2", "value": "val2"},
		},
	}, &res)

	if res.Created != 2 || res.Updated != 1 || res.Total != 3 {
		t.Fatalf("expected 2 created, 1 updated, 3 total; got %+v", res)
	}

	// Verify values and version increment
	var list secretListDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets?reveal=1", prj.ID), nil, &list)
	if list.Total != 3 {
		t.Fatalf("expected 3 total secrets, got %d", list.Total)
	}
	for _, item := range list.Items {
		if item.Key == "EXISTING_KEY" {
			if item.Value != "updated_val" {
				t.Fatalf("expected updated_val, got %s", item.Value)
			}
			if item.Version != 2 {
				t.Fatalf("expected version 2 after overwrite, got %d", item.Version)
			}
		}
	}
}

func TestSharesAtomicRevealAndBurnedFiltering(t *testing.T) {
	ts := newTestServer(t)
	anon := newClient(t, ts)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	// Create single-view public share
	var sh shareCreatedDTO
	anon.must(201, "POST", "/shares", map[string]any{
		"ciphertext":  "Y2lwaGVy",
		"nonce":       "MTIzNDU2Nzg5MDEy",
		"ttl_seconds": 3600,
		"max_views":   1,
	}, &sh)

	// Concurrent reveals: only 1 caller may succeed with 200 OK
	var okCount atomic.Int32
	var notFoundCount atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", ts.URL+"/api/v1/shares/"+sh.ID+"/reveal", bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Ducksecrets-Request", "1")
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err != nil {
				t.Errorf("request failed: %v", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
					t.Errorf("expected Cache-Control: no-store, got %q", cc)
				}
				okCount.Add(1)
			} else if resp.StatusCode == 404 {
				notFoundCount.Add(1)
			} else {
				t.Errorf("unexpected status %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	if okCount.Load() != 1 || notFoundCount.Load() != 7 {
		t.Fatalf("expected exactly 1 reveal and 7 404s; got ok=%d 404=%d", okCount.Load(), notFoundCount.Load())
	}

	// Authenticated burned share must not appear in GET /shares
	var authSh shareCreatedDTO
	admin.must(201, "POST", "/shares", map[string]any{
		"ciphertext":  "Y2lwaGVyMg==",
		"nonce":       "MTIzNDU2Nzg5MDEy",
		"ttl_seconds": 3600,
		"max_views":   1,
	}, &authSh)
	admin.must(200, "POST", "/shares/"+authSh.ID+"/reveal", nil, nil)

	var myShares []shareMetadataDTO
	admin.must(200, "GET", "/shares", nil, &myShares)
	for _, item := range myShares {
		if item.ID == authSh.ID {
			t.Fatalf("burned share %s still returned by GET /shares", authSh.ID)
		}
	}
}

func TestSecretsPathDisambiguationAndExportEscaping(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{"name": "Multi Path", "slug": "multipath"}, &prj)

	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"path":  "/api",
		"key":   "PORT",
		"value": "8080",
	}, nil)
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"path":  "/worker",
		"key":   "PORT",
		"value": "9090",
	}, nil)
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"path":  "/worker",
		"key":   "ADDR",
		"value": "http://localhost:${PORT}\r\nLINE2",
	}, nil)

	listReq, _ := http.NewRequest("GET", c.base+fmt.Sprintf("/projects/%s/environments/dev/secrets?reveal=1", prj.ID), nil)
	listReq.Header.Set("X-Ducksecrets-Request", "1")
	resp, err := c.http.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("list revealed status: %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %q", cc)
	}
	var list secretListDTO
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, it := range list.Items {
		seen[it.Path+":"+it.Key] = it.Value
	}
	if seen["/api:PORT"] != "8080" || seen["/worker:PORT"] != "9090" {
		t.Fatalf("cross-path PORT collision: %+v", seen)
	}
	if seen["/worker:ADDR"] != "http://localhost:9090\r\nLINE2" {
		t.Fatalf("expected worker ADDR to interpolate 9090, got %q", seen["/worker:ADDR"])
	}

	expReq, _ := http.NewRequest("GET", c.base+fmt.Sprintf("/projects/%s/environments/dev/secrets/export?format=dotenv&path=/worker", prj.ID), nil)
	expReq.Header.Set("X-Ducksecrets-Request", "1")
	expResp, err := c.http.Do(expReq)
	if err != nil {
		t.Fatal(err)
	}
	defer expResp.Body.Close()
	if expResp.StatusCode != 200 {
		t.Fatalf("export status: %d", expResp.StatusCode)
	}
	if cc := expResp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("expected Cache-Control: no-store on export, got %q", cc)
	}
	bodyBytes, _ := io.ReadAll(expResp.Body)
	if !strings.Contains(string(bodyBytes), `ADDR="http://localhost:9090\r\nLINE2"`) {
		t.Fatalf("expected \\r and \\n escaped in dotenv export, got:\n%s", string(bodyBytes))
	}
}
