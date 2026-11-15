package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestTokenCIDRValidation(t *testing.T) {
	// Valid formats
	valids := []string{
		"100.64.0.0/10",
		"10.0.1.5",
		"192.168.1.0/24, 10.0.0.1",
		"127.0.0.1, 100.83.173.113",
		"10.0.0.0/8; 172.16.0.0/12",
	}
	for _, v := range valids {
		if err := validateCIDRs(v); err != nil {
			t.Errorf("expected %q to be valid CIDR, got: %v", v, err)
		}
	}

	// Invalid formats
	invalids := []string{
		"not-an-ip",
		"999.999.999.999",
		"10.0.0.0/35",
		"10.0.0.1/abc",
	}
	for _, inv := range invalids {
		if err := validateCIDRs(inv); err == nil {
			t.Errorf("expected %q to be invalid, got nil error", inv)
		}
	}
}

func TestTokenIPMatching(t *testing.T) {
	// Tailscale CGNAT
	if !isIPAllowed("100.83.173.113", "100.64.0.0/10") {
		t.Errorf("expected 100.83.173.113 to match 100.64.0.0/10")
	}

	// Localhost
	if !isIPAllowed("127.0.0.1", "127.0.0.1, 10.0.0.0/8") {
		t.Errorf("expected 127.0.0.1 to match allowed list")
	}

	// Outside IP
	if isIPAllowed("192.168.1.100", "100.64.0.0/10, 10.0.0.0/8") {
		t.Errorf("did not expect 192.168.1.100 to match")
	}

	// Empty list means any IP allowed
	if !isIPAllowed("192.168.1.100", "") {
		t.Errorf("expected empty allowed list to allow any IP")
	}
}

func TestTokenSecurityEnforcement(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	// 1. Create project & secret
	var prj projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Sec Project",
		"slug": "sec-proj",
	}, &prj)

	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "DB_SECRET",
		"value": "super-secure-production-db",
	}, nil)

	// 2. Create Token with IP restriction (Only 10.0.0.0/8 and 100.64.0.0/10)
	var created createdServiceTokenDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/tokens", prj.ID), map[string]any{
		"name":             "ip-restricted-token",
		"environment_slug": "dev",
		"permissions":      "secrets.read",
		"allowed_cidrs":    "10.0.0.0/8, 100.64.0.0/10",
	}, &created)

	// Try using token from unauthorized IP (192.168.1.50)
	req1 := httptest.NewRequest("GET", "/api/v1/projects/"+prj.ID+"/environments/dev/secrets/export?format=json", nil)
	req1.Header.Set("Authorization", "Bearer "+created.RawToken)
	req1.RemoteAddr = "192.168.1.50:54321"
	w1 := httptest.NewRecorder()
	ts.Config.Handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for unauthorized IP, got %d: %s", w1.Code, w1.Body.String())
	}

	// Try using token from authorized IP (100.83.173.113 - Tailscale)
	req2 := httptest.NewRequest("GET", "/api/v1/projects/"+prj.ID+"/environments/dev/secrets/export?format=json", nil)
	req2.Header.Set("Authorization", "Bearer "+created.RawToken)
	req2.RemoteAddr = "100.83.173.113:54321"
	w2 := httptest.NewRecorder()
	ts.Config.Handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for authorized IP, got %d: %s", w2.Code, w2.Body.String())
	}

	// 3. Create Single-Use Token (Burn-on-Boot)
	var createdSU createdServiceTokenDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/tokens", prj.ID), map[string]any{
		"name":             "single-use-boot-token",
		"environment_slug": "dev",
		"permissions":      "secrets.read",
		"single_use":       true,
	}, &createdSU)

	if !createdSU.SingleUse {
		t.Fatalf("expected single_use to be true")
	}

	// First export: should succeed
	suReq1 := httptest.NewRequest("GET", "/api/v1/projects/"+prj.ID+"/environments/dev/secrets/export?format=json", nil)
	suReq1.Header.Set("Authorization", "Bearer "+createdSU.RawToken)
	suW1 := httptest.NewRecorder()
	ts.Config.Handler.ServeHTTP(suW1, suReq1)
	if suW1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on first single-use retrieval, got %d: %s", suW1.Code, suW1.Body.String())
	}

	// Second export: must fail with 403 Forbidden ("single-use service token has already been consumed")
	suReq2 := httptest.NewRequest("GET", "/api/v1/projects/"+prj.ID+"/environments/dev/secrets/export?format=json", nil)
	suReq2.Header.Set("Authorization", "Bearer "+createdSU.RawToken)
	suW2 := httptest.NewRecorder()
	ts.Config.Handler.ServeHTTP(suW2, suReq2)
	if suW2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on second retrieval of burned token, got %d: %s", suW2.Code, suW2.Body.String())
	}
	if !strings.Contains(suW2.Body.String(), "already been consumed") {
		t.Fatalf("expected error message to mention 'already been consumed', got: %s", suW2.Body.String())
	}
}

func TestTokenPathScopeSingleUseAndSecretReadAudit(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	var prj projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Path Scope Project",
		"slug": "path-scope",
	}, &prj)

	var secApp, secSub, secAdmin secretDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"path": "/app", "key": "APP_REF", "value": "uses=${ADMIN_ONLY}",
	}, &secApp)
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"path": "/app/db", "key": "DB_PASS", "value": "app-db-secret",
	}, &secSub)
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"path": "/admin", "key": "ADMIN_ONLY", "value": "top-secret-admin",
	}, &secAdmin)

	var scopedTok createdServiceTokenDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/tokens", prj.ID), map[string]any{
		"name":             "app-only-token",
		"environment_slug": "dev",
		"path":             "/app",
		"permissions":      "secrets.read secrets.write",
	}, &scopedTok)

	callTok := func(tok, method, path string, body any) (int, []byte) {
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, "/api/v1"+path, rd)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.Config.Handler.ServeHTTP(w, req)
		return w.Code, w.Body.Bytes()
	}

	// 1. Listing/exporting with path=/app token excludes /admin and does NOT interpolate ADMIN_ONLY
	code, listBody := callTok(scopedTok.RawToken, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets?reveal=1", prj.ID), nil)
	if code != http.StatusOK {
		t.Fatalf("list revealed: status %d: %s", code, listBody)
	}
	var listRes secretListDTO
	_ = json.Unmarshal(listBody, &listRes)
	if listRes.Total != 2 {
		t.Fatalf("expected 2 secrets under /app*, got %d: %+v", listRes.Total, listRes.Items)
	}

	code, exportBody := callTok(scopedTok.RawToken, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/export?format=json", prj.ID), nil)
	if code != http.StatusOK {
		t.Fatalf("export: status %d: %s", code, exportBody)
	}
	if strings.Contains(string(exportBody), "top-secret-admin") || strings.Contains(string(exportBody), `"ADMIN_ONLY"`) {
		t.Fatalf("path-scoped export leaked /admin secret: %s", exportBody)
	}

	// Direct /admin path operations fail with 403
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{"GET", fmt.Sprintf("/projects/%s/environments/dev/secrets?path=/admin", prj.ID), nil},
		{"GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/export?path=/admin&format=json", prj.ID), nil},
		{"GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, secAdmin.ID), nil},
		{"GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/versions?reveal=1", prj.ID, secAdmin.ID), nil},
		{"POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{"path": "/admin", "key": "X", "value": "Y"}},
		{"PATCH", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, secAdmin.ID), map[string]any{"value": "pwn"}},
		{"DELETE", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, secAdmin.ID), nil},
	} {
		c, _ := callTok(scopedTok.RawToken, tc.method, tc.path, tc.body)
		if c != http.StatusForbidden {
			t.Fatalf("path-scoped %s %s: status %d, want 403", tc.method, tc.path, c)
		}
	}

	// Authorized subpath write + read + versions succeed
	if c, _ := callTok(scopedTok.RawToken, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"path": "/app/cache", "key": "REDIS_PASS", "value": "ok",
	}); c != http.StatusCreated {
		t.Fatalf("subpath create: status %d, want 201", c)
	}
	if c, _ := callTok(scopedTok.RawToken, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, secApp.ID), nil); c != http.StatusOK {
		t.Fatalf("getSecret /app: status %d, want 200", c)
	}
	if c, _ := callTok(scopedTok.RawToken, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/versions?reveal=1", prj.ID, secApp.ID), nil); c != http.StatusOK {
		t.Fatalf("listSecretVersions reveal=1 /app: status %d, want 200", c)
	}

	// 2. Single-use token: does NOT burn on reveal=0, burns atomically on reveal=1 / write
	var suMeta createdServiceTokenDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/tokens", prj.ID), map[string]any{
		"name": "su-no-meta-burn", "environment_slug": "dev", "permissions": "secrets.read", "single_use": true,
	}, &suMeta)
	if c, _ := callTok(suMeta.RawToken, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets?reveal=0", prj.ID), nil); c != http.StatusOK {
		t.Fatalf("single-use metadata list: status %d", c)
	}
	if c, _ := callTok(suMeta.RawToken, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets?reveal=1", prj.ID), nil); c != http.StatusOK {
		t.Fatalf("single-use reveal after metadata list: status %d, want 200", c)
	}
	if c, _ := callTok(suMeta.RawToken, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets?reveal=1", prj.ID), nil); c != http.StatusForbidden {
		t.Fatalf("second single-use reveal: status %d, want 403", c)
	}

	// Concurrent single-use race test: exactly 1 succeeds with 200
	var suRace createdServiceTokenDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/tokens", prj.ID), map[string]any{
		"name": "su-race", "environment_slug": "dev", "permissions": "secrets.read", "single_use": true,
	}, &suRace)
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _ := callTok(suRace.RawToken, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s", prj.ID, secApp.ID), nil)
			codes <- c
		}()
	}
	wg.Wait()
	close(codes)
	okCount := 0
	for c := range codes {
		if c == http.StatusOK {
			okCount++
		} else if c != http.StatusForbidden {
			t.Fatalf("unexpected concurrent single-use status: %d", c)
		}
	}
	if okCount != 1 {
		t.Fatalf("expected exactly 1 success for concurrent single-use token, got %d", okCount)
	}

	// 3. Audit log (#36) contains secret read/list/export/versions_read events
	var auditList paginatedAuditEvents
	admin.must(200, "GET", "/audit?limit=100", nil, &auditList)
	seen := map[string]bool{}
	for _, ev := range auditList.Items {
		seen[ev.Action] = true
	}
	for _, wantAction := range []string{
		"secrets.list_revealed",
		"secret.export",
		"secret.read",
		"secret.versions_read",
	} {
		if !seen[wantAction] {
			t.Fatalf("missing audit action %q in %v", wantAction, seen)
		}
	}
}
