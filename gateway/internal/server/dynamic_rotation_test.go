package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/leandrofus/ducksecrets/gateway/internal/audit"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/events"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
)

func TestDynamicSecrets_LeaseLifecycle(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	// 1. Create a project
	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Infra Engine Project",
		"slug": "infra-engine",
	}, &prj)

	// 2. Register dynamic secret provider (PAM simulated mode)
	var prov dynamicProviderDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prj.ID), map[string]any{
		"name":                "bastion-access",
		"engine":              "pam",
		"role_template":       "sudo",
		"default_ttl_seconds": 1800,
		"max_ttl_seconds":     3600,
		"config": map[string]any{
			"mode":   "simulated",
			"host":   "bastion.corp.internal",
			"port":   22,
			"groups": "devops",
		},
	}, &prov)

	if prov.ID == "" || prov.Name != "bastion-access" || prov.Engine != "pam" {
		t.Fatalf("unexpected provider DTO: %+v", prov)
	}

	// 3. Test provider connection
	var testRes map[string]any
	c.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/test", prj.ID, prov.ID), nil, &testRes)
	if testRes["success"] != true {
		t.Fatalf("expected provider test connection success=true, got: %+v", testRes)
	}

	// 4. List providers
	var provList []dynamicProviderDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prj.ID), nil, &provList)
	if len(provList) != 1 || provList[0].ID != prov.ID {
		t.Fatalf("expected 1 provider in list, got %+v", provList)
	}

	// 5. Issue dynamic credential lease
	var issued issuedLeaseDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/lease", prj.ID, prov.ID), map[string]any{
		"ttl_seconds": 1800,
	}, &issued)

	if !strings.HasPrefix(issued.LeaseID, "ls_") {
		t.Fatalf("expected lease ID starting with ls_, got %s", issued.LeaseID)
	}
	if !strings.HasPrefix(issued.Username, "duck_d_") {
		t.Fatalf("expected dynamic username starting with duck_d_, got %s", issued.Username)
	}
	if issued.Password == "" {
		t.Fatal("expected non-empty generated password")
	}
	if !strings.Contains(issued.ConnString, "ssh ") {
		t.Fatalf("expected ssh connection string, got %s", issued.ConnString)
	}

	// 6. List active leases
	var leaseList []dynamicLeaseDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/leases", prj.ID, prov.ID), nil, &leaseList)
	if len(leaseList) != 1 || leaseList[0].ID != issued.LeaseID {
		t.Fatalf("expected active lease in list, got %+v", leaseList)
	}

	// 7. Revoke dynamic lease immediately
	c.must(204, "DELETE", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/leases/%s", prj.ID, prov.ID, issued.LeaseID), nil, nil)

	// 8. Verify lease is no longer listed in active leases
	var afterRevokeList []dynamicLeaseDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/leases", prj.ID, prov.ID), nil, &afterRevokeList)
	if len(afterRevokeList) != 0 {
		t.Fatalf("expected 0 active leases after revocation, got %+v", afterRevokeList)
	}

	// 9. Delete provider
	c.must(204, "DELETE", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s", prj.ID, prov.ID), nil, nil)
}

func newTestServerWithPrivateProbes(t *testing.T) *httptest.Server {
	t.Helper()
	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDB)
	v, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Store:              st,
		Version:            "test",
		AllowPrivateProbes: true,
		Auth:               &auth.Service{Store: st},
		Audit:              &audit.Log{Store: st, Key: []byte("k")},
		Events:             events.New(),
		Vault:              v,
	}
	if _, err := srv.Auth.Bootstrap(context.Background(), "admin", "admin-password"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestRotation_AutoRollbackOnProbeFailure(t *testing.T) {
	ts := newTestServerWithPrivateProbes(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	// 1. Create a project
	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Payment Gateway",
		"slug": "payment-gateway",
	}, &prj)

	// 2. Create initial secret
	var sec secretDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":     "PAYMENT_API_KEY",
		"value":   "live_secret_initial_v1",
		"comment": "External payment gateway production key",
	}, &sec)

	// 3. Mock external service that rejects the new key (returns 500 / 401)
	probeCallCount := int32(0)
	mockGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&probeCallCount, 1)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized_api_key"}`))
	}))
	defer mockGateway.Close()

	// 4. Configure rotation policy with failing http_probe
	var policy rotationPolicyDTO
	c.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation", prj.ID, sec.ID), map[string]any{
		"interval_seconds": 86400,
		"generator_type":   "password",
		"generator_config": `{"length": 32}`,
		"verifier_type":    "http_probe",
		"verifier_config": fmt.Sprintf(`{
			"url": "%s/v1/auth/verify",
			"method": "POST",
			"headers": {"Authorization": "Bearer {{secret}}"},
			"expected_status": 200
		}`, mockGateway.URL),
	}, &policy)

	if policy.SecretID != sec.ID || policy.GeneratorType != "password" {
		t.Fatalf("unexpected policy DTO: %+v", policy)
	}

	// 5. Trigger rotation run -> MUST FAIL AND AUTOMATICALLY ROLLBACK
	var runRes rotationRunResponse
	c.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation/run", prj.ID, sec.ID), nil, &runRes)

	if runRes.Success {
		t.Fatal("expected rotation to fail due to probe rejection")
	}
	if !runRes.RolledBack {
		t.Fatal("expected RolledBack to be true")
	}
	if !strings.Contains(runRes.Message, "Health verification probe failed") {
		t.Fatalf("unexpected rollback message: %s", runRes.Message)
	}

	// 6. Verify secret value in vault was preserved/restored to initial value!
	var currentSec secretDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s?reveal=1", prj.ID, sec.ID), nil, &currentSec)
	if currentSec.Value != "live_secret_initial_v1" {
		t.Fatalf("secret value was corrupted! Expected %q, got %q", "live_secret_initial_v1", currentSec.Value)
	}

	// 7. Verify version history records candidate and rollback
	var verList struct {
		Items []secretVersionDTO `json:"items"`
	}
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/versions?reveal=1", prj.ID, sec.ID), nil, &verList)

	// Should have v1 (initial), v2 (candidate), v3 (rollback)
	if len(verList.Items) < 3 {
		t.Fatalf("expected at least 3 versions in history, got %d", len(verList.Items))
	}

	// Check latest version is v3 with rollback comment
	latest := verList.Items[0]
	if !strings.Contains(latest.Comment, "Rolled back") {
		t.Fatalf("expected latest version comment to mention Rolled back, got: %s", latest.Comment)
	}
	if latest.Value != "live_secret_initial_v1" {
		t.Fatalf("latest restored version value mismatch: expected initial value, got %s", latest.Value)
	}
}

func TestRotation_Success(t *testing.T) {
	ts := newTestServerWithPrivateProbes(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	// 1. Create a project
	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Auth Service",
		"slug": "auth-service",
	}, &prj)

	// 2. Create initial secret
	var sec secretDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":     "JWT_SIGNING_KEY",
		"value":   "old_jwt_signing_key_v1",
		"comment": "HS512 JWT key",
	}, &sec)

	// 3. Mock external service that validates the new secret format and succeeds
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") && len(strings.TrimPrefix(authHeader, "Bearer ")) >= 32 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"valid":true}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer mockAuthServer.Close()

	// 4. Configure rotation policy with passing http_probe
	c.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation", prj.ID, sec.ID), map[string]any{
		"interval_seconds": 3600,
		"generator_type":   "hex",
		"generator_config": `{"length": 64}`,
		"verifier_type":    "http_probe",
		"verifier_config": fmt.Sprintf(`{
			"url": "%s/token/check",
			"method": "POST",
			"headers": {"Authorization": "Bearer {{secret}}"},
			"expected_status": 200
		}`, mockAuthServer.URL),
	}, nil)

	// 5. Trigger rotation run -> MUST SUCCEED
	var runRes rotationRunResponse
	c.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation/run", prj.ID, sec.ID), nil, &runRes)

	if !runRes.Success {
		t.Fatalf("expected rotation success, got: %+v", runRes)
	}
	if runRes.RolledBack {
		t.Fatal("expected RolledBack to be false on success")
	}
	if runRes.NewVersion != 2 {
		t.Fatalf("expected new version to be 2, got %d", runRes.NewVersion)
	}

	// 6. Verify rotated value in vault
	var currentSec secretDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s?reveal=1", prj.ID, sec.ID), nil, &currentSec)

	if currentSec.Value == "old_jwt_signing_key_v1" {
		t.Fatal("secret value was not rotated")
	}
	if len(currentSec.Value) != 64 {
		t.Fatalf("expected 64-char hex key, got %d chars: %s", len(currentSec.Value), currentSec.Value)
	}
	if currentSec.Version != 2 {
		t.Fatalf("expected secret version 2, got %d", currentSec.Version)
	}
}

func TestDynamicSecrets_ManagedTunnel(t *testing.T) {
	// 1. Start a mock TCP service (simulating Postgres or redis backend)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	mockTCPPort := l.Addr().(*net.TCPAddr).Port

	// Echo server on mock TCP service
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				// Echo response back
				_, _ = c.Write(append([]byte("ECHO:"), buf[:n]...))
			}(conn)
		}
	}()

	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Tunnel Test Project",
		"slug": "tunnel-test",
	}, &prj)

	// Register provider pointing to our mock TCP service
	var prov dynamicProviderDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prj.ID), map[string]any{
		"name":          "mock-db-provider",
		"engine":        "pam",
		"enforced_port": 0,
		"config": map[string]any{
			"mode": "simulated",
			"host": "127.0.0.1",
			"port": mockTCPPort,
		},
	}, &prov)

	// Issue lease
	var issued issuedLeaseDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/lease", prj.ID, prov.ID), map[string]any{
		"ttl_seconds": 3600,
	}, &issued)

	// Dial WebSocket tunnel
	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/api/v1/projects/%s/environments/dev/dynamic/%s/tunnel?lease_id=%s", prj.ID, prov.ID, issued.LeaseID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: c.http,
	})
	if err != nil {
		t.Fatalf("failed to dial websocket tunnel: %v", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "test done")

	netConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer netConn.Close()

	// Send message through WebSocket tunnel
	_, err = netConn.Write([]byte("HELLO_DUCK_TUNNEL"))
	if err != nil {
		t.Fatalf("failed to write through tunnel: %v", err)
	}

	// Read echoed response
	reply := make([]byte, 1024)
	n, err := netConn.Read(reply)
	if err != nil {
		t.Fatalf("failed to read from tunnel: %v", err)
	}

	if string(reply[:n]) != "ECHO:HELLO_DUCK_TUNNEL" {
		t.Fatalf("unexpected reply: got %q, want %q", string(reply[:n]), "ECHO:HELLO_DUCK_TUNNEL")
	}
}

func TestDynamicSecrets_EnforcedPortPolicy(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Enforced Port Project",
		"slug": "enforced-port-project",
	}, &prj)

	// 1. Create provider with enforced_port: 54321
	var prov dynamicProviderDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prj.ID), map[string]any{
		"name":          "enforced-postgres",
		"engine":        "pam",
		"enforced_port": 54321,
		"config": map[string]any{
			"mode": "simulated",
			"host": "127.0.0.1",
			"port": 22,
		},
	}, &prov)

	if prov.EnforcedPort != 54321 {
		t.Fatalf("expected enforced_port 54321, got %d", prov.EnforcedPort)
	}

	// Issue lease and check enforced_port propagation
	var issued issuedLeaseDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/lease", prj.ID, prov.ID), map[string]any{
		"ttl_seconds": 3600,
	}, &issued)

	if issued.EnforcedPort != 54321 {
		t.Fatalf("expected lease EnforcedPort 54321, got %d", issued.EnforcedPort)
	}

	// 2. Create provider with enforced_port: 0 (ephemeral)
	var ephemProv dynamicProviderDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prj.ID), map[string]any{
		"name":          "ephemeral-postgres",
		"engine":        "pam",
		"enforced_port": 0,
		"config": map[string]any{
			"mode": "simulated",
			"host": "127.0.0.1",
			"port": 22,
		},
	}, &ephemProv)

	if ephemProv.EnforcedPort != 0 {
		t.Fatalf("expected enforced_port 0, got %d", ephemProv.EnforcedPort)
	}

	var ephemIssued issuedLeaseDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/lease", prj.ID, ephemProv.ID), map[string]any{
		"ttl_seconds": 3600,
	}, &ephemIssued)

	if ephemIssued.EnforcedPort != 0 {
		t.Fatalf("expected lease EnforcedPort 0 for ephemeral, got %d", ephemIssued.EnforcedPort)
	}
}

func TestHostExecutionDisabledByDefault(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	var prj projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Exec Gate Project",
		"slug": "exec-gate",
	}, &prj)

	var sec secretDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "API_KEY",
		"value": "initial",
	}, &sec)

	// 1. Rotation policy with verifier_type="script" must be rejected (403) when AllowScripts is false.
	admin.must(403, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation", prj.ID, sec.ID), map[string]any{
		"interval_seconds": 3600,
		"generator_type":   "hex",
		"verifier_type":    "script",
		"verifier_config":  `{"command":"echo ok"}`,
	}, nil)

	// 2. Dynamic PAM provider in "command" or "local" mode must be rejected (403) when AllowScripts is false.
	for _, mode := range []string{"command", "local"} {
		admin.must(403, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prj.ID), map[string]any{
			"name":   "pam-" + mode,
			"engine": "pam",
			"config": map[string]any{
				"mode": mode,
				"host": "127.0.0.1",
				"port": 22,
			},
		}, nil)
	}

	// 3. Even a PAM provider created with an empty mode defaults to non-simulated and is blocked.
	admin.must(403, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prj.ID), map[string]any{
		"name":   "pam-default",
		"engine": "pam",
		"config": map[string]any{
			"host": "127.0.0.1",
			"port": 22,
		},
	}, nil)

	// 4. Even when AllowScripts is enabled on the server, a standard user without system.manage
	// cannot create a "script" rotation verifier or a non-simulated PAM provider.
	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDB)
	v, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s2 := &Server{
		Store:        st,
		Version:      "test",
		AllowScripts: true,
		Auth:         &auth.Service{Store: st},
		Audit:        &audit.Log{Store: st, Key: []byte("k")},
		Events:       events.New(),
		Vault:        v,
	}
	if _, err := s2.Auth.Bootstrap(context.Background(), "admin", "admin-password"); err != nil {
		t.Fatal(err)
	}
	srv2 := httptest.NewServer(s2.Handler())
	t.Cleanup(srv2.Close)

	a2 := newClient(t, srv2)
	a2.login("admin", "admin-password")
	var alice userDTO
	a2.must(201, "POST", "/users", map[string]any{
		"username":     "alice",
		"display_name": "Alice",
		"password":     "alice-secret-1234",
		"role":         "user",
	}, &alice)
	var prj2 projectDTO
	a2.must(201, "POST", "/projects", map[string]any{
		"name": "Exec Gate 2",
		"slug": "exec-gate-2",
	}, &prj2)
	var sec2 secretDTO
	a2.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj2.ID), map[string]any{
		"key":   "KEY2",
		"value": "val2",
	}, &sec2)

	u2 := newClient(t, srv2)
	u2.login("alice", "alice-secret-1234")
	u2.must(403, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation", prj2.ID, sec2.ID), map[string]any{
		"interval_seconds": 3600,
		"generator_type":   "hex",
		"verifier_type":    "script",
		"verifier_config":  `{"command":"echo ok"}`,
	}, nil)
	u2.must(403, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prj2.ID), map[string]any{
		"name":   "pam-cmd-user",
		"engine": "pam",
		"config": map[string]any{
			"mode":      "command",
			"issue_cmd": "true",
		},
	}, nil)
}

func TestInstallScriptHostInjectionBlocked(t *testing.T) {
	ts := newTestServer(t)

	// Unsafe Host header must be rejected with 400
	for _, badHost := range []string{
		`evil.com";id;#`,
		`evil.com$(id)`,
		"evil.com`id`",
		`evil.com extra`,
	} {
		req := httptest.NewRequest("GET", "/install.sh", nil)
		req.Host = badHost
		w := httptest.NewRecorder()
		ts.Config.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("Host=%q: got status %d, want 400", badHost, w.Code)
		}
	}

	// Valid Host produces single-quoted SERVER='http://example.com:8443'
	req := httptest.NewRequest("GET", "/install.sh", nil)
	req.Host = "example.com:8443"
	w := httptest.NewRecorder()
	ts.Config.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("valid Host: status %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "SERVER='http://example.com:8443'") {
		t.Fatalf("expected safely single-quoted SERVER assignment, got:\n%s", w.Body.String())
	}
}

func TestCrossProjectIDOR_DynamicRotationSitesAndTunnelOrigin(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	var prjA, prjB projectDTO
	admin.must(201, "POST", "/projects", map[string]any{"name": "A", "slug": "proj-a"}, &prjA)
	admin.must(201, "POST", "/projects", map[string]any{"name": "B", "slug": "proj-b"}, &prjB)

	// Site in B, secret + rotation in B, dynamic provider + lease in B
	var siteB struct {
		ID string `json:"id"`
	}
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/sites", prjB.ID), map[string]any{"name": "site-b"}, &siteB)

	var secB secretDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prjB.ID), map[string]any{
		"key": "SEC_B", "value": "valB",
	}, &secB)
	admin.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation", prjB.ID, secB.ID), map[string]any{
		"interval_seconds": 3600, "generator_type": "hex", "verifier_type": "none",
	}, nil)

	var provB dynamicProviderDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prjB.ID), map[string]any{
		"name": "prov-b", "engine": "pam",
		"config": map[string]any{"mode": "simulated", "host": "127.0.0.1", "port": 22},
	}, &provB)
	var leaseB issuedLeaseDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/lease", prjB.ID, provB.ID), map[string]any{
		"ttl_seconds": 600,
	}, &leaseB)

	// User alice has write ONLY on project A (and strictly restricted off B via policy on B)
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/policies", prjB.ID), map[string]any{
		"subject_type": "user", "subject_id": "someone-else", "environment_slug": "*", "can_read": true,
	}, nil)
	var aliceUser userDTO
	admin.must(201, "POST", "/users", map[string]any{
		"username": "alice", "display_name": "Alice", "password": "alice-secret-1234", "role": "user",
	}, &aliceUser)
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/policies", prjA.ID), map[string]any{
		"subject_type": "user", "subject_id": aliceUser.ID, "environment_slug": "*", "can_read": true, "can_write": true,
	}, nil)

	alice := newClient(t, ts)
	alice.login("alice", "alice-secret-1234")

	// Cross-project IDOR via project A URLs referencing B resources must all return 404
	alice.must(404, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prjA.ID), map[string]any{
		"name": "hijack-site", "engine": "pam", "site_id": siteB.ID,
		"config": map[string]any{"mode": "simulated", "host": "127.0.0.1", "port": 22},
	}, nil)
	alice.must(404, "GET", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s", prjA.ID, provB.ID), nil, nil)
	alice.must(404, "DELETE", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s", prjA.ID, provB.ID), nil, nil)
	alice.must(404, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/test", prjA.ID, provB.ID), nil, nil)
	alice.must(404, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/lease", prjA.ID, provB.ID), map[string]any{"ttl_seconds": 60}, nil)
	alice.must(404, "GET", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/leases", prjA.ID, provB.ID), nil, nil)
	alice.must(404, "DELETE", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/leases/%s", prjA.ID, provB.ID, leaseB.LeaseID), nil, nil)

	// Cross-env IDOR on B's own provider via prod URL must also return 404
	admin.must(404, "GET", fmt.Sprintf("/projects/%s/environments/prod/dynamic/%s", prjB.ID, provB.ID), nil, nil)

	// Rotation IDOR across project/env must return 404
	alice.must(404, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation", prjA.ID, secB.ID), nil, nil)
	alice.must(404, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation", prjA.ID, secB.ID), map[string]any{
		"interval_seconds": 60, "generator_type": "hex", "verifier_type": "none",
	}, nil)
	alice.must(404, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation/run", prjA.ID, secB.ID), nil, nil)
	alice.must(404, "DELETE", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation", prjA.ID, secB.ID), nil, nil)

	// Site delete IDOR across project must return 404 (and siteB remains intact)
	alice.must(404, "DELETE", fmt.Sprintf("/projects/%s/sites/%s", prjA.ID, siteB.ID), nil, nil)

	// extractDynamicTargetHostPort parses connection_url, dsn, and address accurately
	if h, p := extractDynamicTargetHostPort("postgres", []byte(`{"connection_url":"postgres://u:p@db.internal:5439/app"}`)); h != "db.internal" || p != 5439 {
		t.Fatalf("postgres host/port=%s:%d, want db.internal:5439", h, p)
	}
	if h, p := extractDynamicTargetHostPort("mysql", []byte(`{"dsn":"u:p@tcp(mysql.internal:3307)/app"}`)); h != "mysql.internal" || p != 3307 {
		t.Fatalf("mysql host/port=%s:%d, want mysql.internal:3307", h, p)
	}
	if h, p := extractDynamicTargetHostPort("redis", []byte(`{"address":"redis.internal:6380"}`)); h != "redis.internal" || p != 6380 {
		t.Fatalf("redis host/port=%s:%d, want redis.internal:6380", h, p)
	}

	// CSWSH check: cross-origin WebSocket dial to tunnel must be rejected
	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/api/v1/projects/%s/environments/dev/dynamic/%s/tunnel?lease_id=%s", prjB.ID, provB.ID, leaseB.LeaseID)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: admin.http,
		HTTPHeader: http.Header{"Origin": []string{"https://evil.example"}},
	})
	if err == nil {
		t.Fatal("expected cross-origin WebSocket tunnel dial to fail")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-origin WebSocket, got %d", resp.StatusCode)
	}

	// Default server (AllowPrivateProbes=false) rejects loopback http_probe on rotation run
	var secLoop secretDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prjA.ID), map[string]any{
		"key": "SSRF_TEST", "value": "v1",
	}, &secLoop)
	admin.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation", prjA.ID, secLoop.ID), map[string]any{
		"interval_seconds": 3600,
		"generator_type":   "hex",
		"verifier_type":    "http_probe",
		"verifier_config":  fmt.Sprintf(`{"url":"%s/api/v1/health"}`, ts.URL),
	}, nil)
	var ssrfRun rotationRunResponse
	admin.must(200, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets/%s/rotation/run", prjA.ID, secLoop.ID), nil, &ssrfRun)
	if ssrfRun.Success || !ssrfRun.RolledBack {
		t.Fatalf("expected SSRF probe to fail & rollback on default server, got: %+v", ssrfRun)
	}
}
