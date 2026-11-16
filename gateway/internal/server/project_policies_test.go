package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProjectPolicies_GranularAccess(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	// 1. Create standard user 'alice'
	var aliceUser userDTO
	admin.must(201, "POST", "/users", map[string]any{
		"username":     "alice",
		"display_name": "Alice Developer",
		"password":     "alice-secret-1234",
		"role":         "user",
	}, &aliceUser)

	// 2. Create project A and project B
	var prjA, prjB projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Backend Service",
		"slug": "backend-svc",
	}, &prjA)

	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Payment Gateway",
		"slug": "payment-gw",
	}, &prjB)

	// Add dev & prod secrets to Project A
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prjA.ID), map[string]any{
		"key":   "DATABASE_URL",
		"value": "postgres://dev:dev@localhost:5432/app_dev",
	}, nil)

	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/prod/secrets", prjA.ID), map[string]any{
		"key":   "DATABASE_URL",
		"value": "postgres://prod:supersecret@rds.aws:5432/app_prod",
	}, nil)

	// Add dev secret to Project B
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prjB.ID), map[string]any{
		"key":   "STRIPE_KEY",
		"value": "sk_live_12345",
	}, nil)

	// 3. Grant Alice access ONLY to Project A in 'dev' environment (read-only)
	var pol projectPolicyDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/policies", prjA.ID), map[string]any{
		"subject_type":     "user",
		"subject_id":       aliceUser.ID,
		"environment_slug": "dev",
		"can_read":         true,
		"can_write":        false,
		"can_admin":        false,
		"description":      "Alice dev read access",
	}, &pol)

	if pol.ID == "" || pol.EnvironmentSlug != "dev" || !pol.CanRead || pol.CanWrite {
		t.Fatalf("unexpected created policy: %+v", pol)
	}

	// Also put a dummy policy on Project B so Project B is strictly governed
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/policies", prjB.ID), map[string]any{
		"subject_type":     "user",
		"subject_id":       "some-other-user",
		"environment_slug": "*",
		"can_read":         true,
	}, nil)

	// 4. Login as Alice
	alice := newClient(t, ts)
	alice.login("alice", "alice-secret-1234")

	// Alice can list projects: project A should be visible, Project B should NOT be visible
	var prjList projectListDTO
	alice.must(200, "GET", "/projects", nil, &prjList)
	foundA := false
	foundB := false
	for _, p := range prjList.Items {
		if p.ID == prjA.ID {
			foundA = true
		}
		if p.ID == prjB.ID {
			foundB = true
		}
	}
	if !foundA {
		t.Fatalf("expected project A to be visible to alice")
	}
	if foundB {
		t.Fatalf("expected project B to NOT be visible to alice")
	}

	// Alice can read secrets in project A 'dev'
	var devSecrets secretListDTO
	alice.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets", prjA.ID), nil, &devSecrets)
	if devSecrets.Total != 1 || devSecrets.Items[0].Key != "DATABASE_URL" {
		t.Fatalf("unexpected secrets for alice in dev: %+v", devSecrets)
	}

	// Alice CANNOT read secrets in project A 'prod' (403 Forbidden)
	if got := alice.do("GET", fmt.Sprintf("/projects/%s/environments/prod/secrets", prjA.ID), nil, nil); got != 403 {
		t.Fatalf("expected 403 Forbidden for prod secrets, got %d", got)
	}

	// Alice CANNOT write secrets in project A 'dev' (can_write is false -> 403 Forbidden)
	if got := alice.do("POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prjA.ID), map[string]any{
		"key":   "NEW_KEY",
		"value": "val",
	}, nil); got != 403 {
		t.Fatalf("expected 403 Forbidden for write in dev, got %d", got)
	}

	// Alice CANNOT access project B secrets (403 Forbidden)
	if got := alice.do("GET", fmt.Sprintf("/projects/%s/environments/dev/secrets", prjB.ID), nil, nil); got != 403 {
		t.Fatalf("expected 403 Forbidden for project B dev secrets, got %d", got)
	}
}

func TestProjectPolicies_WriteAndJITExpiry(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	// 1. Create user 'bob'
	var bobUser userDTO
	admin.must(201, "POST", "/users", map[string]any{
		"username":     "bob",
		"display_name": "Bob Contributor",
		"password":     "bob-secret-1234",
		"role":         "user",
	}, &bobUser)

	var prj projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Microservice X",
		"slug": "ms-x",
	}, &prj)

	// 2. Grant Bob JIT access with 1 second TTL, with can_write = true
	var pol projectPolicyDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/policies", prj.ID), map[string]any{
		"subject_type":     "user",
		"subject_id":       bobUser.ID,
		"environment_slug": "dev",
		"can_read":         true,
		"can_write":        true,
		"can_admin":        false,
		"ttl_seconds":      1,
		"description":      "Bob 1-second JIT dev write access",
	}, &pol)

	if pol.ExpiresAt == nil {
		t.Fatalf("expected expires_at to be populated for JIT policy")
	}

	bob := newClient(t, ts)
	bob.login("bob", "bob-secret-1234")

	// Bob can write immediately while policy is active
	bob.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "INITIAL_KEY",
		"value": "initial_value",
	}, nil)

	// Wait 1.2 seconds for JIT expiration
	time.Sleep(1200 * time.Millisecond)

	// Bob should now be forbidden (policy expired)
	if got := bob.do("GET", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), nil, nil); got != 403 {
		t.Fatalf("expected 403 Forbidden after JIT policy expired, got %d", got)
	}

	if got := bob.do("POST", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), map[string]any{
		"key":   "EXPIRED_KEY",
		"value": "val",
	}, nil); got != 403 {
		t.Fatalf("expected 403 Forbidden after JIT policy expired, got %d", got)
	}
}

func TestProjectPolicies_CRUDAndAudit(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	var prj projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Audit Policy Project",
		"slug": "audit-pol-prj",
	}, &prj)

	// 1. Create policy for a role
	var created projectPolicyDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/policies", prj.ID), map[string]any{
		"subject_type":     "role",
		"subject_id":       "user",
		"environment_slug": "*",
		"can_read":         true,
		"can_write":        false,
		"can_admin":        false,
		"description":      "Default read policy for users",
	}, &created)

	// 2. List policies
	var polList []projectPolicyDTO
	admin.must(200, "GET", fmt.Sprintf("/projects/%s/policies", prj.ID), nil, &polList)
	if len(polList) != 1 || polList[0].ID != created.ID {
		t.Fatalf("expected 1 policy in list, got %+v", polList)
	}

	// 3. Update policy
	var updated projectPolicyDTO
	admin.must(200, "PUT", fmt.Sprintf("/projects/%s/policies/%s", prj.ID, created.ID), map[string]any{
		"can_write":   true,
		"description": "Upgraded to write",
	}, &updated)

	if !updated.CanWrite || updated.Description != "Upgraded to write" {
		t.Fatalf("expected policy to be updated, got %+v", updated)
	}

	// 4. Delete policy
	admin.must(204, "DELETE", fmt.Sprintf("/projects/%s/policies/%s", prj.ID, created.ID), nil, nil)

	// List should now be empty
	admin.must(200, "GET", fmt.Sprintf("/projects/%s/policies", prj.ID), nil, &polList)
	if len(polList) != 0 {
		t.Fatalf("expected 0 policies after delete, got %d", len(polList))
	}

	// 5. Verify audit log contains policy events
	var auditList paginatedAuditEvents
	admin.must(200, "GET", "/audit", nil, &auditList)
	hasCreate := false
	hasUpdate := false
	hasDelete := false
	for _, ev := range auditList.Items {
		if ev.Action == "policy.create" {
			hasCreate = true
		}
		if ev.Action == "policy.update" {
			hasUpdate = true
		}
		if ev.Action == "policy.delete" {
			hasDelete = true
		}
	}
	if !hasCreate || !hasUpdate || !hasDelete {
		t.Fatalf("missing audit events: create=%v update=%v delete=%v", hasCreate, hasUpdate, hasDelete)
	}
}

func TestRBACAndServiceTokenPrivilegeEscalation(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	// Create a project that is strictly restricted by a policy so a global "user"
	// with no grant or policy on it has zero access.
	var prjRestricted, prjDevOnly projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Restricted Project",
		"slug": "restricted-proj",
	}, &prjRestricted)
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/policies", prjRestricted.ID), map[string]any{
		"subject_type":     "user",
		"subject_id":       "someone-else",
		"environment_slug": "*",
		"can_read":         true,
	}, nil)

	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Dev Only Project",
		"slug": "dev-only-proj",
	}, &prjDevOnly)

	// Create user bob with standard "user" role.
	var bobUser userDTO
	admin.must(201, "POST", "/users", map[string]any{
		"username":     "bob",
		"display_name": "Bob",
		"password":     "bob-secret-1234",
		"role":         "user",
	}, &bobUser)

	// Give bob write+admin on prjDevOnly ONLY in "dev".
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/policies", prjDevOnly.ID), map[string]any{
		"subject_type":     "user",
		"subject_id":       bobUser.ID,
		"environment_slug": "dev",
		"can_read":         true,
		"can_write":        true,
		"can_admin":        true,
	}, nil)

	bob := newClient(t, ts)
	bob.login("bob", "bob-secret-1234")

	// 1. Bob's global "user" role (projects.write, environments.write, secrets.write) must NOT
	// bypass prjRestricted policies or RBAC for project/environment/token/site mutations.
	bob.must(403, "GET", "/projects/"+prjRestricted.ID, nil, nil)
	bob.must(403, "PATCH", "/projects/"+prjRestricted.ID, map[string]any{"name": "pwned"}, nil)
	bob.must(403, "DELETE", "/projects/"+prjRestricted.ID, nil, nil)
	bob.must(403, "POST", fmt.Sprintf("/projects/%s/environments", prjRestricted.ID), map[string]any{
		"name": "Staging",
		"slug": "staging",
	}, nil)
	bob.must(403, "POST", fmt.Sprintf("/projects/%s/tokens", prjRestricted.ID), map[string]any{
		"name":             "pwn",
		"environment_slug": "dev",
		"permissions":      "secrets.read",
	}, nil)
	bob.must(403, "POST", fmt.Sprintf("/projects/%s/sites", prjRestricted.ID), map[string]any{
		"name": "pwn-site",
	}, nil)

	// 2. Bob only has access to dev on prjDevOnly, so creating a wildcard (*) env token or
	// prod token must be rejected with 403.
	bob.must(403, "POST", fmt.Sprintf("/projects/%s/tokens", prjDevOnly.ID), map[string]any{
		"name":             "wildcard-esc",
		"environment_slug": "*",
		"permissions":      "secrets.read",
	}, nil)
	bob.must(403, "POST", fmt.Sprintf("/projects/%s/tokens", prjDevOnly.ID), map[string]any{
		"name":             "prod-esc",
		"environment_slug": "prod",
		"permissions":      "secrets.read",
	}, nil)
	// Even in dev, bob cannot mint a wildcard (*) permission token.
	bob.must(400, "POST", fmt.Sprintf("/projects/%s/tokens", prjDevOnly.ID), map[string]any{
		"name":             "star-perm-bob",
		"environment_slug": "dev",
		"permissions":      "*",
	}, nil)

	// 3. Even admin cannot mint wildcard (*) or global/admin permissions (users.manage) in a project token.
	admin.must(400, "POST", fmt.Sprintf("/projects/%s/tokens", prjDevOnly.ID), map[string]any{
		"name":             "star-perm-admin",
		"environment_slug": "dev",
		"permissions":      "*",
	}, nil)
	admin.must(400, "POST", fmt.Sprintf("/projects/%s/tokens", prjDevOnly.ID), map[string]any{
		"name":             "users-manage-token",
		"environment_slug": "dev",
		"permissions":      "users.manage",
	}, nil)

	// 4. A valid project service token must NEVER access global/session/user/system routes or
	// mint new tokens.
	var tok createdServiceTokenDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/tokens", prjDevOnly.ID), map[string]any{
		"name":             "ci-dev",
		"environment_slug": "dev",
		"permissions":      "projects.write secrets.read",
	}, &tok)

	callWithToken := func(method, path string, body any) int {
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, "/api/v1"+path, rd)
		req.Header.Set("Authorization", "Bearer "+tok.RawToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.Config.Handler.ServeHTTP(w, req)
		return w.Code
	}

	globalBlocked := []struct {
		method string
		path   string
		body   any
	}{
		{"GET", "/users", nil},
		{"GET", "/roles", nil},
		{"GET", "/audit", nil},
		{"GET", "/projects", nil},
		{"POST", "/projects", map[string]any{"name": "via-token", "slug": "via-token"}},
		{"GET", "/system/database", nil},
		{"GET", "/shares", nil},
		{"POST", fmt.Sprintf("/projects/%s/tokens", prjDevOnly.ID), map[string]any{
			"name":             "self-repro",
			"environment_slug": "dev",
			"permissions":      "secrets.read",
		}},
	}
	for _, tc := range globalBlocked {
		if code := callWithToken(tc.method, tc.path, tc.body); code != http.StatusForbidden {
			t.Fatalf("service token %s %s: status %d, want 403", tc.method, tc.path, code)
		}
	}

	// Token can still access its authorized project secret export.
	if code := callWithToken("GET", fmt.Sprintf("/projects/%s/environments/dev/secrets/export?format=json", prjDevOnly.ID), nil); code != http.StatusOK {
		t.Fatalf("service token valid export: status %d, want 200", code)
	}
}

func TestProjectPolicies_NonUTCTimestampNormalized(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	var aliceUser userDTO
	admin.must(201, "POST", "/users", map[string]any{
		"username":     "alice-tz",
		"display_name": "Alice TZ",
		"password":     "alice-secret-1234",
		"role":         "user",
	}, &aliceUser)

	var prj projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "TZ Project",
		"slug": "tz-proj",
	}, &prj)

	// Starts 30 minutes ago in UTC, expressed in -05:00 offset (wall clock looks +5h/-5h shifted)
	// e.g. 12:00 UTC == 07:00-05:00. With naive SQLite string comparison against 12:30+00:00,
	// expiresAt at +1h in -05:00 (e.g. 08:00-05:00 vs 12:30+00:00) would falsely appear expired!
	locMinus5 := time.FixedZone("UTC-5", -5*3600)
	starts := time.Now().Add(-30 * time.Minute).In(locMinus5)
	expires := time.Now().Add(2 * time.Hour).In(locMinus5)

	var pol projectPolicyDTO
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/policies", prj.ID), map[string]any{
		"subject_type":     "user",
		"subject_id":       aliceUser.ID,
		"environment_slug": "dev",
		"can_read":         true,
		"starts_at":        starts.Format(time.RFC3339),
		"expires_at":       expires.Format(time.RFC3339),
	}, &pol)

	alice := newClient(t, ts)
	alice.login("alice-tz", "alice-secret-1234")
	alice.must(200, "GET", fmt.Sprintf("/projects/%s/environments/dev/secrets", prj.ID), nil, nil)
}
