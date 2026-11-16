package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVaultV1Compatibility(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	doVaultHeaders := func(method, path, token string, extraHeaders map[string]string, body any) (int, map[string]any) {
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rd)
		if token != "" {
			req.Header.Set("X-Vault-Token", token)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		ts.Config.Handler.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	doVault := func(method, path, token string, body any) (int, map[string]any) {
		return doVaultHeaders(method, path, token, nil, body)
	}

	// 1. /v1/sys/health & /v1/sys/seal-status (unauthenticated)
	code, health := doVault("GET", "/v1/sys/health", "", nil)
	if code != http.StatusOK || health["initialized"] != true || health["sealed"] != false {
		t.Fatalf("unexpected /v1/sys/health: code=%d body=%+v", code, health)
	}
	code, seal := doVault("GET", "/v1/sys/seal-status", "", nil)
	if code != http.StatusOK || seal["sealed"] != false {
		t.Fatalf("unexpected /v1/sys/seal-status: code=%d body=%+v", code, seal)
	}

	// 2. /v1/auth/userpass/login/admin -> returns auth.client_token
	code, loginRes := doVault("POST", "/v1/auth/userpass/login/admin", "", map[string]any{
		"password": "admin-password",
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on userpass login, got %d (%+v)", code, loginRes)
	}
	authBlock, _ := loginRes["auth"].(map[string]any)
	vaultToken, _ := authBlock["client_token"].(string)
	if vaultToken == "" {
		t.Fatalf("expected client_token in Vault auth response, got %+v", loginRes)
	}

	// 3. /v1/auth/token/lookup-self with X-Vault-Token
	code, lookupRes := doVault("GET", "/v1/auth/token/lookup-self", vaultToken, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on lookup-self, got %d (%+v)", code, lookupRes)
	}
	lookupData, _ := lookupRes["data"].(map[string]any)
	if lookupData["display_name"] != "admin" {
		t.Fatalf("expected display_name=admin, got %+v", lookupData)
	}

	// 4. Create project via REST API, then write & read secrets via Vault KV v2 API (/v1/secret/data/<project>/<env>)
	var proj projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Vault Compat App",
		"slug": "vault-app",
	}, &proj)

	// Write KV v2 secrets
	code, writeRes := doVault("POST", "/v1/secret/data/vault-app/prod", vaultToken, map[string]any{
		"data": map[string]any{
			"DB_HOST": "10.0.1.50",
			"DB_PASS": "s3cr3t-vault-kv2",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 writing KV v2 secret, got %d (%+v)", code, writeRes)
	}

	// Read KV v2 secrets (all keys in environment)
	code, readRes := doVault("GET", "/v1/secret/data/vault-app/prod", vaultToken, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 reading KV v2 secret, got %d (%+v)", code, readRes)
	}
	outerData, _ := readRes["data"].(map[string]any)
	innerData, _ := outerData["data"].(map[string]any)
	if innerData["DB_HOST"] != "10.0.1.50" || innerData["DB_PASS"] != "s3cr3t-vault-kv2" {
		t.Fatalf("unexpected KV v2 secret data: %+v", innerData)
	}

	// Read single key via /v1/secret/data/vault-app/prod/DB_PASS
	code, singleKeyRes := doVault("GET", "/v1/secret/data/vault-app/prod/DB_PASS", vaultToken, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 reading single key, got %d (%+v)", code, singleKeyRes)
	}
	singleOuter, _ := singleKeyRes["data"].(map[string]any)
	singleInner, _ := singleOuter["data"].(map[string]any)
	if singleInner["DB_PASS"] != "s3cr3t-vault-kv2" {
		t.Fatalf("expected DB_PASS=s3cr3t-vault-kv2, got %+v", singleInner)
	}

	// 5. Subkeys & Metadata & Version lifecycle (subkeys, delete, undelete, destroy)
	code, subkeysRes := doVault("GET", "/v1/secret/subkeys/vault-app/prod", vaultToken, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on subkeys, got %d (%+v)", code, subkeysRes)
	}
	subkeysData, _ := subkeysRes["data"].(map[string]any)
	subkeysMap, _ := subkeysData["subkeys"].(map[string]any)
	if _, has := subkeysMap["DB_PASS"]; !has {
		t.Fatalf("expected DB_PASS in subkeys, got %+v", subkeysMap)
	}

	// Update DB_PASS to version 2, then rollback via /v1/secret/undelete
	doVault("POST", "/v1/secret/data/vault-app/prod", vaultToken, map[string]any{
		"data": map[string]any{"DB_PASS": "v2-password"},
	})
	code, _ = doVault("POST", "/v1/secret/undelete/vault-app/prod/DB_PASS", vaultToken, map[string]any{
		"versions": []int{1},
	})
	if code != http.StatusNoContent {
		t.Fatalf("expected 204 on undelete, got %d", code)
	}
	_, afterUndelete := doVault("GET", "/v1/secret/data/vault-app/prod/DB_PASS", vaultToken, nil)
	uOuter, _ := afterUndelete["data"].(map[string]any)
	uInner, _ := uOuter["data"].(map[string]any)
	if uInner["DB_PASS"] != "s3cr3t-vault-kv2" {
		t.Fatalf("expected undelete to restore version 1 value, got %+v", uInner)
	}

	// 6. Structured Credentials Engine (/v1/creds/data/<project>/<name>) — Write, Read, Delete
	code, credWrite := doVault("POST", "/v1/creds/data/vault-app/redis-prod", vaultToken, map[string]any{
		"data": map[string]any{
			"kind":             "login",
			"environment_slug": "prod",
			"username":         "default",
			"password":         "redis-vault-password",
			"host":             "10.0.5.10",
			"port":             6379,
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 writing /v1/creds/data/vault-app/redis-prod, got %d (%+v)", code, credWrite)
	}

	code, credVaultRes := doVault("GET", "/v1/creds/data/vault-app/redis-prod", vaultToken, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 reading /v1/creds/data/vault-app/redis-prod, got %d (%+v)", code, credVaultRes)
	}
	credOuter, _ := credVaultRes["data"].(map[string]any)
	credInner, _ := credOuter["data"].(map[string]any)
	if credInner["password"] != "redis-vault-password" {
		t.Fatalf("expected decrypted credential password via Vault API, got %+v", credInner)
	}

	// 7. Response Wrapping (`X-Vault-Wrap-TTL` header and `/v1/sys/wrapping/unwrap`)
	code, wrappedRes := doVaultHeaders("GET", "/v1/secret/data/vault-app/prod", vaultToken, map[string]string{
		"X-Vault-Wrap-TTL": "5m",
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on wrapped request, got %d (%+v)", code, wrappedRes)
	}
	wrapInfo, _ := wrappedRes["wrap_info"].(map[string]any)
	wrapTok, _ := wrapInfo["token"].(string)
	if !strings.HasPrefix(wrapTok, "vw_") {
		t.Fatalf("expected wrap token vw_..., got %+v", wrappedRes)
	}
	// Unwrap once -> succeeds
	code, unwrappedRes := doVault("POST", "/v1/sys/wrapping/unwrap", vaultToken, map[string]any{
		"token": wrapTok,
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on unwrap, got %d (%+v)", code, unwrappedRes)
	}
	// Unwrap second time -> fails (burned)
	code, _ = doVault("POST", "/v1/sys/wrapping/unwrap", vaultToken, map[string]any{
		"token": wrapTok,
	})
	if code == http.StatusOK {
		t.Fatalf("expected second unwrap of single-use wrapping token to fail")
	}

	// 8. Transit Secrets Engine (/v1/transit/encrypt, decrypt, hmac, random)
	plainB64 := base64.StdEncoding.EncodeToString([]byte("sensitive-credit-card-number"))
	code, encRes := doVault("POST", "/v1/transit/encrypt/payments-key", vaultToken, map[string]any{
		"plaintext": plainB64,
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on transit encrypt, got %d (%+v)", code, encRes)
	}
	encData, _ := encRes["data"].(map[string]any)
	ciphertext, _ := encData["ciphertext"].(string)
	if !strings.HasPrefix(ciphertext, "vault:v1:") {
		t.Fatalf("expected vault:v1: ciphertext, got %q", ciphertext)
	}

	code, decRes := doVault("POST", "/v1/transit/decrypt/payments-key", vaultToken, map[string]any{
		"ciphertext": ciphertext,
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on transit decrypt, got %d (%+v)", code, decRes)
	}
	decData, _ := decRes["data"].(map[string]any)
	if decData["plaintext"] != plainB64 {
		t.Fatalf("expected decrypted plaintext %q, got %+v", plainB64, decData)
	}

	code, hmacRes := doVault("POST", "/v1/transit/hmac/payments-key", vaultToken, map[string]any{
		"input": plainB64,
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on transit hmac, got %d (%+v)", code, hmacRes)
	}

	code, randRes := doVault("POST", "/v1/transit/random/32", vaultToken, map[string]any{
		"format": "hex",
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on transit random, got %d (%+v)", code, randRes)
	}

	// 9. Token Creation (/v1/auth/token/create), AppRole Login (/v1/auth/approle/login), & Capabilities (/v1/sys/capabilities-self)
	code, tokCreateRes := doVault("POST", "/v1/auth/token/create", vaultToken, map[string]any{
		"display_name": "k8s-eso",
		"policies":     []string{"secrets.read"},
		"meta": map[string]string{
			"project":     "vault-app",
			"environment": "prod",
		},
		"ttl": "24h",
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on /v1/auth/token/create, got %d (%+v)", code, tokCreateRes)
	}
	createdAuth, _ := tokCreateRes["auth"].(map[string]any)
	stRawToken, _ := createdAuth["client_token"].(string)
	if !strings.HasPrefix(stRawToken, "duck_st_") {
		t.Fatalf("expected duck_st_ token from /v1/auth/token/create, got %q", stRawToken)
	}

	// Login via AppRole using role_id=vault-app and secret_id=stRawToken
	code, approleRes := doVault("POST", "/v1/auth/approle/login", "", map[string]any{
		"role_id":   "vault-app",
		"secret_id": stRawToken,
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on /v1/auth/approle/login, got %d (%+v)", code, approleRes)
	}

	// Capabilities check for stRawToken (has secrets.read on vault-app/prod, but NOT credentials.read)
	code, capsRes := doVault("POST", "/v1/sys/capabilities-self", stRawToken, map[string]any{
		"paths": []string{"secret/data/vault-app/prod", "creds/data/vault-app/redis-prod"},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on /v1/sys/capabilities-self, got %d (%+v)", code, capsRes)
	}
	capsData, _ := capsRes["data"].(map[string]any)
	credCaps, _ := capsData["creds/data/vault-app/redis-prod"].([]any)
	if len(credCaps) != 1 || credCaps[0] != "deny" {
		t.Fatalf("expected deny capability on creds/data for secrets-only token, got %+v", credCaps)
	}
}
