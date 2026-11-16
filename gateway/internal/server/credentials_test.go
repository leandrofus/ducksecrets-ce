package server

import (
	"strings"
	"testing"
)

func TestCredentialsCRUDAndSyncEnv(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	// 1. Generate SSH keypair
	var gen generateSSHKeyResponse
	c.must(200, "POST", "/credentials/generate-ssh", map[string]any{
		"algorithm": "ed25519",
		"comment":   "ci-deploy@ducksecrets",
	}, &gen)
	if !strings.Contains(gen.PrivateKey, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("unexpected generated private key: %q", gen.PrivateKey)
	}
	if !strings.HasPrefix(gen.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("unexpected generated public key: %q", gen.PublicKey)
	}
	if !strings.HasPrefix(gen.Fingerprint, "SHA256:") {
		t.Fatalf("unexpected fingerprint: %q", gen.Fingerprint)
	}

	// 2. Create a global SSH credential
	var sshCred credentialDTO
	c.must(201, "POST", "/credentials", map[string]any{
		"name":        "Prod Bastion SSH",
		"kind":        "ssh_key",
		"description": "Primary bastion key",
		"payload": map[string]any{
			"private_key": gen.PrivateKey,
			"username":    "ubuntu",
			"host":        "10.0.0.15",
			"port":        22,
		},
	}, &sshCred)
	if sshCred.ID == "" {
		t.Fatal("expected credential ID")
	}
	if !strings.Contains(sshCred.Summary, "ssh-ed25519") || !strings.Contains(sshCred.Summary, "ubuntu@10.0.0.15") {
		t.Fatalf("expected auto-enriched summary, got %q", sshCred.Summary)
	}

	// 3. Create a project and bind an OAuth/API credential to it
	var proj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Payments Service",
		"slug": "payments",
	}, &proj)

	var oauthCred credentialDTO
	c.must(201, "POST", "/projects/"+proj.ID+"/credentials", map[string]any{
		"name":             "Stripe OAuth",
		"kind":             "oauth_api",
		"environment_slug": "prod",
		"payload": map[string]any{
			"provider":      "Stripe",
			"client_id":     "ca_live_1234567890",
			"client_secret": "sk_live_secret_value",
			"token_url":     "https://connect.stripe.com/oauth/token",
			"scopes":        "read_write",
		},
	}, &oauthCred)

	// 4. List credentials (payload omitted by default)
	var list credentialListDTO
	c.must(200, "GET", "/credentials", nil, &list)
	if list.Total != 2 {
		t.Fatalf("expected 2 credentials, got %d", list.Total)
	}
	for _, item := range list.Items {
		if item.Payload != nil {
			t.Fatalf("expected payload to be omitted on unrevealed list")
		}
	}

	// 5. Inspect single credential (decrypted payload returned)
	var fetched credentialDTO
	c.must(200, "GET", "/credentials/"+oauthCred.ID, nil, &fetched)
	if fetched.Payload == nil || fetched.Payload.ClientSecret != "sk_live_secret_value" {
		t.Fatalf("expected decrypted client_secret, got %+v", fetched.Payload)
	}

	// 6. Sync OAuth credential fields into project environment secrets
	var syncRes syncCredentialEnvResponse
	c.must(200, "POST", "/credentials/"+oauthCred.ID+"/sync-env", map[string]any{
		"project_id":       proj.ID,
		"environment_slug": "prod",
		"prefix":           "STRIPE",
		"overwrite":        true,
	}, &syncRes)
	if syncRes.Created != 4 {
		t.Fatalf("expected 4 secrets created, got %d (%v)", syncRes.Created, syncRes.Keys)
	}

	var secrets secretListDTO
	c.must(200, "GET", "/projects/"+proj.ID+"/environments/prod/secrets?reveal=1", nil, &secrets)
	foundSecret := false
	for _, s := range secrets.Items {
		if s.Key == "STRIPE_CLIENT_SECRET" && s.Value == "sk_live_secret_value" {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Fatalf("expected STRIPE_CLIENT_SECRET in prod environment secrets, got %+v", secrets.Items)
	}

	// 7. Delete credential
	c.must(204, "DELETE", "/credentials/"+sshCred.ID, nil, nil)
}

func TestCredentialsRBAC_CanViewAndEditCreds(t *testing.T) {
	ts := newTestServer(t)
	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	// Create standard user 'alice'
	var aliceUser userDTO
	admin.must(201, "POST", "/users", map[string]any{
		"username":     "alice-creds",
		"display_name": "Alice Creds",
		"password":     "alice-secret-1234",
		"role":         "user",
	}, &aliceUser)

	// Create project and credential
	var proj projectDTO
	admin.must(201, "POST", "/projects", map[string]any{
		"name": "Infra Vault",
		"slug": "infra-vault",
	}, &proj)

	var dbCred credentialDTO
	admin.must(201, "POST", "/projects/"+proj.ID+"/credentials", map[string]any{
		"name":             "Prod Postgres DB",
		"kind":             "login",
		"environment_slug": "prod",
		"payload": map[string]any{
			"username": "dbadmin",
			"password": "super-secret-db-password",
			"host":     "10.0.2.50",
			"port":     5432,
			"database": "app_prod",
		},
	}, &dbCred)

	// 1. Grant Alice ONLY secrets read (can_read=true), WITHOUT credential view/edit (can_view_creds=false, can_edit_creds=false)
	var pol projectPolicyDTO
	admin.must(201, "POST", "/projects/"+proj.ID+"/policies", map[string]any{
		"subject_type":     "user",
		"subject_id":       aliceUser.ID,
		"environment_slug": "prod",
		"can_read":         true,
		"can_write":        false,
		"can_view_creds":   false,
		"can_edit_creds":   false,
		"can_admin":        false,
	}, &pol)

	alice := newClient(t, ts)
	alice.login("alice-creds", "alice-secret-1234")

	// Alice CANNOT read plaintext credential when can_view_creds is false, even though can_read (secrets) is true!
	if got := alice.do("GET", "/credentials/"+dbCred.ID, nil, nil); got != 403 {
		t.Fatalf("expected 403 Forbidden when can_view_creds=false, got %d", got)
	}
	var filteredList credentialListDTO
	alice.must(200, "GET", "/projects/"+proj.ID+"/credentials", nil, &filteredList)
	if len(filteredList.Items) != 0 {
		t.Fatalf("expected 0 credentials visible when can_view_creds=false, got %d", len(filteredList.Items))
	}

	// 2. Upgrade Alice's policy to can_view_creds = true (still can_edit_creds = false)
	admin.must(200, "PUT", "/projects/"+proj.ID+"/policies/"+pol.ID, map[string]any{
		"can_view_creds": true,
		"can_edit_creds": false,
	}, nil)

	// Now Alice CAN view and decrypt the credential
	var fetched credentialDTO
	alice.must(200, "GET", "/credentials/"+dbCred.ID, nil, &fetched)
	if fetched.Payload == nil || fetched.Payload.Password != "super-secret-db-password" {
		t.Fatalf("expected Alice with can_view_creds=true to decrypt password, got %+v", fetched.Payload)
	}

	// But Alice CANNOT edit or delete the credential (can_edit_creds=false)
	if got := alice.do("PATCH", "/credentials/"+dbCred.ID, map[string]any{
		"description": "hacked",
	}, nil); got != 403 {
		t.Fatalf("expected 403 Forbidden editing credential when can_edit_creds=false, got %d", got)
	}
	if got := alice.do("DELETE", "/credentials/"+dbCred.ID, nil, nil); got != 403 {
		t.Fatalf("expected 403 Forbidden deleting credential when can_edit_creds=false, got %d", got)
	}

	// 3. Upgrade Alice's policy to can_edit_creds = true
	admin.must(200, "PUT", "/projects/"+proj.ID+"/policies/"+pol.ID, map[string]any{
		"can_edit_creds": true,
	}, nil)

	// Now Alice CAN update and create credentials in that project/env
	var updated credentialDTO
	alice.must(200, "PATCH", "/credentials/"+dbCred.ID, map[string]any{
		"description": "Updated by Alice with can_edit_creds",
	}, &updated)
	if updated.Description != "Updated by Alice with can_edit_creds" {
		t.Fatalf("expected updated description, got %q", updated.Description)
	}
}
