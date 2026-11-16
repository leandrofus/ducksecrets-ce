package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLI_CredsResolveAndFormat(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cliCredentialList{
			Items: []cliCredential{
				{
					ID:          "cred_1",
					Name:        "Prod Bastion",
					Kind:        "ssh_key",
					Summary:     "ssh-ed25519 · ubuntu@10.0.1.25",
					ProjectSlug: "backend",
				},
			},
			Total: 1,
		})
	})
	mux.HandleFunc("GET /api/v1/credentials/cred_1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cliCredential{
			ID:          "cred_1",
			Name:        "Prod Bastion",
			Kind:        "ssh_key",
			ProjectSlug: "backend",
			Payload: &cliCredentialPayload{
				PrivateKey:  "-----BEGIN OPENSSH PRIVATE KEY-----\nTESTKEY\n-----END OPENSSH PRIVATE KEY-----",
				PublicKey:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@ducksecrets",
				Username:    "ubuntu",
				Host:        "10.0.1.25",
				Port:        2222,
				Fingerprint: "SHA256:abc123xyz",
			},
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := cliConfig{ServerURL: srv.URL, Token: "duck_st_test"}

	cred, err := resolveCredentialByNameOrID(cfg, "prod bastion", "", "")
	if err != nil {
		t.Fatalf("resolveCredentialByNameOrID failed: %v", err)
	}
	if cred.ID != "cred_1" || cred.Payload == nil || cred.Payload.Host != "10.0.1.25" {
		t.Fatalf("unexpected credential resolved: %+v", cred)
	}

	priv, err := extractCredentialField(cred.Payload, "private_key")
	if err != nil || !strings.Contains(priv, "TESTKEY") {
		t.Fatalf("extractCredentialField(private_key) = %q, err=%v", priv, err)
	}

	envMap := credentialToEnvMap(cred, "")
	if envMap["PROD_BASTION_HOST"] != "10.0.1.25" || envMap["PROD_BASTION_USER"] != "ubuntu" || envMap["PROD_BASTION_PORT"] != "2222" {
		t.Fatalf("unexpected envMap: %+v", envMap)
	}
}
