// Package server exposes a complete HashiCorp Vault HTTP v1 compatibility layer under /v1/*.
//
// Supported Engines & Subsystems:
//   - System & Health: /v1/sys/health, /v1/sys/seal-status, /v1/sys/mounts, /v1/sys/internal/ui/mounts/*, /v1/sys/capabilities-self
//   - Response Wrapping: X-Vault-Wrap-TTL header on any /v1/* request, /v1/sys/wrapping/wrap, /v1/sys/wrapping/unwrap, /v1/sys/wrapping/lookup, /v1/sys/wrapping/rewrap
//   - Auth (Userpass, AppRole, Token): /v1/auth/userpass/login/*, /v1/auth/approle/login, /v1/auth/token/lookup-self, /v1/auth/token/renew-self, /v1/auth/token/revoke-self, /v1/auth/token/create
//   - KV v2 Secrets Engine: /v1/secret/data/*, /v1/secret/metadata/*, /v1/secret/subkeys/*, /v1/secret/delete/*, /v1/secret/undelete/*, /v1/secret/destroy/* (and /v1/kv/* alias)
//   - Structured Credentials Engine: /v1/creds/data/* (GET/POST/PUT/PATCH/DELETE), /v1/creds/metadata/*, /v1/creds/generate-ssh, /v1/ssh/creds/*
//   - Dynamic Database Engine & Leases: /v1/database/creds/*, /v1/database/roles/*, /v1/sys/leases/lookup, /v1/sys/leases/renew, /v1/sys/leases/revoke
//   - Transit (Encryption-as-a-Service): /v1/transit/encrypt/*, /v1/transit/decrypt/*, /v1/transit/hmac/*, /v1/transit/hash/*, /v1/transit/random/*
package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/dynamic"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// vaultEnvelope is the standard HashiCorp Vault HTTP v1 response wrapper.
type vaultEnvelope struct {
	RequestID     string         `json:"request_id"`
	LeaseID       string         `json:"lease_id"`
	Renewable     bool           `json:"renewable"`
	LeaseDuration int            `json:"lease_duration"`
	Data          any            `json:"data,omitempty"`
	WrapInfo      *vaultWrapInfo `json:"wrap_info"`
	Warnings      []string       `json:"warnings"`
	Auth          *vaultAuthInfo `json:"auth,omitempty"`
}

type vaultWrapInfo struct {
	Token           string    `json:"token"`
	Accessor        string    `json:"accessor"`
	TTL             int       `json:"ttl"`
	CreationTime    time.Time `json:"creation_time"`
	CreationPath    string    `json:"creation_path"`
	WrappedAccessor string    `json:"wrapped_accessor,omitempty"`
}

type vaultAuthInfo struct {
	ClientToken   string            `json:"client_token"`
	Accessor      string            `json:"accessor"`
	Policies      []string          `json:"policies"`
	TokenPolicies []string          `json:"token_policies"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	LeaseDuration int               `json:"lease_duration"`
	Renewable     bool              `json:"renewable"`
	EntityID      string            `json:"entity_id"`
	TokenType     string            `json:"token_type"`
	Orphan        bool              `json:"orphan"`
}

func writeVaultOK(w http.ResponseWriter, data any) {
	writeVaultStatus(w, http.StatusOK, "", 0, false, data, nil)
}

func writeVaultStatus(w http.ResponseWriter, status int, leaseID string, leaseDuration int, renewable bool, data any, authInfo *vaultAuthInfo) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(vaultEnvelope{
		RequestID:     uuid.NewString(),
		LeaseID:       leaseID,
		Renewable:     renewable,
		LeaseDuration: leaseDuration,
		Data:          data,
		WrapInfo:      nil,
		Warnings:      nil,
		Auth:          authInfo,
	})
}

func writeVaultWrapped(w http.ResponseWriter, info *vaultWrapInfo) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(vaultEnvelope{
		RequestID: uuid.NewString(),
		WrapInfo:  info,
	})
}

func writeVaultErr(w http.ResponseWriter, status int, msgs ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if len(msgs) == 0 {
		msgs = []string{http.StatusText(status)}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": msgs,
	})
}

func writeVaultFromAPIError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	var ae *apiError
	if errors.As(err, &ae) {
		status := ae.Status
		if status == http.StatusUnauthorized {
			status = http.StatusForbidden
		}
		writeVaultErr(w, status, ae.Message)
		return
	}
	writeVaultErr(w, http.StatusInternalServerError, err.Error())
}

// parseVaultTTL parses a Vault duration string ("300", "5m", "1h") into seconds.
func parseVaultTTL(raw string, defSec int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defSec, nil
	}
	if sec, err := strconv.Atoi(raw); err == nil {
		if sec <= 0 {
			return 0, fmt.Errorf("ttl must be positive")
		}
		return sec, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", raw)
	}
	return int(d.Seconds()), nil
}

// isVaultListRequest reports whether the request is a Vault LIST operation
// (either HTTP method LIST or GET with ?list=true / ?list=1).
func isVaultListRequest(r *http.Request) bool {
	if strings.EqualFold(r.Method, "LIST") {
		return true
	}
	if r.Method == http.MethodGet {
		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("list")))
		return q == "true" || q == "1"
	}
	return false
}

// handleVaultV1 dispatches all /v1/* HashiCorp Vault compatible API requests,
// including transparent Response Wrapping when X-Vault-Wrap-TTL is set.
func (s *Server) handleVaultV1(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.URL.Path, "/v1/")
	sub = strings.TrimSuffix(sub, "/")

	// Transparent X-Vault-Wrap-TTL response wrapping (except on unwrap/lookup itself)
	if wrapTTLStr := strings.TrimSpace(r.Header.Get("X-Vault-Wrap-TTL")); wrapTTLStr != "" && !strings.HasPrefix(sub, "sys/wrapping/") {
		ttlSec, err := parseVaultTTL(wrapTTLStr, 300)
		if err != nil {
			writeVaultErr(w, http.StatusBadRequest, err.Error())
			return
		}
		rec := httptest.NewRecorder()
		rClone := r.Clone(r.Context())
		rClone.Header.Del("X-Vault-Wrap-TTL")
		s.dispatchVaultV1(rec, rClone, sub)
		if rec.Code < 200 || rec.Code >= 300 {
			for k, vals := range rec.Header() {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
		p, _ := s.resolve(r)
		wrapInfo, wErr := s.storeWrappedPayload(r.Context(), rec.Body.Bytes(), ttlSec, r.URL.Path, p.User.Username)
		if wErr != nil {
			writeVaultErr(w, http.StatusInternalServerError, wErr.Error())
			return
		}
		writeVaultWrapped(w, wrapInfo)
		return
	}

	s.dispatchVaultV1(w, r, sub)
}

func (s *Server) dispatchVaultV1(w http.ResponseWriter, r *http.Request, sub string) {
	// 1. Public / Unauthenticated endpoints in Vault
	switch {
	case sub == "sys/health":
		s.vaultSysHealth(w, r)
		return
	case sub == "sys/seal-status":
		s.vaultSysSealStatus(w, r)
		return
	case strings.HasPrefix(sub, "auth/userpass/login/"):
		s.vaultUserpassLogin(w, r, strings.TrimPrefix(sub, "auth/userpass/login/"))
		return
	case sub == "auth/userpass/login":
		s.vaultUserpassLogin(w, r, "")
		return
	case sub == "auth/approle/login":
		s.vaultAppRoleLogin(w, r)
		return
	}

	// 2. All other /v1/* endpoints require authentication (X-Vault-Token, Bearer, or Session Cookie)
	p, err := s.resolve(r)
	if err != nil {
		writeVaultErr(w, http.StatusForbidden, "permission denied")
		return
	}

	switch {
	// Token introspection & creation
	case sub == "auth/token/lookup-self":
		s.vaultTokenLookupSelf(w, r, p)
	case sub == "auth/token/renew-self":
		s.vaultTokenLookupSelf(w, r, p)
	case sub == "auth/token/revoke-self":
		s.vaultTokenRevokeSelf(w, r, p)
	case sub == "auth/token/create" || sub == "auth/token/create-orphan":
		s.vaultTokenCreate(w, r, p)

	// Mounts, Engine discovery & Capabilities
	case strings.HasPrefix(sub, "sys/internal/ui/mounts"):
		s.vaultSysUIMounts(w, r, strings.TrimPrefix(sub, "sys/internal/ui/mounts"))
	case sub == "sys/mounts":
		s.vaultSysMounts(w, r)
	case sub == "sys/capabilities-self" || sub == "sys/capabilities":
		s.vaultSysCapabilitiesSelf(w, r, p)

	// Response Wrapping (/v1/sys/wrapping/*)
	case sub == "sys/wrapping/wrap":
		s.vaultSysWrappingWrap(w, r, p)
	case sub == "sys/wrapping/unwrap":
		s.vaultSysWrappingUnwrap(w, r, p)
	case sub == "sys/wrapping/lookup":
		s.vaultSysWrappingLookup(w, r, p)
	case sub == "sys/wrapping/rewrap":
		s.vaultSysWrappingRewrap(w, r, p)

	// Lease management (/v1/sys/leases/revoke, lookup, renew)
	case sub == "sys/leases/revoke":
		s.vaultSysLeaseRevoke(w, r, p)
	case sub == "sys/leases/lookup":
		s.vaultSysLeaseLookup(w, r, p)
	case sub == "sys/leases/renew":
		s.vaultSysLeaseRenew(w, r, p)

	// KV v2 Secrets Engine (/v1/secret/... and /v1/kv/...)
	case sub == "secret/config" || sub == "kv/config":
		writeVaultOK(w, map[string]any{
			"cas_required":         false,
			"delete_version_after": "0s",
			"max_versions":         0,
		})
	case strings.HasPrefix(sub, "secret/data/"):
		s.vaultKVData(w, r, p, strings.TrimPrefix(sub, "secret/data/"))
	case strings.HasPrefix(sub, "kv/data/"):
		s.vaultKVData(w, r, p, strings.TrimPrefix(sub, "kv/data/"))
	case sub == "secret/metadata" || strings.HasPrefix(sub, "secret/metadata/"):
		s.vaultKVMetadata(w, r, p, strings.TrimPrefix(strings.TrimPrefix(sub, "secret/metadata"), "/"))
	case sub == "kv/metadata" || strings.HasPrefix(sub, "kv/metadata/"):
		s.vaultKVMetadata(w, r, p, strings.TrimPrefix(strings.TrimPrefix(sub, "kv/metadata"), "/"))
	case strings.HasPrefix(sub, "secret/subkeys/"):
		s.vaultKVSubkeys(w, r, p, strings.TrimPrefix(sub, "secret/subkeys/"))
	case strings.HasPrefix(sub, "kv/subkeys/"):
		s.vaultKVSubkeys(w, r, p, strings.TrimPrefix(sub, "kv/subkeys/"))
	case strings.HasPrefix(sub, "secret/delete/"):
		s.vaultKVVersionOp(w, r, p, strings.TrimPrefix(sub, "secret/delete/"), "delete")
	case strings.HasPrefix(sub, "kv/delete/"):
		s.vaultKVVersionOp(w, r, p, strings.TrimPrefix(sub, "kv/delete/"), "delete")
	case strings.HasPrefix(sub, "secret/undelete/"):
		s.vaultKVVersionOp(w, r, p, strings.TrimPrefix(sub, "secret/undelete/"), "undelete")
	case strings.HasPrefix(sub, "kv/undelete/"):
		s.vaultKVVersionOp(w, r, p, strings.TrimPrefix(sub, "kv/undelete/"), "undelete")
	case strings.HasPrefix(sub, "secret/destroy/"):
		s.vaultKVVersionOp(w, r, p, strings.TrimPrefix(sub, "secret/destroy/"), "destroy")
	case strings.HasPrefix(sub, "kv/destroy/"):
		s.vaultKVVersionOp(w, r, p, strings.TrimPrefix(sub, "kv/destroy/"), "destroy")
	// KV v1 & Cubbyhole compatibility (/v1/secret/<project>/<env>, /v1/cubbyhole/...)
	case strings.HasPrefix(sub, "secret/"):
		s.vaultKVv1OrCreds(w, r, p, "secret", strings.TrimPrefix(sub, "secret/"))
	case strings.HasPrefix(sub, "kv/"):
		s.vaultKVv1OrCreds(w, r, p, "secret", strings.TrimPrefix(sub, "kv/"))
	case strings.HasPrefix(sub, "cubbyhole/"):
		s.vaultKVv1OrCreds(w, r, p, "cubbyhole", strings.TrimPrefix(sub, "cubbyhole/"))

	// Structured Credentials Engine (/v1/creds/... and /v1/ssh/...)
	case sub == "creds/config":
		writeVaultOK(w, map[string]any{
			"cas_required":         false,
			"delete_version_after": "0s",
			"max_versions":         1,
		})
	case sub == "creds/generate-ssh" || strings.HasPrefix(sub, "ssh/creds/"):
		s.vaultSSHGenerate(w, r, p)
	case strings.HasPrefix(sub, "creds/data/"):
		s.vaultCredsData(w, r, p, strings.TrimPrefix(sub, "creds/data/"))
	case sub == "creds/metadata" || strings.HasPrefix(sub, "creds/metadata/"):
		s.vaultCredsMetadata(w, r, p, strings.TrimPrefix(strings.TrimPrefix(sub, "creds/metadata"), "/"))
	case strings.HasPrefix(sub, "creds/"):
		s.vaultKVv1OrCreds(w, r, p, "creds", strings.TrimPrefix(sub, "creds/"))

	// Dynamic Database Secrets Engine (/v1/database/creds/..., /v1/database/roles/...)
	case strings.HasPrefix(sub, "database/creds/"):
		s.vaultDatabaseCreds(w, r, p, strings.TrimPrefix(sub, "database/creds/"))
	case sub == "database/roles" || strings.HasPrefix(sub, "database/roles/"):
		s.vaultDatabaseRoles(w, r, p, strings.TrimPrefix(strings.TrimPrefix(sub, "database/roles"), "/"))

	// Transit Secrets Engine (/v1/transit/...)
	case strings.HasPrefix(sub, "transit/encrypt/"):
		s.vaultTransitEncrypt(w, r, p, strings.TrimPrefix(sub, "transit/encrypt/"))
	case strings.HasPrefix(sub, "transit/decrypt/"):
		s.vaultTransitDecrypt(w, r, p, strings.TrimPrefix(sub, "transit/decrypt/"))
	case strings.HasPrefix(sub, "transit/hmac/"):
		s.vaultTransitHMAC(w, r, p, strings.TrimPrefix(sub, "transit/hmac/"))
	case strings.HasPrefix(sub, "transit/hash") || strings.HasPrefix(sub, "transit/hash/"):
		s.vaultTransitHash(w, r, strings.TrimPrefix(strings.TrimPrefix(sub, "transit/hash"), "/"))
	case sub == "transit/random" || strings.HasPrefix(sub, "transit/random/"):
		s.vaultTransitRandom(w, r, strings.TrimPrefix(strings.TrimPrefix(sub, "transit/random"), "/"))
	case sub == "transit/keys" || strings.HasPrefix(sub, "transit/keys/"):
		s.vaultTransitKeys(w, r, strings.TrimPrefix(strings.TrimPrefix(sub, "transit/keys"), "/"))

	default:
		// Support arbitrary Engine Mount names (e.g. when a client sets Engine Mount = "MYSQL_ROOT" or custom mount name
		// and Secret Path = "<project>/<env>[/<key>]"):
		//   - /v1/<custom_mount>/data/<path>
		//   - /v1/<custom_mount>/metadata/<path>
		//   - /v1/<custom_mount>/<path>
		if mount, rest, ok := strings.Cut(sub, "/"); ok && mount != "" && mount != "sys" && mount != "auth" {
			switch {
			case rest == "config":
				writeVaultOK(w, map[string]any{
					"cas_required":         false,
					"delete_version_after": "0s",
					"max_versions":         0,
				})
				return
			case strings.HasPrefix(rest, "data/"):
				pathAfterData := strings.TrimPrefix(rest, "data/")
				// If mount is a specific secret key name (e.g. "MYSQL_ROOT") and pathAfterData is "tt/dev",
				// also append "/<mount>" if pathAfterData has only <project>/<env> and no key segment, or let vaultKVData return all keys + common aliases.
				s.vaultKVCustomMountData(w, r, p, mount, pathAfterData)
				return
			case rest == "metadata" || strings.HasPrefix(rest, "metadata/"):
				s.vaultKVMetadata(w, r, p, strings.TrimPrefix(strings.TrimPrefix(rest, "metadata"), "/"))
				return
			default:
				s.vaultKVv1OrCreds(w, r, p, mount, rest)
				return
			}
		}
		writeVaultErr(w, http.StatusNotFound, fmt.Sprintf("unsupported path %q", sub))
	}
}

func (s *Server) vaultSysHealth(w http.ResponseWriter, r *http.Request) {
	ver := s.Version
	if ver == "" {
		ver = "0.3.0"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"initialized":                  true,
		"sealed":                       false,
		"standby":                      false,
		"performance_standby":          false,
		"replication_performance_mode": "disabled",
		"replication_dr_mode":          "disabled",
		"server_time_utc":              time.Now().UTC().Unix(),
		"version":                      ver,
		"cluster_name":                 "ducksecrets",
		"cluster_id":                   "ducksecrets-vault-v1",
	})
}

func (s *Server) vaultSysSealStatus(w http.ResponseWriter, r *http.Request) {
	ver := s.Version
	if ver == "" {
		ver = "0.3.0"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":          "shamir",
		"initialized":   true,
		"sealed":        false,
		"t":             1,
		"n":             1,
		"progress":      0,
		"nonce":         "",
		"version":       ver,
		"build_date":    time.Now().UTC().Format(time.RFC3339),
		"migration":     false,
		"cluster_name":  "ducksecrets",
		"cluster_id":    "ducksecrets-vault-v1",
		"recovery_seal": false,
		"storage_type":  "AES-256-GCM",
	})
}

func (s *Server) vaultUserpassLogin(w http.ResponseWriter, r *http.Request, pathUsername string) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeVaultErr(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	username := strings.TrimSpace(pathUsername)
	if username == "" {
		username = strings.TrimSpace(body.Username)
	}
	if username == "" || body.Password == "" {
		writeVaultErr(w, http.StatusBadRequest, "missing username or password")
		return
	}

	ip := s.clientIP(r)
	key := strings.ToLower(username) + "|" + ip
	if !s.limiter.Allowed(key) {
		writeVaultErr(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}
	u, err := s.Auth.Authenticate(r.Context(), username, body.Password)
	if errors.Is(err, auth.ErrInvalid) || errors.Is(err, auth.ErrDisabled) {
		s.limiter.Fail(key)
		writeVaultErr(w, http.StatusBadRequest, "invalid username or password")
		return
	}
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.limiter.Reset(key)

	tok, err := s.Auth.NewSession(r.Context(), u.ID, ip, r.UserAgent())
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.Store.Q.TouchUserLogin(r.Context(), db.TouchUserLoginParams{ID: u.ID, Now: store.NullTime(store.Now())})
	s.record(r, principal{IP: ip, User: u}, "auth.vault_login", "user", u.ID, nil)

	policies := []string{"default", u.Role}
	writeVaultStatus(w, http.StatusOK, "", 0, false, nil, &vaultAuthInfo{
		ClientToken:   tok,
		Accessor:      "acc_" + u.ID,
		Policies:      policies,
		TokenPolicies: policies,
		Metadata: map[string]string{
			"username": u.Username,
			"role":     u.Role,
		},
		LeaseDuration: int(auth.SessionAbsolute / time.Second),
		Renewable:     true,
		EntityID:      u.ID,
		TokenType:     "service",
		Orphan:        true,
	})
}

// vaultAppRoleLogin implements `/v1/auth/approle/login`, mapping `role_id` (optional project ID or slug)
// and `secret_id` (a DuckSecrets Service Token `duck_st_*`) into a standard Vault `auth.client_token`.
func (s *Server) vaultAppRoleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeVaultErr(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	secretID := strings.TrimSpace(body.SecretID)
	if secretID == "" {
		writeVaultErr(w, http.StatusBadRequest, "secret_id is required")
		return
	}
	p, err := s.resolveServiceToken(r, secretID)
	if err != nil || p.ServiceToken == nil {
		writeVaultErr(w, http.StatusBadRequest, "invalid approle credentials")
		return
	}
	if roleRef := strings.TrimSpace(body.RoleID); roleRef != "" {
		proj, pErr := s.resolveProject(r.Context(), roleRef)
		if pErr != nil || proj.ID != p.ServiceToken.ProjectID {
			writeVaultErr(w, http.StatusBadRequest, "role_id does not match secret_id project")
			return
		}
	}

	ttl := 86400 * 30
	if p.ServiceToken.ExpiresAt.Valid {
		rem := int(time.Until(p.ServiceToken.ExpiresAt.Time).Seconds())
		if rem > 0 {
			ttl = rem
		}
	}
	policies := append([]string{"default"}, p.Perms...)
	writeVaultStatus(w, http.StatusOK, "", 0, false, nil, &vaultAuthInfo{
		ClientToken:   secretID,
		Accessor:      p.ServiceToken.TokenPrefix,
		Policies:      policies,
		TokenPolicies: policies,
		Metadata: map[string]string{
			"role_name":   p.ServiceToken.Name,
			"project_id":  p.ServiceToken.ProjectID,
			"environment": p.ServiceToken.EnvironmentSlug,
		},
		LeaseDuration: ttl,
		Renewable:     false,
		EntityID:      p.ServiceToken.ID,
		TokenType:     "service",
		Orphan:        true,
	})
}

// vaultTokenCreate implements `POST /v1/auth/token/create`, minting a scoped Service Token (`duck_st_*`)
// when `meta.project` (or `meta.project_id`) is provided, or a new session token for the caller.
func (s *Server) vaultTokenCreate(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if p.ServiceToken != nil {
		writeVaultErr(w, http.StatusForbidden, "service tokens cannot create child tokens")
		return
	}

	var body struct {
		DisplayName string            `json:"display_name"`
		Policies    []string          `json:"policies"`
		Meta        map[string]string `json:"meta"`
		TTL         string            `json:"ttl"`
		NumUses     int               `json:"num_uses"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	projRef := ""
	envSlug := "*"
	if body.Meta != nil {
		projRef = strings.TrimSpace(body.Meta["project"])
		if projRef == "" {
			projRef = strings.TrimSpace(body.Meta["project_id"])
		}
		if e := strings.TrimSpace(body.Meta["environment"]); e != "" {
			envSlug = e
		}
	}

	// If a project is specified (or if policies exist and projects exist), mint a project Service Token (`duck_st_*`).
	if projRef != "" {
		proj, err := s.resolveProject(r.Context(), projRef)
		if err != nil {
			writeVaultFromAPIError(w, fromStore(err, "project"))
			return
		}
		if err := s.allow(r, p, auth.PermProjectsWrite, "project", proj.ID); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}

		var validPerms []string
		for _, pol := range body.Policies {
			if allowedTokenPerms[pol] {
				validPerms = append(validPerms, pol)
			}
		}
		if len(validPerms) == 0 {
			validPerms = []string{auth.PermSecretsRead, auth.PermCredentialsRead}
		}

		ttlSec, err := parseVaultTTL(body.TTL, 86400*30)
		if err != nil {
			writeVaultErr(w, http.StatusBadRequest, err.Error())
			return
		}
		expiresAt := sql.NullTime{
			Time:  store.Now().Add(time.Duration(ttlSec) * time.Second),
			Valid: true,
		}

		rawToken, prefix, tokenHash, err := generateServiceToken()
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		name := strings.TrimSpace(body.DisplayName)
		if name == "" {
			name = "vault-token-" + prefix[:12]
		}
		id := store.NewID()
		now := store.Now()
		singleUse := body.NumUses == 1

		if err := s.Store.Q.CreateServiceToken(r.Context(), db.CreateServiceTokenParams{
			ID:              id,
			Name:            name,
			TokenHash:       tokenHash,
			TokenPrefix:     prefix,
			ProjectID:       proj.ID,
			EnvironmentSlug: envSlug,
			Path:            "/",
			Permissions:     strings.Join(validPerms, " "),
			AllowedCidrs:    "",
			SingleUse:       singleUse,
			CreatedBy:       p.User.Username,
			Now:             now,
			ExpiresAt:       expiresAt,
		}); err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeVaultStatus(w, http.StatusOK, "", 0, false, nil, &vaultAuthInfo{
			ClientToken:   rawToken,
			Accessor:      prefix,
			Policies:      append([]string{"default"}, validPerms...),
			TokenPolicies: validPerms,
			Metadata: map[string]string{
				"project_id":  proj.ID,
				"environment": envSlug,
			},
			LeaseDuration: ttlSec,
			Renewable:     false,
			EntityID:      id,
			TokenType:     "service",
			Orphan:        true,
		})
		return
	}

	// Otherwise create a session token for the current user
	tok, err := s.Auth.NewSession(r.Context(), p.User.ID, p.IP, r.UserAgent())
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	policies := append([]string{"default"}, p.Perms...)
	writeVaultStatus(w, http.StatusOK, "", 0, false, nil, &vaultAuthInfo{
		ClientToken:   tok,
		Accessor:      "acc_" + p.User.ID,
		Policies:      policies,
		TokenPolicies: policies,
		Metadata:      body.Meta,
		LeaseDuration: int(auth.SessionAbsolute / time.Second),
		Renewable:     true,
		EntityID:      p.User.ID,
		TokenType:     "service",
		Orphan:        true,
	})
}

func (s *Server) vaultTokenLookupSelf(w http.ResponseWriter, r *http.Request, p principal) {
	ttl := int(auth.SessionAbsolute / time.Second)
	policies := append([]string{"default"}, p.Perms...)
	meta := map[string]string{
		"username": p.User.Username,
		"role":     p.User.Role,
	}
	if p.ServiceToken != nil {
		meta["project_id"] = p.ServiceToken.ProjectID
		meta["environment"] = p.ServiceToken.EnvironmentSlug
		if p.ServiceToken.ExpiresAt.Valid {
			rem := int(time.Until(p.ServiceToken.ExpiresAt.Time).Seconds())
			if rem < 0 {
				rem = 0
			}
			ttl = rem
		}
	}
	writeVaultOK(w, map[string]any{
		"accessor":         p.SessionHash,
		"creation_time":    time.Now().UTC().Unix(),
		"creation_ttl":     ttl,
		"display_name":     p.User.Username,
		"entity_id":        p.User.ID,
		"expire_time":      nil,
		"explicit_max_ttl": 0,
		"id":               "redacted",
		"meta":             meta,
		"num_uses":         0,
		"orphan":           true,
		"path":             "auth/token/create",
		"policies":         policies,
		"renewable":        p.ServiceToken == nil,
		"ttl":              ttl,
		"type":             "service",
	})
}

func (s *Server) vaultTokenRevokeSelf(w http.ResponseWriter, r *http.Request, p principal) {
	if p.ServiceToken == nil && p.SessionHash != "" {
		_ = s.Auth.EndSession(r.Context(), p.SessionHash)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) vaultSysUIMounts(w http.ResponseWriter, r *http.Request, suffix string) {
	suffix = strings.TrimPrefix(suffix, "/")
	if suffix != "" {
		switch {
		case strings.HasPrefix(suffix, "database"):
			writeVaultOK(w, map[string]any{
				"type":        "database",
				"path":        "database/",
				"description": "DuckSecrets Dynamic Database Credentials Engine",
			})
			return
		case strings.HasPrefix(suffix, "transit"):
			writeVaultOK(w, map[string]any{
				"type":        "transit",
				"path":        "transit/",
				"description": "DuckSecrets Transit Encryption-as-a-Service Engine",
			})
			return
		}
		mount := "secret/"
		if strings.HasPrefix(suffix, "kv") {
			mount = "kv/"
		} else if strings.HasPrefix(suffix, "creds") {
			mount = "creds/"
		}
		writeVaultOK(w, map[string]any{
			"type":        "kv",
			"path":        mount,
			"description": "DuckSecrets KV v2 Engine",
			"options": map[string]string{
				"version": "2",
			},
		})
		return
	}

	writeVaultOK(w, map[string]any{
		"secret": map[string]any{
			"secret/": map[string]any{
				"type":        "kv",
				"description": "DuckSecrets Project & Environment KV v2 Secrets",
				"options":     map[string]string{"version": "2"},
			},
			"kv/": map[string]any{
				"type":        "kv",
				"description": "DuckSecrets Project & Environment KV v2 Secrets (alias)",
				"options":     map[string]string{"version": "2"},
			},
			"creds/": map[string]any{
				"type":        "kv",
				"description": "DuckSecrets Structured Credentials Vault (SSH, TLS, OAuth/API, Logins)",
				"options":     map[string]string{"version": "2"},
			},
			"database/": map[string]any{
				"type":        "database",
				"description": "DuckSecrets Dynamic Database Leases",
			},
			"transit/": map[string]any{
				"type":        "transit",
				"description": "DuckSecrets Transit Encryption-as-a-Service",
			},
		},
	})
}

func (s *Server) vaultSysMounts(w http.ResponseWriter, r *http.Request) {
	writeVaultOK(w, map[string]any{
		"secret/": map[string]any{
			"type":        "kv",
			"description": "DuckSecrets Project & Environment KV v2 Secrets",
			"options":     map[string]string{"version": "2"},
		},
		"creds/": map[string]any{
			"type":        "kv",
			"description": "DuckSecrets Structured Credentials Vault",
			"options":     map[string]string{"version": "2"},
		},
		"database/": map[string]any{
			"type":        "database",
			"description": "DuckSecrets Dynamic Database Leases",
		},
		"transit/": map[string]any{
			"type":        "transit",
			"description": "DuckSecrets Transit Encryption-as-a-Service",
		},
	})
}

// vaultSysCapabilitiesSelf implements `POST /v1/sys/capabilities-self` (used by `vault token capabilities <path>`).
func (s *Server) vaultSysCapabilitiesSelf(w http.ResponseWriter, r *http.Request, p principal) {
	var body struct {
		Paths []string `json:"paths"`
		Path  string   `json:"path"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	paths := body.Paths
	if body.Path != "" {
		paths = append(paths, body.Path)
	}

	result := map[string]any{}
	var lastCaps []string

	for _, rawP := range paths {
		clean := strings.TrimPrefix(strings.Trim(rawP, "/"), "v1/")
		caps := s.evaluateVaultCapabilities(r, p, clean)
		result[rawP] = caps
		lastCaps = caps
	}
	result["capabilities"] = lastCaps
	writeVaultOK(w, result)
}

func (s *Server) evaluateVaultCapabilities(r *http.Request, p principal, cleanPath string) []string {
	if auth.Has(p.Perms, auth.PermAll) {
		return []string{"root", "create", "read", "update", "patch", "delete", "list", "sudo"}
	}
	switch {
	case strings.HasPrefix(cleanPath, "secret/") || strings.HasPrefix(cleanPath, "kv/"):
		rest := strings.TrimPrefix(strings.TrimPrefix(cleanPath, "secret/"), "kv/")
		for _, pfx := range []string{"data/", "metadata/", "subkeys/", "delete/", "undelete/", "destroy/"} {
			rest = strings.TrimPrefix(rest, pfx)
		}
		projRef, envSlug, _, ok := parseVaultKVPath(rest)
		if !ok {
			return []string{"list"}
		}
		proj, err := s.resolveProject(r.Context(), projRef)
		if err != nil {
			return []string{"deny"}
		}
		var caps []string
		if s.allowEnv(r, p, auth.PermSecretsRead, proj.ID, envSlug) == nil {
			caps = append(caps, "read", "list")
		}
		if s.allowEnv(r, p, auth.PermSecretsWrite, proj.ID, envSlug) == nil {
			caps = append(caps, "create", "update", "patch", "delete")
		}
		if len(caps) == 0 {
			return []string{"deny"}
		}
		return caps

	case strings.HasPrefix(cleanPath, "creds/"):
		rest := strings.TrimPrefix(strings.TrimPrefix(cleanPath, "creds/"), "data/")
		rest = strings.TrimPrefix(rest, "metadata/")
		parts := strings.SplitN(strings.Trim(rest, "/"), "/", 2)
		var caps []string
		if len(parts) == 2 && !strings.EqualFold(parts[0], "global") {
			if proj, err := s.resolveProject(r.Context(), parts[0]); err == nil {
				if s.allowEnv(r, p, auth.PermCredentialsRead, proj.ID, "") == nil {
					caps = append(caps, "read", "list")
				}
				if s.allowEnv(r, p, auth.PermCredentialsWrite, proj.ID, "") == nil {
					caps = append(caps, "create", "update", "patch", "delete")
				}
				if len(caps) == 0 {
					return []string{"deny"}
				}
				return caps
			}
		}
		if auth.Has(p.Perms, auth.PermCredentialsRead) {
			caps = append(caps, "read", "list")
		}
		if auth.Has(p.Perms, auth.PermCredentialsWrite) {
			caps = append(caps, "create", "update", "patch", "delete")
		}
		if len(caps) == 0 {
			return []string{"deny"}
		}
		return caps

	case strings.HasPrefix(cleanPath, "transit/"):
		if auth.Has(p.Perms, auth.PermSecretsRead) {
			return []string{"create", "read", "update", "list"}
		}
		return []string{"deny"}
	}
	return []string{"read"}
}

// ---- Response Wrapping (/v1/sys/wrapping/*) ----

func (s *Server) storeWrappedPayload(ctx context.Context, rawJSON []byte, ttlSec int, creationPath, createdBy string) (*vaultWrapInfo, error) {
	if ttlSec <= 0 {
		ttlSec = 300
	} else if ttlSec > 86400*7 {
		ttlSec = 86400 * 7
	}
	wrapVault, err := s.Vault.DeriveSubVault("vault_wrapping", "v1")
	if err != nil {
		return nil, err
	}
	ciphertext, nonce, err := wrapVault.Encrypt(rawJSON)
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 12)
	_, _ = rand.Read(idBytes)
	wrapToken := "vw_" + hex.EncodeToString(idBytes)
	now := store.Now()
	expiresAt := now.Add(time.Duration(ttlSec) * time.Second)

	if err := s.Store.Q.CreateShare(ctx, db.CreateShareParams{
		ID:             wrapToken,
		Ciphertext:     ciphertext,
		Nonce:          nonce,
		ExpiresAt:      expiresAt,
		MaxViews:       1,
		HasPassphrase:  false,
		PassphraseSalt: []byte(creationPath),
		CreatedBy:      createdBy,
		Now:            now,
	}); err != nil {
		return nil, err
	}

	return &vaultWrapInfo{
		Token:        wrapToken,
		Accessor:     "acc_" + wrapToken[:10],
		TTL:          ttlSec,
		CreationTime: now.UTC(),
		CreationPath: creationPath,
	}, nil
}

func (s *Server) vaultSysWrappingWrap(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var data map[string]any
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil || len(data) == 0 {
		writeVaultErr(w, http.StatusBadRequest, "wrap body must be a non-empty JSON object")
		return
	}
	ttlSec, err := parseVaultTTL(r.Header.Get("X-Vault-Wrap-TTL"), 300)
	if err != nil {
		writeVaultErr(w, http.StatusBadRequest, err.Error())
		return
	}
	envBytes, _ := json.Marshal(vaultEnvelope{
		RequestID: uuid.NewString(),
		Data:      data,
	})
	info, err := s.storeWrappedPayload(r.Context(), envBytes, ttlSec, "sys/wrapping/wrap", p.User.Username)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeVaultWrapped(w, info)
}

func (s *Server) vaultSysWrappingUnwrap(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	tok := strings.TrimSpace(body.Token)
	if tok == "" {
		tok = strings.TrimSpace(r.Header.Get("X-Vault-Token"))
	}
	if !strings.HasPrefix(tok, "vw_") {
		writeVaultErr(w, http.StatusBadRequest, "wrapping token is not valid or does not exist")
		return
	}

	now := store.Now()
	var rawPlain []byte
	err := s.Store.Tx(r.Context(), func(q *db.Queries) error {
		n, err := q.ConsumeShareView(r.Context(), db.ConsumeShareViewParams{
			ID:  tok,
			Now: now,
		})
		if err != nil || n == 0 {
			return store.ErrNotFound
		}
		row, err := q.GetShareForReveal(r.Context(), tok)
		if err != nil {
			return store.ErrNotFound
		}
		wrapVault, err := s.Vault.DeriveSubVault("vault_wrapping", "v1")
		if err != nil {
			return err
		}
		rawPlain, err = wrapVault.Decrypt(row.Ciphertext, row.Nonce)
		if err != nil {
			return err
		}
		return q.BurnShare(r.Context(), db.BurnShareParams{
			BurnedAt:        sql.NullTime{Time: now, Valid: true},
			EmptyCiphertext: []byte{},
			EmptyNonce:      []byte{},
			ID:              tok,
		})
	})
	if err != nil {
		writeVaultErr(w, http.StatusBadRequest, "wrapping token is not valid or has already been unwrapped")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rawPlain)
}

func (s *Server) vaultSysWrappingLookup(w http.ResponseWriter, r *http.Request, p principal) {
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	tok := strings.TrimSpace(body.Token)
	if tok == "" {
		tok = strings.TrimSpace(r.Header.Get("X-Vault-Token"))
	}
	meta, err := s.Store.Q.GetShareMetadata(r.Context(), tok)
	if err != nil || meta.BurnedAt.Valid || meta.ViewCount >= meta.MaxViews || store.Now().After(meta.ExpiresAt) {
		writeVaultErr(w, http.StatusBadRequest, "wrapping token is not valid or does not exist")
		return
	}
	ttl := int(meta.ExpiresAt.Sub(meta.CreatedAt).Seconds())
	writeVaultOK(w, map[string]any{
		"creation_path": string(meta.PassphraseSalt),
		"creation_time": meta.CreatedAt.UTC().Format(time.RFC3339Nano),
		"creation_ttl":  ttl,
	})
}

func (s *Server) vaultSysWrappingRewrap(w http.ResponseWriter, r *http.Request, p principal) {
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	tok := strings.TrimSpace(body.Token)
	if tok == "" {
		tok = strings.TrimSpace(r.Header.Get("X-Vault-Token"))
	}
	now := store.Now()
	row, err := s.Store.Q.GetShareForReveal(r.Context(), tok)
	if err != nil || row.BurnedAt.Valid || row.ViewCount >= row.MaxViews || now.After(row.ExpiresAt) {
		writeVaultErr(w, http.StatusBadRequest, "wrapping token is not valid or does not exist")
		return
	}
	wrapVault, err := s.Vault.DeriveSubVault("vault_wrapping", "v1")
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rawPlain, err := wrapVault.Decrypt(row.Ciphertext, row.Nonce)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.Store.Q.BurnShare(r.Context(), db.BurnShareParams{
		BurnedAt:        sql.NullTime{Time: now, Valid: true},
		EmptyCiphertext: []byte{},
		EmptyNonce:      []byte{},
		ID:              tok,
	})
	ttl := int(row.ExpiresAt.Sub(row.CreatedAt).Seconds())
	info, err := s.storeWrappedPayload(r.Context(), rawPlain, ttl, string(row.PassphraseSalt), p.User.Username)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeVaultWrapped(w, info)
}

// ---- KV v2 Secrets Engine (/v1/secret/... and /v1/kv/...) ----

func parseVaultKVPath(rawPath string) (projectRef, envSlug, subPath string, ok bool) {
	clean := strings.Trim(rawPath, "/")
	if clean == "" {
		return "", "", "/", false
	}
	parts := strings.SplitN(clean, "/", 3)
	if len(parts) < 2 {
		return parts[0], "", "/", false
	}
	projectRef = parts[0]
	envSlug = parts[1]
	subPath = "/"
	if len(parts) == 3 && strings.TrimSpace(parts[2]) != "" {
		subPath = normalizePath(parts[2])
	}
	return projectRef, envSlug, subPath, true
}

func (s *Server) vaultKVData(w http.ResponseWriter, r *http.Request, p principal, rawPath string) {
	projectRef, envSlug, subPath, ok := parseVaultKVPath(rawPath)
	if !ok {
		writeVaultErr(w, http.StatusBadRequest, "KV path must be <project>/<environment>[/<path>]")
		return
	}

	proj, err := s.resolveProject(r.Context(), projectRef)
	if err != nil {
		writeVaultFromAPIError(w, fromStore(err, "project"))
		return
	}

	switch r.Method {
	case http.MethodGet:
		if err := s.allowEnv(r, p, auth.PermSecretsRead, proj.ID, envSlug); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}
		if !serviceTokenAllowsPath(p, subPath) {
			writeVaultErr(w, http.StatusForbidden, "permission denied for path "+subPath)
			return
		}

		subVault, err := s.projectVault(proj.ID)
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		rows, err := s.Store.Q.ListSecrets(r.Context(), db.ListSecretsParams{
			ProjectID:       proj.ID,
			EnvironmentSlug: envSlug,
			Path:            subPath,
		})
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		singleKeyMode := false
		if len(rows) == 0 && subPath != "/" && !strings.Contains(strings.TrimPrefix(subPath, "/"), "/") {
			candidateKey := strings.TrimPrefix(subPath, "/")
			if sec, kErr := s.Store.Q.GetSecretByKey(r.Context(), db.GetSecretByKeyParams{
				ProjectID:       proj.ID,
				EnvironmentSlug: envSlug,
				Path:            "/",
				Key:             candidateKey,
			}); kErr == nil {
				rows = []db.Secret{sec}
				singleKeyMode = true
			}
		}

		if len(rows) == 0 {
			// Fallback: if the requested environment had 0 secrets at "/", check if any other environment in this project has the requested key (or all keys if only 1 env has secrets).
			allProjSecrets, _ := s.Store.Q.ListSecretsAllPaths(r.Context(), db.ListSecretsAllPathsParams{
				ProjectID:       proj.ID,
				EnvironmentSlug: envSlug,
			})
			if len(allProjSecrets) == 0 {
				envs, _ := s.Store.Q.ListEnvironmentsByProject(r.Context(), proj.ID)
				for _, env := range envs {
					if s.allowEnv(r, p, auth.PermSecretsRead, proj.ID, env.Slug) != nil {
						continue
					}
					candidateRows, _ := s.Store.Q.ListSecrets(r.Context(), db.ListSecretsParams{
						ProjectID:       proj.ID,
						EnvironmentSlug: env.Slug,
						Path:            subPath,
					})
					if len(candidateRows) == 0 && subPath != "/" && !strings.Contains(strings.TrimPrefix(subPath, "/"), "/") {
						candidateKey := strings.TrimPrefix(subPath, "/")
						if sec, kErr := s.Store.Q.GetSecretByKey(r.Context(), db.GetSecretByKeyParams{
							ProjectID:       proj.ID,
							EnvironmentSlug: env.Slug,
							Path:            "/",
							Key:             candidateKey,
						}); kErr == nil {
							candidateRows = []db.Secret{sec}
							singleKeyMode = true
						}
					}
					if len(candidateRows) > 0 {
						rows = candidateRows
						envSlug = env.Slug
						break
					}
				}
			}
		}

		if len(rows) == 0 {
			writeVaultErr(w, http.StatusNotFound, "no secrets found at path")
			return
		}

		if err := s.consumeSingleUseToken(r, p); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}

		reqVersion := 0
		if vStr := strings.TrimSpace(r.URL.Query().Get("version")); vStr != "" {
			if parsedV, vErr := strconv.Atoi(vStr); vErr == nil && parsedV > 0 {
				reqVersion = parsedV
			}
		}

		dataMap := make(map[string]any, len(rows))
		var maxVer int32 = 1
		var latestTime time.Time

		if singleKeyMode && reqVersion > 0 && len(rows) == 1 {
			sv, vErr := s.Store.Q.GetSecretVersion(r.Context(), db.GetSecretVersionParams{
				SecretID: rows[0].ID,
				Version:  int32(reqVersion),
			})
			if vErr != nil {
				writeVaultErr(w, http.StatusNotFound, fmt.Sprintf("version %d not found", reqVersion))
				return
			}
			plain, decErr := subVault.Decrypt(sv.ValueEncrypted, sv.ValueNonce)
			if decErr != nil {
				writeVaultErr(w, http.StatusInternalServerError, "decryption error")
				return
			}
			dataMap[rows[0].Key] = string(plain)
			maxVer = sv.Version
			latestTime = sv.CreatedAt.UTC()
		} else {
			_, expandedByPath := decryptRowsAndExpand(rows, subVault)
			for _, row := range rows {
				val := ""
				if pm := expandedByPath[row.Path]; pm != nil {
					val = pm[row.Key]
				}
				dataMap[row.Key] = val
				if row.Version > maxVer {
					maxVer = row.Version
				}
				if row.UpdatedAt.After(latestTime) {
					latestTime = row.UpdatedAt.UTC()
				}
			}
		}

		// If single-key or single-secret environment, also populate common password aliases ("password", "value")
		// when not already present, so external tools (like Zabbix, Nagios, Portainer, etc.) that look up a single secret
		// or use Engine Mount as the key name can always extract the password/value seamlessly.
		if len(dataMap) == 1 {
			for _, v := range dataMap {
				if _, has := dataMap["password"]; !has {
					dataMap["password"] = v
				}
				if _, has := dataMap["value"]; !has {
					dataMap["value"] = v
				}
				break
			}
		}

		s.record(r, p, "vault.kv.read", "environment", envSlug, map[string]any{
			"project_id":  proj.ID,
			"environment": envSlug,
			"path":        subPath,
			"count":       len(dataMap),
		})

		writeVaultOK(w, map[string]any{
			"data": dataMap,
			"metadata": map[string]any{
				"created_time":    latestTime.Format(time.RFC3339Nano),
				"custom_metadata": nil,
				"deletion_time":   "",
				"destroyed":       false,
				"version":         maxVer,
			},
		})

	case http.MethodPost, http.MethodPut, http.MethodPatch:
		if err := s.allowEnv(r, p, auth.PermSecretsWrite, proj.ID, envSlug); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}
		if _, err := s.Store.Q.GetEnvironmentBySlug(r.Context(), db.GetEnvironmentBySlugParams{
			ProjectID: proj.ID,
			Slug:      envSlug,
		}); err != nil {
			writeVaultFromAPIError(w, fromStore(err, "environment"))
			return
		}
		if !serviceTokenAllowsPath(p, subPath) {
			writeVaultErr(w, http.StatusForbidden, "permission denied for path "+subPath)
			return
		}

		var body struct {
			Data    map[string]any `json:"data"`
			Options struct {
				CAS *int32 `json:"cas"`
			} `json:"options"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Data == nil {
			writeVaultErr(w, http.StatusBadRequest, "request body must contain a 'data' map")
			return
		}

		isPatch := r.Method == http.MethodPatch || strings.Contains(r.Header.Get("Content-Type"), "merge-patch+json")

		subVault, err := s.projectVault(proj.ID)
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err := s.consumeSingleUseToken(r, p); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}

		now := store.Now()
		var maxVer int32 = 1

		err = s.Store.Tx(r.Context(), func(q *db.Queries) error {
			for k, rawV := range body.Data {
				key := strings.TrimSpace(k)
				if key == "" {
					continue
				}
				// RFC 7396 merge-patch: null value deletes the key
				if isPatch && rawV == nil {
					if existing, getErr := q.GetSecretByKey(r.Context(), db.GetSecretByKeyParams{
						ProjectID:       proj.ID,
						EnvironmentSlug: envSlug,
						Path:            subPath,
						Key:             key,
					}); getErr == nil {
						_, _ = q.DeleteSecret(r.Context(), existing.ID)
					}
					continue
				}

				strVal := fmt.Sprint(rawV)
				if sVal, isStr := rawV.(string); isStr {
					strVal = sVal
				} else if b, mErr := json.Marshal(rawV); mErr == nil {
					strVal = string(b)
				}

				ciphertext, nonce, encErr := subVault.Encrypt([]byte(strVal))
				if encErr != nil {
					return encErr
				}

				existing, getErr := q.GetSecretByKey(r.Context(), db.GetSecretByKeyParams{
					ProjectID:       proj.ID,
					EnvironmentSlug: envSlug,
					Path:            subPath,
					Key:             key,
				})
				if getErr != nil {
					if body.Options.CAS != nil && *body.Options.CAS != 0 {
						return fmt.Errorf("check-and-set mismatch: key %q does not exist (expected version %d)", key, *body.Options.CAS)
					}
					secID := store.NewID()
					verID := store.NewID()
					if err := q.CreateSecret(r.Context(), db.CreateSecretParams{
						ID:              secID,
						ProjectID:       proj.ID,
						EnvironmentSlug: envSlug,
						Path:            subPath,
						Key:             key,
						ValueEncrypted:  ciphertext,
						ValueNonce:      nonce,
						Comment:         "Written via Vault KV v2 API",
						Version:         1,
						Now:             now,
					}); err != nil {
						return err
					}
					if err := q.CreateSecretVersion(r.Context(), db.CreateSecretVersionParams{
						ID:             verID,
						SecretID:       secID,
						Version:        1,
						ValueEncrypted: ciphertext,
						ValueNonce:     nonce,
						Comment:        "Written via Vault KV v2 API",
						Now:            now,
						CreatedBy:      p.User.Username,
					}); err != nil {
						return err
					}
				} else {
					if body.Options.CAS != nil && *body.Options.CAS != existing.Version {
						return fmt.Errorf("check-and-set mismatch on key %q: current version is %d, cas was %d", key, existing.Version, *body.Options.CAS)
					}
					newVer := existing.Version + 1
					if newVer > maxVer {
						maxVer = newVer
					}
					if err := q.UpdateSecret(r.Context(), db.UpdateSecretParams{
						ValueEncrypted: ciphertext,
						ValueNonce:     nonce,
						Comment:        existing.Comment,
						Now:            now,
						ID:             existing.ID,
					}); err != nil {
						return err
					}
					if err := q.CreateSecretVersion(r.Context(), db.CreateSecretVersionParams{
						ID:             store.NewID(),
						SecretID:       existing.ID,
						Version:        newVer,
						ValueEncrypted: ciphertext,
						ValueNonce:     nonce,
						Comment:        existing.Comment,
						Now:            now,
						CreatedBy:      p.User.Username,
					}); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			writeVaultErr(w, http.StatusBadRequest, err.Error())
			return
		}

		s.record(r, p, "vault.kv.write", "environment", envSlug, map[string]any{
			"project_id":  proj.ID,
			"environment": envSlug,
			"path":        subPath,
		})
		s.changed(r, "secret", "")

		writeVaultOK(w, map[string]any{
			"created_time":    now.UTC().Format(time.RFC3339Nano),
			"custom_metadata": nil,
			"deletion_time":   "",
			"destroyed":       false,
			"version":         maxVer,
		})

	case http.MethodDelete:
		if err := s.allowEnv(r, p, auth.PermSecretsWrite, proj.ID, envSlug); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}
		rows, err := s.Store.Q.ListSecrets(r.Context(), db.ListSecretsParams{
			ProjectID:       proj.ID,
			EnvironmentSlug: envSlug,
			Path:            subPath,
		})
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(rows) == 0 && subPath != "/" && !strings.Contains(strings.TrimPrefix(subPath, "/"), "/") {
			candidateKey := strings.TrimPrefix(subPath, "/")
			if sec, kErr := s.Store.Q.GetSecretByKey(r.Context(), db.GetSecretByKeyParams{
				ProjectID:       proj.ID,
				EnvironmentSlug: envSlug,
				Path:            "/",
				Key:             candidateKey,
			}); kErr == nil {
				rows = []db.Secret{sec}
			}
		}
		for _, row := range rows {
			_, _ = s.Store.Q.DeleteSecret(r.Context(), row.ID)
		}
		s.record(r, p, "vault.kv.delete", "environment", envSlug, map[string]any{
			"project_id":  proj.ID,
			"environment": envSlug,
			"path":        subPath,
			"deleted":     len(rows),
		})
		s.changed(r, "secret", "")
		w.WriteHeader(http.StatusNoContent)

	default:
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// vaultKVSubkeys implements `GET /v1/secret/subkeys/{project}/{env}[/{subpath}]`,
// returning the key structure with `null` values (without decrypting secret values).
func (s *Server) vaultKVSubkeys(w http.ResponseWriter, r *http.Request, p principal, rawPath string) {
	projectRef, envSlug, subPath, ok := parseVaultKVPath(rawPath)
	if !ok {
		writeVaultErr(w, http.StatusBadRequest, "KV path must be <project>/<environment>[/<path>]")
		return
	}
	proj, err := s.resolveProject(r.Context(), projectRef)
	if err != nil {
		writeVaultFromAPIError(w, fromStore(err, "project"))
		return
	}
	if err := s.allowEnv(r, p, auth.PermSecretsRead, proj.ID, envSlug); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}
	rows, err := s.Store.Q.ListSecrets(r.Context(), db.ListSecretsParams{
		ProjectID:       proj.ID,
		EnvironmentSlug: envSlug,
		Path:            subPath,
	})
	if err != nil || len(rows) == 0 {
		writeVaultErr(w, http.StatusNotFound, "no secrets found at path")
		return
	}
	subkeys := make(map[string]any, len(rows))
	var maxVer int32 = 1
	var latestTime time.Time
	for _, row := range rows {
		subkeys[row.Key] = nil
		if row.Version > maxVer {
			maxVer = row.Version
		}
		if row.UpdatedAt.After(latestTime) {
			latestTime = row.UpdatedAt.UTC()
		}
	}
	writeVaultOK(w, map[string]any{
		"subkeys": subkeys,
		"metadata": map[string]any{
			"created_time":    latestTime.Format(time.RFC3339Nano),
			"custom_metadata": nil,
			"deletion_time":   "",
			"destroyed":       false,
			"version":         maxVer,
		},
	})
}

// vaultKVVersionOp implements `/v1/secret/{delete,undelete,destroy}/{project}/{env}[/{key}]`.
func (s *Server) vaultKVVersionOp(w http.ResponseWriter, r *http.Request, p principal, rawPath, op string) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectRef, envSlug, subPath, ok := parseVaultKVPath(rawPath)
	if !ok {
		writeVaultErr(w, http.StatusBadRequest, "KV path must be <project>/<environment>[/<key>]")
		return
	}
	proj, err := s.resolveProject(r.Context(), projectRef)
	if err != nil {
		writeVaultFromAPIError(w, fromStore(err, "project"))
		return
	}
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, proj.ID, envSlug); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}

	var body struct {
		Versions []int32 `json:"versions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	rows, _ := s.Store.Q.ListSecrets(r.Context(), db.ListSecretsParams{
		ProjectID:       proj.ID,
		EnvironmentSlug: envSlug,
		Path:            subPath,
	})
	if len(rows) == 0 && subPath != "/" && !strings.Contains(strings.TrimPrefix(subPath, "/"), "/") {
		candidateKey := strings.TrimPrefix(subPath, "/")
		if sec, kErr := s.Store.Q.GetSecretByKey(r.Context(), db.GetSecretByKeyParams{
			ProjectID:       proj.ID,
			EnvironmentSlug: envSlug,
			Path:            "/",
			Key:             candidateKey,
		}); kErr == nil {
			rows = []db.Secret{sec}
		}
	}

	switch op {
	case "destroy":
		for _, row := range rows {
			for _, ver := range body.Versions {
				_, _ = s.Store.Q.DeleteSecretVersion(r.Context(), db.DeleteSecretVersionParams{
					SecretID: row.ID,
					Version:  ver,
				})
			}
		}
	case "undelete":
		// If a prior version was requested, rollback the active secret to that version
		if len(body.Versions) > 0 {
			targetVer := body.Versions[len(body.Versions)-1]
			now := store.Now()
			for _, row := range rows {
				if sv, vErr := s.Store.Q.GetSecretVersion(r.Context(), db.GetSecretVersionParams{
					SecretID: row.ID,
					Version:  targetVer,
				}); vErr == nil {
					_ = s.Store.Q.RollbackSecret(r.Context(), db.RollbackSecretParams{
						ValueEncrypted: sv.ValueEncrypted,
						ValueNonce:     sv.ValueNonce,
						Comment:        sv.Comment,
						Version:        row.Version + 1,
						Now:            now,
						ID:             row.ID,
					})
				}
			}
		}
	case "delete":
		for _, row := range rows {
			if len(body.Versions) == 0 {
				_, _ = s.Store.Q.DeleteSecret(r.Context(), row.ID)
			} else {
				for _, ver := range body.Versions {
					if ver == row.Version {
						_, _ = s.Store.Q.DeleteSecret(r.Context(), row.ID)
					}
				}
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) vaultKVMetadata(w http.ResponseWriter, r *http.Request, p principal, rawPath string) {
	clean := strings.Trim(rawPath, "/")

	if clean == "" {
		if !isVaultListRequest(r) {
			writeVaultErr(w, http.StatusBadRequest, "use LIST or ?list=true on metadata root")
			return
		}
		projects, err := s.Store.Q.ListProjects(r.Context())
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		var keys []string
		for _, prj := range projects {
			if s.allow(r, p, auth.PermProjectsRead, "project", prj.ID) == nil {
				keys = append(keys, prj.Slug+"/")
			}
		}
		sort.Strings(keys)
		writeVaultOK(w, map[string]any{"keys": keys})
		return
	}

	parts := strings.SplitN(clean, "/", 3)
	proj, err := s.resolveProject(r.Context(), parts[0])
	if err != nil {
		writeVaultFromAPIError(w, fromStore(err, "project"))
		return
	}

	if len(parts) == 1 {
		if !isVaultListRequest(r) {
			writeVaultErr(w, http.StatusBadRequest, "use LIST or ?list=true on project metadata path")
			return
		}
		envs, err := s.Store.Q.ListEnvironmentsByProject(r.Context(), proj.ID)
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		var keys []string
		for _, env := range envs {
			if s.allowEnv(r, p, auth.PermSecretsRead, proj.ID, env.Slug) == nil {
				keys = append(keys, env.Slug+"/")
			}
		}
		sort.Strings(keys)
		writeVaultOK(w, map[string]any{"keys": keys})
		return
	}

	envSlug := parts[1]
	if err := s.allowEnv(r, p, auth.PermSecretsRead, proj.ID, envSlug); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}

	subPath := "/"
	if len(parts) == 3 && strings.TrimSpace(parts[2]) != "" {
		subPath = normalizePath(parts[2])
	}

	if isVaultListRequest(r) {
		rows, err := s.Store.Q.ListSecrets(r.Context(), db.ListSecretsParams{
			ProjectID:       proj.ID,
			EnvironmentSlug: envSlug,
			Path:            subPath,
		})
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		keys := make([]string, 0, len(rows))
		for _, row := range rows {
			keys = append(keys, row.Key)
		}
		sort.Strings(keys)
		writeVaultOK(w, map[string]any{"keys": keys})
		return
	}

	if r.Method == http.MethodDelete {
		s.vaultKVData(w, r, p, rawPath)
		return
	}

	rows, err := s.Store.Q.ListSecrets(r.Context(), db.ListSecretsParams{
		ProjectID:       proj.ID,
		EnvironmentSlug: envSlug,
		Path:            subPath,
	})
	if err != nil || len(rows) == 0 {
		writeVaultErr(w, http.StatusNotFound, "metadata not found")
		return
	}
	var maxVer int32 = 1
	var createdTime, updatedTime time.Time
	for i, row := range rows {
		if i == 0 || row.CreatedAt.Before(createdTime) {
			createdTime = row.CreatedAt.UTC()
		}
		if row.UpdatedAt.After(updatedTime) {
			updatedTime = row.UpdatedAt.UTC()
		}
		if row.Version > maxVer {
			maxVer = row.Version
		}
	}

	versionsMap := map[string]any{}
	for v := int32(1); v <= maxVer; v++ {
		versionsMap[strconv.Itoa(int(v))] = map[string]any{
			"created_time":  updatedTime.Format(time.RFC3339Nano),
			"deletion_time": "",
			"destroyed":     false,
		}
	}

	writeVaultOK(w, map[string]any{
		"cas_required":         false,
		"created_time":         createdTime.Format(time.RFC3339Nano),
		"current_version":      maxVer,
		"custom_metadata":      nil,
		"delete_version_after": "0s",
		"max_versions":         0,
		"oldest_version":       1,
		"updated_time":         updatedTime.Format(time.RFC3339Nano),
		"versions":             versionsMap,
	})
}

// ---- Structured Credentials Engine (/v1/creds/* and /v1/ssh/*) ----

// vaultCredsData supports GET, POST/PUT/PATCH, and DELETE on:
//   - /v1/creds/data/global/<name-or-id>
//   - /v1/creds/data/<project>/<name-or-id>
//   - /v1/creds/data/<name-or-id>
func (s *Server) vaultCredsData(w http.ResponseWriter, r *http.Request, p principal, rawPath string) {
	clean := strings.Trim(rawPath, "/")
	if clean == "" {
		writeVaultErr(w, http.StatusBadRequest, "credential path is required")
		return
	}

	parts := strings.SplitN(clean, "/", 2)
	var projectID string
	targetRef := clean
	if len(parts) == 2 {
		if !strings.EqualFold(parts[0], "global") {
			proj, err := s.resolveProject(r.Context(), parts[0])
			if err != nil {
				writeVaultFromAPIError(w, fromStore(err, "project"))
				return
			}
			projectID = proj.ID
		}
		targetRef = parts[1]
	}

	rows, err := s.Store.Q.ListAllCredentials(r.Context())
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var matched *db.Credential
	for i := range rows {
		row := rows[i]
		if projectID != "" && row.ProjectID.String != projectID {
			continue
		}
		if row.ID == targetRef || strings.EqualFold(row.Name, targetRef) {
			matched = &row
			break
		}
	}

	switch r.Method {
	case http.MethodGet:
		if matched == nil {
			writeVaultErr(w, http.StatusNotFound, "credential not found")
			return
		}
		if !s.canReadCredential(r, p, *matched) {
			writeVaultErr(w, http.StatusForbidden, "permission denied (requires credentials.read / can_view_creds)")
			return
		}
		if err := s.consumeSingleUseToken(r, p); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}

		v, err := s.credentialVault(matched.ProjectID.String)
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		plain, err := v.Decrypt(matched.PayloadEncrypted, matched.PayloadNonce)
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, "decrypting credential payload")
			return
		}

		var payMap map[string]any
		_ = json.Unmarshal(plain, &payMap)
		if payMap == nil {
			payMap = map[string]any{}
		}
		payMap["id"] = matched.ID
		payMap["name"] = matched.Name
		payMap["kind"] = matched.Kind
		payMap["summary"] = matched.Summary

		s.record(r, p, "credential.read", "credential", matched.ID, map[string]any{
			"name":   matched.Name,
			"kind":   matched.Kind,
			"source": "vault_v1",
		})

		writeVaultOK(w, map[string]any{
			"data": payMap,
			"metadata": map[string]any{
				"created_time":    matched.CreatedAt.UTC().Format(time.RFC3339Nano),
				"custom_metadata": map[string]string{"kind": matched.Kind, "name": matched.Name},
				"deletion_time":   "",
				"destroyed":       false,
				"version":         1,
			},
		})

	case http.MethodPost, http.MethodPut, http.MethodPatch:
		var rawBody map[string]any
		if err := json.NewDecoder(r.Body).Decode(&rawBody); err != nil {
			writeVaultErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		// Accept both KV v2 wrapped `{"data": {...}}` and direct `{...}`
		dataObj := rawBody
		if inner, ok := rawBody["data"].(map[string]any); ok {
			dataObj = inner
		}

		envSlug, _ := dataObj["environment_slug"].(string)
		if matched != nil && envSlug == "" {
			envSlug = matched.EnvironmentSlug
		}
		targetProjID := projectID
		if matched != nil && targetProjID == "" {
			targetProjID = matched.ProjectID.String
		}

		if err := s.canWriteCredential(r, p, targetProjID, envSlug); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}

		kind, _ := dataObj["kind"].(string)
		if kind == "" && matched != nil {
			kind = matched.Kind
		}
		if kind == "" {
			// Infer kind from payload fields
			switch {
			case dataObj["private_key"] != nil && dataObj["certificate"] != nil:
				kind = "tls_cert"
			case dataObj["private_key"] != nil || dataObj["public_key"] != nil:
				kind = "ssh_key"
			case dataObj["api_key"] != nil || dataObj["client_secret"] != nil:
				kind = "oauth_api"
			default:
				kind = "login"
			}
		}
		if !validCredentialKind(kind) {
			writeVaultErr(w, http.StatusBadRequest, "kind must be ssh_key, tls_cert, oauth_api, or login")
			return
		}

		payBytes, _ := json.Marshal(dataObj)
		var pay credentialPayload
		_ = json.Unmarshal(payBytes, &pay)

		summary, expires := enrichAndSummarizeCredential(kind, &pay, nil)
		enrichedBytes, _ := json.Marshal(pay)

		v, err := s.credentialVault(targetProjID)
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		ciphertext, nonce, err := v.Encrypt(enrichedBytes)
		if err != nil {
			writeVaultErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		now := store.Now()
		desc, _ := dataObj["description"].(string)

		if matched == nil {
			credID := store.NewID()
			if err := s.Store.Q.CreateCredential(r.Context(), db.CreateCredentialParams{
				ID:               credID,
				ProjectID:        store.NullString(targetProjID),
				EnvironmentSlug:  envSlug,
				Name:             targetRef,
				Kind:             kind,
				Description:      desc,
				Summary:          summary,
				PayloadEncrypted: ciphertext,
				PayloadNonce:     nonce,
				ExpiresAt:        nullTime(expires),
				CreatedBy:        p.User.Username,
				Now:              now,
			}); err != nil {
				writeVaultErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.record(r, p, "credential.create", "credential", credID, map[string]any{"name": targetRef, "kind": kind, "source": "vault_v1"})
			s.changed(r, "credential", credID)
		} else {
			if desc == "" {
				desc = matched.Description
			}
			if err := s.Store.Q.UpdateCredential(r.Context(), db.UpdateCredentialParams{
				ID:               matched.ID,
				ProjectID:        store.NullString(targetProjID),
				EnvironmentSlug:  envSlug,
				Name:             matched.Name,
				Description:      desc,
				Summary:          summary,
				PayloadEncrypted: ciphertext,
				PayloadNonce:     nonce,
				ExpiresAt:        nullTime(expires),
				Now:              now,
			}); err != nil {
				writeVaultErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.record(r, p, "credential.update", "credential", matched.ID, map[string]any{"name": matched.Name, "kind": kind, "source": "vault_v1"})
			s.changed(r, "credential", matched.ID)
		}

		writeVaultOK(w, map[string]any{
			"created_time":    now.UTC().Format(time.RFC3339Nano),
			"custom_metadata": map[string]string{"kind": kind, "name": targetRef},
			"deletion_time":   "",
			"destroyed":       false,
			"version":         1,
		})

	case http.MethodDelete:
		if matched == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := s.canWriteCredential(r, p, matched.ProjectID.String, matched.EnvironmentSlug); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}
		_, _ = s.Store.Q.DeleteCredential(r.Context(), matched.ID)
		s.record(r, p, "credential.delete", "credential", matched.ID, map[string]any{"name": matched.Name, "source": "vault_v1"})
		s.changed(r, "credential", matched.ID)
		w.WriteHeader(http.StatusNoContent)

	default:
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) vaultCredsMetadata(w http.ResponseWriter, r *http.Request, p principal, rawPath string) {
	if r.Method == http.MethodDelete {
		s.vaultCredsData(w, r, p, rawPath)
		return
	}
	if !isVaultListRequest(r) {
		writeVaultErr(w, http.StatusBadRequest, "use LIST or ?list=true on /v1/creds/metadata")
		return
	}
	rows, err := s.Store.Q.ListAllCredentials(r.Context())
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var keys []string
	for _, row := range rows {
		if s.canReadCredential(r, p, row) {
			keys = append(keys, row.Name)
		}
	}
	sort.Strings(keys)
	writeVaultOK(w, map[string]any{"keys": keys})
}

func (s *Server) vaultKVCustomMountData(w http.ResponseWriter, r *http.Request, p principal, mount, pathAfterData string) {
	// First try `<pathAfterData>/<mount>` in case the user put the Secret Key Name in "Engine Mount" (e.g. Engine Mount = "MYSQL_ROOT", Secret Path = "tt/prod")
	clean := strings.Trim(pathAfterData, "/")
	if strings.Count(clean, "/") == 1 {
		rec := httptest.NewRecorder()
		s.vaultKVData(rec, r, p, clean+"/"+mount)
		if rec.Code == http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
	}
	// Otherwise try standard KV data on pathAfterData, and fallback to Credentials Vault
	rec := httptest.NewRecorder()
	s.vaultKVData(rec, r, p, pathAfterData)
	if rec.Code == http.StatusNotFound {
		rec2 := httptest.NewRecorder()
		s.vaultCredsData(rec2, r, p, pathAfterData)
		if rec2.Code == http.StatusOK {
			rec = rec2
		}
	}
	for k, vals := range rec.Header() {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

// vaultKVv1OrCreds supports KV v1 (`Engine Version: 1`) and `cubbyhole` requests where clients call
// `/v1/<mount>/<path>` directly without `/data/` in the URL, and expect flat `{"data": {"k": "v"}}`
// (and also includes `"data": {"data": ...}` or flat fields so both v1 and v2 parsers work).
func (s *Server) vaultKVv1OrCreds(w http.ResponseWriter, r *http.Request, p principal, mount, rawPath string) {
	if isVaultListRequest(r) {
		if mount == "creds" {
			s.vaultCredsMetadata(w, r, p, rawPath)
		} else {
			s.vaultKVMetadata(w, r, p, rawPath)
		}
		return
	}

	rec := httptest.NewRecorder()
	if mount == "creds" {
		s.vaultCredsData(rec, r, p, rawPath)
	} else {
		// Try KV secrets first; if 404 on cubbyhole/secret, also check if it matches a Credential name!
		s.vaultKVData(rec, r, p, rawPath)
		if rec.Code == http.StatusNotFound {
			rec2 := httptest.NewRecorder()
			s.vaultCredsData(rec2, r, p, rawPath)
			if rec2.Code == http.StatusOK {
				rec = rec2
			}
		}
	}

	if rec.Code != http.StatusOK || r.Method != http.MethodGet {
		for k, vals := range rec.Header() {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}

	// Unwrap v2 `data.data` into v1 flat `data`
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err == nil {
		if outer, ok := env["data"].(map[string]any); ok {
			if inner, ok := outer["data"].(map[string]any); ok {
				writeVaultOK(w, inner)
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

// vaultSSHGenerate implements `/v1/creds/generate-ssh` and `/v1/ssh/creds/{role}` to generate SSH keypairs.
func (s *Server) vaultSSHGenerate(w http.ResponseWriter, r *http.Request, p principal) {
	if !auth.Has(p.Perms, auth.PermCredentialsWrite) && !auth.Has(p.Perms, auth.PermCredentialsRead) {
		writeVaultErr(w, http.StatusForbidden, "permission denied")
		return
	}
	var body generateSSHKeyRequest
	_ = json.NewDecoder(r.Body).Decode(&body)
	buf := new(bytes.Buffer)
	b, _ := json.Marshal(body)
	buf.Write(b)
	reqClone := r.Clone(r.Context())
	reqClone.Body = http.MaxBytesReader(w, nopCloser{buf}, 4096)

	rec := httptest.NewRecorder()
	if err := s.generateSSHKeypair(rec, reqClone, p); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}
	var gen generateSSHKeyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &gen)
	writeVaultOK(w, map[string]any{
		"private_key": gen.PrivateKey,
		"public_key":  gen.PublicKey,
		"fingerprint": gen.Fingerprint,
		"key_type":    gen.KeyType,
	})
}

type nopCloser struct{ *bytes.Buffer }

func (nopCloser) Close() error { return nil }

// ---- Dynamic Database Engine & Leases (/v1/database/* and /v1/sys/leases/*) ----

func (s *Server) vaultDatabaseRoles(w http.ResponseWriter, r *http.Request, p principal, rawPath string) {
	clean := strings.Trim(rawPath, "/")
	if isVaultListRequest(r) {
		projects, _ := s.Store.Q.ListProjects(r.Context())
		var keys []string
		for _, prj := range projects {
			envs, _ := s.Store.Q.ListEnvironmentsByProject(r.Context(), prj.ID)
			for _, env := range envs {
				if s.allowEnv(r, p, auth.PermSecretsRead, prj.ID, env.Slug) != nil {
					continue
				}
				provs, _ := s.Store.Q.ListDynamicProviders(r.Context(), db.ListDynamicProvidersParams{
					ProjectID:       prj.ID,
					EnvironmentSlug: env.Slug,
				})
				for _, prov := range provs {
					keys = append(keys, fmt.Sprintf("%s/%s/%s", prj.Slug, env.Slug, prov.Name))
				}
			}
		}
		sort.Strings(keys)
		writeVaultOK(w, map[string]any{"keys": keys})
		return
	}

	parts := strings.Split(clean, "/")
	if len(parts) == 3 {
		proj, err := s.resolveProject(r.Context(), parts[0])
		if err != nil {
			writeVaultFromAPIError(w, fromStore(err, "project"))
			return
		}
		if err := s.allowEnv(r, p, auth.PermSecretsRead, proj.ID, parts[1]); err != nil {
			writeVaultFromAPIError(w, err)
			return
		}
		prov, err := s.Store.Q.GetDynamicProviderByName(r.Context(), db.GetDynamicProviderByNameParams{
			ProjectID:       proj.ID,
			EnvironmentSlug: parts[1],
			Name:            parts[2],
		})
		if err != nil {
			writeVaultErr(w, http.StatusNotFound, "database role not found")
			return
		}
		writeVaultOK(w, map[string]any{
			"db_name":             prov.Name,
			"engine":              prov.Engine,
			"default_ttl":         prov.DefaultTtlSeconds,
			"max_ttl":             prov.MaxTtlSeconds,
			"creation_statements": []string{prov.RoleTemplate},
		})
		return
	}
	writeVaultErr(w, http.StatusBadRequest, "path must be /v1/database/roles/<project>/<env>/<provider> or ?list=true")
}

func (s *Server) vaultDatabaseCreds(w http.ResponseWriter, r *http.Request, p principal, rawPath string) {
	if r.Method != http.MethodGet {
		writeVaultErr(w, http.StatusMethodNotAllowed, "only GET is supported on /v1/database/creds/*")
		return
	}
	clean := strings.Trim(rawPath, "/")
	parts := strings.Split(clean, "/")

	var prov db.DynamicProvider
	var err error

	switch len(parts) {
	case 1:
		prov, err = s.Store.Q.GetDynamicProvider(r.Context(), parts[0])
		if err != nil {
			writeVaultErr(w, http.StatusNotFound, "dynamic provider not found")
			return
		}
	case 3:
		proj, pErr := s.resolveProject(r.Context(), parts[0])
		if pErr != nil {
			writeVaultFromAPIError(w, fromStore(pErr, "project"))
			return
		}
		envSlug := parts[1]
		target := parts[2]
		prov, err = s.Store.Q.GetDynamicProviderByName(r.Context(), db.GetDynamicProviderByNameParams{
			ProjectID:       proj.ID,
			EnvironmentSlug: envSlug,
			Name:            target,
		})
		if err != nil {
			prov, err = s.Store.Q.GetDynamicProvider(r.Context(), target)
			if err != nil || prov.ProjectID != proj.ID || prov.EnvironmentSlug != envSlug {
				writeVaultErr(w, http.StatusNotFound, "dynamic provider not found")
				return
			}
		}
	default:
		writeVaultErr(w, http.StatusBadRequest, "path must be /v1/database/creds/<project>/<env>/<provider> or /v1/database/creds/<provider_id>")
		return
	}

	if err := s.allowEnv(r, p, auth.PermSecretsRead, prov.ProjectID, prov.EnvironmentSlug); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}

	ttlSec := int(prov.DefaultTtlSeconds)
	if ttlSec <= 0 {
		ttlSec = 3600
	}
	ttl := time.Duration(ttlSec) * time.Second

	pv, err := s.projectVault(prov.ProjectID)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	configJSON, err := pv.Decrypt(prov.ConfigEncrypted, prov.ConfigNonce)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, "decrypting provider config")
		return
	}
	driver, err := dynamic.GetDriver(prov.Engine)
	if err != nil {
		writeVaultErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.allowDynamicExecution(prov.Engine, configJSON, nil); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}
	if err := s.consumeSingleUseToken(r, p); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}

	username, password, err := dynamic.GenerateRandomCredentials("duck_d_")
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	creds, err := driver.IssueLease(r.Context(), configJSON, prov.RoleTemplate, username, password, ttl)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	credsJSON, _ := json.Marshal(creds)
	credsEnc, credsNonce, err := pv.Encrypt(credsJSON)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	leaseID := "ls_" + uuid.NewString()[:12]
	now := store.Now()
	expiresAt := now.Add(ttl)

	issuedTo := p.User.Username
	if p.ServiceToken != nil {
		issuedTo = "token:" + p.ServiceToken.Name
	}

	if err := s.Store.Q.CreateDynamicLease(r.Context(), db.CreateDynamicLeaseParams{
		ID:                   leaseID,
		ProviderID:           prov.ID,
		Username:             username,
		CredentialsEncrypted: credsEnc,
		CredentialsNonce:     credsNonce,
		IssuedTo:             issuedTo,
		ExpiresAt:            expiresAt,
		Now:                  now,
	}); err != nil {
		_ = driver.RevokeLease(context.Background(), configJSON, username)
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "dynamic.lease_issue", "dynamic_lease", leaseID, map[string]any{
		"username":    username,
		"ttl_seconds": ttlSec,
		"source":      "vault_v1",
	})

	writeVaultStatus(w, http.StatusOK, leaseID, ttlSec, true, map[string]any{
		"username":          creds.Username,
		"password":          creds.Password,
		"connection_string": creds.ConnString,
		"engine":            creds.Engine,
	}, nil)
}

func (s *Server) vaultSysLeaseRenew(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		LeaseID   string `json:"lease_id"`
		Increment int    `json:"increment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.LeaseID) == "" {
		writeVaultErr(w, http.StatusBadRequest, "lease_id is required")
		return
	}
	leaseID := strings.TrimSpace(body.LeaseID)
	lease, err := s.Store.Q.GetDynamicLease(r.Context(), leaseID)
	if err != nil || lease.RevokedAt.Valid {
		writeVaultErr(w, http.StatusBadRequest, "lease not found or already revoked")
		return
	}
	prov, err := s.Store.Q.GetDynamicProvider(r.Context(), lease.ProviderID)
	if err != nil {
		writeVaultErr(w, http.StatusNotFound, "provider not found")
		return
	}
	if err := s.allowEnv(r, p, auth.PermSecretsRead, prov.ProjectID, prov.EnvironmentSlug); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}
	inc := body.Increment
	if inc <= 0 {
		inc = int(prov.DefaultTtlSeconds)
	}
	if inc > int(prov.MaxTtlSeconds) && prov.MaxTtlSeconds > 0 {
		inc = int(prov.MaxTtlSeconds)
	}
	newExpires := store.Now().Add(time.Duration(inc) * time.Second)
	if err := s.Store.Q.RenewDynamicLease(r.Context(), db.RenewDynamicLeaseParams{
		ID:        lease.ID,
		ExpiresAt: newExpires,
	}); err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeVaultStatus(w, http.StatusOK, lease.ID, inc, true, nil, nil)
}

func (s *Server) vaultSysLeaseRevoke(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		LeaseID string `json:"lease_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.LeaseID) == "" {
		writeVaultErr(w, http.StatusBadRequest, "lease_id is required")
		return
	}
	leaseID := strings.TrimSpace(body.LeaseID)
	lease, err := s.Store.Q.GetDynamicLease(r.Context(), leaseID)
	if err != nil {
		writeVaultErr(w, http.StatusNotFound, "lease not found")
		return
	}
	prov, err := s.Store.Q.GetDynamicProvider(r.Context(), lease.ProviderID)
	if err != nil {
		writeVaultErr(w, http.StatusNotFound, "provider not found")
		return
	}
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, prov.ProjectID, prov.EnvironmentSlug); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}
	if !lease.RevokedAt.Valid {
		if pv, err := s.projectVault(prov.ProjectID); err == nil {
			if configJSON, err := pv.Decrypt(prov.ConfigEncrypted, prov.ConfigNonce); err == nil {
				if driver, err := dynamic.GetDriver(prov.Engine); err == nil {
					_ = driver.RevokeLease(r.Context(), configJSON, lease.Username)
				}
			}
		}
		_ = s.Store.Q.RevokeDynamicLease(r.Context(), db.RevokeDynamicLeaseParams{
			ID:        lease.ID,
			RevokedAt: store.NullTime(store.Now()),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) vaultSysLeaseLookup(w http.ResponseWriter, r *http.Request, p principal) {
	var body struct {
		LeaseID string `json:"lease_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	leaseID := strings.TrimSpace(body.LeaseID)
	if leaseID == "" {
		leaseID = strings.TrimSpace(r.URL.Query().Get("lease_id"))
	}
	lease, err := s.Store.Q.GetDynamicLease(r.Context(), leaseID)
	if err != nil {
		writeVaultErr(w, http.StatusNotFound, "lease not found")
		return
	}
	prov, err := s.Store.Q.GetDynamicProvider(r.Context(), lease.ProviderID)
	if err != nil {
		writeVaultErr(w, http.StatusNotFound, "provider not found")
		return
	}
	if err := s.allowEnv(r, p, auth.PermSecretsRead, prov.ProjectID, prov.EnvironmentSlug); err != nil {
		writeVaultFromAPIError(w, err)
		return
	}
	ttl := int(time.Until(lease.ExpiresAt).Seconds())
	if ttl < 0 {
		ttl = 0
	}
	writeVaultOK(w, map[string]any{
		"id":           lease.ID,
		"issue_time":   lease.CreatedAt.UTC().Format(time.RFC3339Nano),
		"expire_time":  lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"last_renewal": nil,
		"renewable":    true,
		"ttl":          ttl,
	})
}

// ---- Transit Secrets Engine (/v1/transit/* — Encryption-as-a-Service) ----

func (s *Server) vaultTransitKeys(w http.ResponseWriter, r *http.Request, keyName string) {
	keyName = strings.Trim(keyName, "/")
	if keyName == "" {
		writeVaultOK(w, map[string]any{"keys": []string{"default"}})
		return
	}
	writeVaultOK(w, map[string]any{
		"name":                   keyName,
		"type":                   "aes256-gcm96",
		"latest_version":         1,
		"min_decryption_version": 1,
		"min_encryption_version": 0,
		"deletion_allowed":       false,
		"derived":                true,
		"exportable":             false,
		"supports_encryption":    true,
		"supports_decryption":    true,
		"supports_signing":       false,
	})
}

func (s *Server) vaultTransitEncrypt(w http.ResponseWriter, r *http.Request, p principal, keyName string) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !auth.Has(p.Perms, auth.PermSecretsRead) {
		writeVaultErr(w, http.StatusForbidden, "permission denied")
		return
	}
	keyName = strings.Trim(keyName, "/")
	if keyName == "" {
		writeVaultErr(w, http.StatusBadRequest, "key name is required")
		return
	}

	var body struct {
		Plaintext string `json:"plaintext"`
		Batch     []struct {
			Plaintext string `json:"plaintext"`
		} `json:"batch_input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeVaultErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	tv, err := s.Vault.DeriveSubVault("transit", keyName)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	encryptOne := func(b64Plain string) (string, error) {
		raw, err := base64.StdEncoding.DecodeString(b64Plain)
		if err != nil {
			return "", fmt.Errorf("plaintext must be base64-encoded")
		}
		ct, nonce, err := tv.Encrypt(raw)
		if err != nil {
			return "", err
		}
		combined := append(nonce, ct...)
		return "vault:v1:" + base64.StdEncoding.EncodeToString(combined), nil
	}

	if len(body.Batch) > 0 {
		results := make([]map[string]any, 0, len(body.Batch))
		for _, item := range body.Batch {
			ct, eErr := encryptOne(item.Plaintext)
			if eErr != nil {
				results = append(results, map[string]any{"error": eErr.Error()})
			} else {
				results = append(results, map[string]any{"ciphertext": ct, "key_version": 1})
			}
		}
		writeVaultOK(w, map[string]any{"batch_results": results})
		return
	}

	ct, err := encryptOne(body.Plaintext)
	if err != nil {
		writeVaultErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeVaultOK(w, map[string]any{
		"ciphertext":  ct,
		"key_version": 1,
	})
}

func (s *Server) vaultTransitDecrypt(w http.ResponseWriter, r *http.Request, p principal, keyName string) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeVaultErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !auth.Has(p.Perms, auth.PermSecretsRead) {
		writeVaultErr(w, http.StatusForbidden, "permission denied")
		return
	}
	keyName = strings.Trim(keyName, "/")
	if keyName == "" {
		writeVaultErr(w, http.StatusBadRequest, "key name is required")
		return
	}

	var body struct {
		Ciphertext string `json:"ciphertext"`
		Batch      []struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"batch_input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeVaultErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	tv, err := s.Vault.DeriveSubVault("transit", keyName)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	decryptOne := func(vaultCT string) (string, error) {
		b64Part, ok := strings.CutPrefix(strings.TrimSpace(vaultCT), "vault:v1:")
		if !ok {
			return "", fmt.Errorf("invalid ciphertext format (expected vault:v1:...)")
		}
		combined, err := base64.StdEncoding.DecodeString(b64Part)
		if err != nil || len(combined) < 12 {
			return "", fmt.Errorf("invalid ciphertext payload")
		}
		nonce := combined[:12]
		ct := combined[12:]
		plain, err := tv.Decrypt(ct, nonce)
		if err != nil {
			return "", fmt.Errorf("ciphertext authentication failed")
		}
		return base64.StdEncoding.EncodeToString(plain), nil
	}

	if len(body.Batch) > 0 {
		results := make([]map[string]any, 0, len(body.Batch))
		for _, item := range body.Batch {
			pt, dErr := decryptOne(item.Ciphertext)
			if dErr != nil {
				results = append(results, map[string]any{"error": dErr.Error()})
			} else {
				results = append(results, map[string]any{"plaintext": pt})
			}
		}
		writeVaultOK(w, map[string]any{"batch_results": results})
		return
	}

	pt, err := decryptOne(body.Ciphertext)
	if err != nil {
		writeVaultErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeVaultOK(w, map[string]any{
		"plaintext": pt,
	})
}

func (s *Server) vaultTransitHMAC(w http.ResponseWriter, r *http.Request, p principal, rawPath string) {
	if !auth.Has(p.Perms, auth.PermSecretsRead) {
		writeVaultErr(w, http.StatusForbidden, "permission denied")
		return
	}
	parts := strings.SplitN(strings.Trim(rawPath, "/"), "/", 2)
	keyName := parts[0]
	alg := "sha2-256"
	if len(parts) == 2 && parts[1] != "" {
		alg = parts[1]
	}

	var body struct {
		Input     string `json:"input"`
		Algorithm string `json:"algorithm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeVaultErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Algorithm != "" {
		alg = body.Algorithm
	}
	rawInput, err := base64.StdEncoding.DecodeString(body.Input)
	if err != nil {
		writeVaultErr(w, http.StatusBadRequest, "input must be base64-encoded")
		return
	}

	// Derive a deterministic HMAC key from the master vault
	macKey, err := s.Vault.DeriveHMACKey(keyName)
	if err != nil {
		writeVaultErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var h func() hash.Hash = sha256.New
	if strings.Contains(alg, "512") {
		h = sha512.New
	}
	mac := hmac.New(h, macKey)
	mac.Write(rawInput)
	sum := mac.Sum(nil)

	writeVaultOK(w, map[string]any{
		"hmac": "vault:v1:" + base64.StdEncoding.EncodeToString(sum),
	})
}

func (s *Server) vaultTransitHash(w http.ResponseWriter, r *http.Request, alg string) {
	var body struct {
		Input     string `json:"input"`
		Algorithm string `json:"algorithm"`
		Format    string `json:"format"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Algorithm != "" {
		alg = body.Algorithm
	}
	rawInput, err := base64.StdEncoding.DecodeString(body.Input)
	if err != nil {
		writeVaultErr(w, http.StatusBadRequest, "input must be base64-encoded")
		return
	}
	var sum []byte
	if strings.Contains(alg, "512") {
		s512 := sha512.Sum512(rawInput)
		sum = s512[:]
	} else {
		s256 := sha256.Sum256(rawInput)
		sum = s256[:]
	}
	out := base64.StdEncoding.EncodeToString(sum)
	if strings.EqualFold(body.Format, "hex") {
		out = hex.EncodeToString(sum)
	}
	writeVaultOK(w, map[string]any{"sum": out})
}

func (s *Server) vaultTransitRandom(w http.ResponseWriter, r *http.Request, urlBytes string) {
	numBytes := 32
	if urlBytes != "" {
		if n, err := strconv.Atoi(strings.Trim(urlBytes, "/")); err == nil && n > 0 && n <= 4096 {
			numBytes = n
		}
	}
	var body struct {
		Bytes  int    `json:"bytes"`
		Format string `json:"format"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Bytes > 0 && body.Bytes <= 4096 {
		numBytes = body.Bytes
	}
	buf := make([]byte, numBytes)
	_, _ = rand.Read(buf)
	out := base64.StdEncoding.EncodeToString(buf)
	if strings.EqualFold(body.Format, "hex") {
		out = hex.EncodeToString(buf)
	}
	writeVaultOK(w, map[string]any{"random_bytes": out})
}
