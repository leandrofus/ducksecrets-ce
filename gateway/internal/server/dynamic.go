package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/dynamic"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// openapi:schema DynamicProvider
// type: object
// required: [id, project_id, environment_slug, name, engine, default_ttl_seconds, max_ttl_seconds, role_template, enforced_port, created_at, updated_at]
// properties:
//   id: { type: string, format: uuid }
//   project_id: { type: string, format: uuid }
//   environment_slug: { type: string }
//   name: { type: string }
//   engine: { type: string }
//   default_ttl_seconds: { type: integer }
//   max_ttl_seconds: { type: integer }
//   role_template: { type: string }
//   enforced_port: { type: integer }
//   site_id: { type: string, format: uuid, nullable: true }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }

type dynamicProviderDTO struct {
	ID                string    `json:"id"`
	ProjectID         string    `json:"project_id"`
	EnvironmentSlug   string    `json:"environment_slug"`
	Name              string    `json:"name"`
	Engine            string    `json:"engine"`
	DefaultTTLSeconds int32     `json:"default_ttl_seconds"`
	MaxTTLSeconds     int32     `json:"max_ttl_seconds"`
	RoleTemplate      string    `json:"role_template"`
	EnforcedPort      int32     `json:"enforced_port"`
	SiteID            *string   `json:"site_id,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// openapi:schema CreateDynamicProviderRequest
// type: object
// required: [name, engine, config]
// additionalProperties: false
// properties:
//   name: { type: string }
//   engine: { type: string }
//   config: { type: string }
//   default_ttl_seconds: { type: integer }
//   max_ttl_seconds: { type: integer }
//   role_template: { type: string }
//   enforced_port: { type: integer }
//   site_id: { type: string, format: uuid, nullable: true }

type createDynamicProviderRequest struct {
	Name              string `json:"name"`
	Engine            string `json:"engine"`
	Config            any    `json:"config"`
	DefaultTTLSeconds int    `json:"default_ttl_seconds"`
	MaxTTLSeconds     int    `json:"max_ttl_seconds"`
	RoleTemplate      string `json:"role_template"`
	EnforcedPort      int    `json:"enforced_port,omitempty"`
	SiteID            string `json:"site_id,omitempty"`
}

// openapi:schema DynamicLease
// type: object
// required: [id, provider_id, username, issued_to, expires_at, created_at]
// properties:
//   id: { type: string }
//   provider_id: { type: string, format: uuid }
//   username: { type: string }
//   issued_to: { type: string }
//   expires_at: { type: string, format: date-time }
//   revoked_at: { type: string, format: date-time, nullable: true }
//   created_at: { type: string, format: date-time }

type dynamicLeaseDTO struct {
	ID         string     `json:"id"`
	ProviderID string     `json:"provider_id"`
	Username   string     `json:"username"`
	IssuedTo   string     `json:"issued_to"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// openapi:schema IssuedLease
// type: object
// required: [lease_id, username, password, expires_at, engine]
// properties:
//   lease_id: { type: string }
//   username: { type: string }
//   password: { type: string }
//   connection_string: { type: string }
//   expires_at: { type: string, format: date-time }
//   engine: { type: string }
//   database: { type: string }
//   enforced_port: { type: integer }

type issuedLeaseDTO struct {
	LeaseID      string    `json:"lease_id"`
	Username     string    `json:"username"`
	Password     string    `json:"password"`
	ConnString   string    `json:"connection_string,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Engine       string    `json:"engine"`
	Database     string    `json:"database,omitempty"`
	EnforcedPort int32     `json:"enforced_port,omitempty"`
}

// openapi:schema RequestLeaseRequest
// type: object
// additionalProperties: false
// properties:
//   ttl_seconds: { type: integer }

type requestLeaseRequest struct {
	TTLSeconds int `json:"ttl_seconds"`
}

// openapi:schema TestProviderResponse
// type: object
// required: [success, message]
// properties:
//   success: { type: boolean }
//   message: { type: string }

type testProviderResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func toProviderDTO(p db.DynamicProvider) dynamicProviderDTO {
	var siteID *string
	if p.SiteID.Valid {
		s := p.SiteID.String
		siteID = &s
	}

	return dynamicProviderDTO{
		ID:                p.ID,
		ProjectID:         p.ProjectID,
		EnvironmentSlug:   p.EnvironmentSlug,
		Name:              p.Name,
		Engine:            p.Engine,
		DefaultTTLSeconds: p.DefaultTtlSeconds,
		MaxTTLSeconds:     p.MaxTtlSeconds,
		RoleTemplate:      p.RoleTemplate,
		EnforcedPort:      p.EnforcedPort,
		SiteID:            siteID,
		CreatedAt:         p.CreatedAt.UTC(),
		UpdatedAt:         p.UpdatedAt.UTC(),
	}
}

// openapi:operation
// summary: List dynamic secret providers
// description: Returns all dynamic credential providers configured for a project environment.
// responses:
//   '200': { description: Providers list, schema: { type: array, items: { $ref: '#/components/schemas/DynamicProvider' } } }

func (s *Server) listDynamicProviders(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}

	providers, err := s.Store.Q.ListDynamicProviders(r.Context(), db.ListDynamicProvidersParams{
		ProjectID:       projectID,
		EnvironmentSlug: envSlug,
	})
	if err != nil {
		return fmt.Errorf("listing dynamic providers: %w", err)
	}

	res := make([]dynamicProviderDTO, len(providers))
	for i, pr := range providers {
		res[i] = toProviderDTO(pr)
	}
	return ok(w, res)
}

// openapi:operation
// summary: Create dynamic secret provider
// description: Configures a new target engine (Postgres, MySQL, Redis, PAM) for on-demand dynamic credentials.
// requestBody:
//   schema: { $ref: '#/components/schemas/CreateDynamicProviderRequest' }
// responses:
//   '201': { description: Provider created, schema: { $ref: '#/components/schemas/DynamicProvider' } }

func (s *Server) createDynamicProvider(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}

	var req createDynamicProviderRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return badRequest("provider name is required")
	}

	var configBytes []byte
	switch v := req.Config.(type) {
	case string:
		configBytes = []byte(v)
	case map[string]any:
		configBytes, _ = json.Marshal(v)
	default:
		configBytes, _ = json.Marshal(v)
	}

	driver, err := dynamic.GetDriver(req.Engine)
	if err != nil {
		return badRequest("%v", err)
	}
	if err := driver.ValidateConfig(configBytes); err != nil {
		return badRequest("invalid engine configuration: %v", err)
	}
	if err := s.allowDynamicExecution(req.Engine, configBytes, &p); err != nil {
		return err
	}

	defTTL := int32(req.DefaultTTLSeconds)
	if defTTL <= 0 {
		defTTL = 3600
	}
	maxTTL := int32(req.MaxTTLSeconds)
	if maxTTL <= 0 {
		maxTTL = 86400
	}
	if defTTL > maxTTL {
		maxTTL = defTTL
	}

	// Encrypt config using project sub-vault
	pv, err := s.projectVault(projectID)
	if err != nil {
		return fmt.Errorf("deriving project vault: %w", err)
	}
	cfgEnc, cfgNonce, err := pv.Encrypt(configBytes)
	if err != nil {
		return fmt.Errorf("encrypting config: %w", err)
	}

	providerID := uuid.NewString()
	now := store.Now()

	siteID := store.NullString(strings.TrimSpace(req.SiteID))
	if siteID.Valid {
		site, err := s.Store.Q.GetSite(r.Context(), siteID.String)
		if err != nil {
			return fromStore(err, "site")
		}
		if site.ProjectID != projectID {
			return notFound("site")
		}
	}

	err = s.Store.Q.CreateDynamicProvider(r.Context(), db.CreateDynamicProviderParams{
		ID:                providerID,
		ProjectID:         projectID,
		EnvironmentSlug:   envSlug,
		Name:              name,
		Engine:            req.Engine,
		ConfigEncrypted:   cfgEnc,
		ConfigNonce:       cfgNonce,
		DefaultTtlSeconds: defTTL,
		MaxTtlSeconds:     maxTTL,
		RoleTemplate:      req.RoleTemplate,
		EnforcedPort:      int32(req.EnforcedPort),
		SiteID:            siteID,
		Now:               now,
	})
	if err != nil {
		return fromStore(err, "dynamic provider")
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "dynamic.provider_create", "dynamic_provider", providerID, map[string]any{"name": name, "engine": req.Engine})

	var resSiteID *string
	if siteID.Valid {
		s := siteID.String
		resSiteID = &s
	}

	return created(w, dynamicProviderDTO{
		ID:                providerID,
		ProjectID:         projectID,
		EnvironmentSlug:   envSlug,
		Name:              name,
		Engine:            req.Engine,
		DefaultTTLSeconds: defTTL,
		MaxTTLSeconds:     maxTTL,
		RoleTemplate:      req.RoleTemplate,
		EnforcedPort:      int32(req.EnforcedPort),
		SiteID:            resSiteID,
		CreatedAt:         now.UTC(),
		UpdatedAt:         now.UTC(),
	})
}

func (s *Server) getScopedDynamicProvider(ctx context.Context, projectID, envSlug, providerID string) (db.DynamicProvider, error) {
	prov, err := s.Store.Q.GetDynamicProvider(ctx, providerID)
	if err != nil {
		return db.DynamicProvider{}, fromStore(err, "dynamic provider")
	}
	if prov.ProjectID != projectID || prov.EnvironmentSlug != envSlug {
		return db.DynamicProvider{}, notFound("dynamic provider")
	}
	return prov, nil
}

// openapi:operation
// summary: Get dynamic secret provider
// description: Retrieves dynamic provider details.
// responses:
//   '200': { description: Provider details, schema: { $ref: '#/components/schemas/DynamicProvider' } }

func (s *Server) getDynamicProvider(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	providerID := r.PathValue("provider_id")
	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}

	prov, err := s.getScopedDynamicProvider(r.Context(), projectID, envSlug, providerID)
	if err != nil {
		return err
	}
	return ok(w, toProviderDTO(prov))
}

// openapi:operation
// summary: Delete dynamic secret provider
// description: Deletes dynamic credential provider and revokes all active leases.
// responses:
//   '204': { description: Provider deleted }

func (s *Server) deleteDynamicProvider(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	providerID := r.PathValue("provider_id")
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}

	if _, err := s.getScopedDynamicProvider(r.Context(), projectID, envSlug, providerID); err != nil {
		return err
	}

	rows, err := s.Store.Q.DeleteDynamicProvider(r.Context(), providerID)
	if err != nil {
		return fromStore(err, "dynamic provider")
	}
	if rows == 0 {
		return notFound("dynamic provider")
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "dynamic.provider_delete", "dynamic_provider", providerID, nil)
	return noContent(w)
}

func (s *Server) allowDynamicExecution(engine string, configJSON []byte, p *principal) error {
	if !strings.EqualFold(engine, "pam") {
		return nil
	}
	var cfg dynamic.PAMConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return badRequest("parsing PAM config: %v", err)
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "local"
	}
	if mode == "simulated" {
		return nil
	}
	if !s.AllowScripts {
		return forbidden("PAM %q mode is disabled on this server", mode)
	}
	if p != nil && !auth.Has(p.Perms, auth.PermSystemManage) {
		return forbidden("configuring PAM %q mode requires %s", mode, auth.PermSystemManage)
	}
	return nil
}

// openapi:operation
// summary: Test dynamic provider connection
// description: Tests connectivity and permissions against the target database or PAM host.
// responses:
//   '200': { description: Test result, schema: { $ref: '#/components/schemas/TestProviderResponse' } }

func (s *Server) testDynamicProvider(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	providerID := r.PathValue("provider_id")
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}

	prov, err := s.getScopedDynamicProvider(r.Context(), projectID, envSlug, providerID)
	if err != nil {
		return err
	}

	pv, err := s.projectVault(projectID)
	if err != nil {
		return fmt.Errorf("deriving project vault: %w", err)
	}
	configJSON, err := pv.Decrypt(prov.ConfigEncrypted, prov.ConfigNonce)
	if err != nil {
		return fmt.Errorf("decrypting provider config: %w", err)
	}

	driver, err := dynamic.GetDriver(prov.Engine)
	if err != nil {
		return badRequest("%v", err)
	}
	if err := s.allowDynamicExecution(prov.Engine, configJSON, nil); err != nil {
		return err
	}

	if err := driver.Test(r.Context(), configJSON); err != nil {
		return ok(w, testProviderResponse{Success: false, Message: err.Error()})
	}

	return ok(w, testProviderResponse{Success: true, Message: "Connection and credentials verified successfully."})
}

// openapi:operation
// summary: Issue dynamic credential lease
// description: Generates on-demand short-lived credentials with automated expiration.
// requestBody:
//   schema: { $ref: '#/components/schemas/RequestLeaseRequest' }
// responses:
//   '201': { description: Lease issued, schema: { $ref: '#/components/schemas/IssuedLease' } }

func (s *Server) issueDynamicLease(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	providerID := r.PathValue("provider_id")
	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}

	prov, err := s.getScopedDynamicProvider(r.Context(), projectID, envSlug, providerID)
	if err != nil {
		return err
	}

	var req requestLeaseRequest
	_ = decode(r, &req)

	ttlSec := req.TTLSeconds
	if ttlSec <= 0 {
		ttlSec = int(prov.DefaultTtlSeconds)
	}
	if ttlSec > int(prov.MaxTtlSeconds) {
		ttlSec = int(prov.MaxTtlSeconds)
	}
	ttl := time.Duration(ttlSec) * time.Second

	pv, err := s.projectVault(projectID)
	if err != nil {
		return fmt.Errorf("deriving project vault: %w", err)
	}
	configJSON, err := pv.Decrypt(prov.ConfigEncrypted, prov.ConfigNonce)
	if err != nil {
		return fmt.Errorf("decrypting provider config: %w", err)
	}

	driver, err := dynamic.GetDriver(prov.Engine)
	if err != nil {
		return badRequest("%v", err)
	}
	if err := s.allowDynamicExecution(prov.Engine, configJSON, nil); err != nil {
		return err
	}
	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}

	username, password, err := dynamic.GenerateRandomCredentials("duck_d_")
	if err != nil {
		return fmt.Errorf("generating credentials: %w", err)
	}

	creds, err := driver.IssueLease(r.Context(), configJSON, prov.RoleTemplate, username, password, ttl)
	if err != nil {
		return fmt.Errorf("issuing dynamic lease on %s: %w", prov.Engine, err)
	}

	credsJSON, _ := json.Marshal(creds)
	credsEnc, credsNonce, err := pv.Encrypt(credsJSON)
	if err != nil {
		return fmt.Errorf("encrypting lease credentials: %w", err)
	}

	leaseID := "ls_" + uuid.NewString()[:12]
	now := store.Now()
	expiresAt := now.Add(ttl)

	issuedTo := p.User.Username
	if p.ServiceToken != nil {
		issuedTo = "token:" + p.ServiceToken.Name
	}

	err = s.Store.Q.CreateDynamicLease(r.Context(), db.CreateDynamicLeaseParams{
		ID:                   leaseID,
		ProviderID:           providerID,
		Username:             username,
		CredentialsEncrypted: credsEnc,
		CredentialsNonce:     credsNonce,
		IssuedTo:             issuedTo,
		ExpiresAt:            expiresAt,
		Now:                  now,
	})
	if err != nil {
		// Rollback lease on target engine
		_ = driver.RevokeLease(context.Background(), configJSON, username)
		return fmt.Errorf("recording lease in database: %w", err)
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "dynamic.lease_issue", "dynamic_lease", leaseID, map[string]any{"username": username, "ttl_seconds": ttlSec})

	var rawCfg struct {
		Database string `json:"database"`
	}
	_ = json.Unmarshal(configJSON, &rawCfg)

	return created(w, issuedLeaseDTO{
		LeaseID:      leaseID,
		Username:     creds.Username,
		Password:     creds.Password,
		ConnString:   creds.ConnString,
		ExpiresAt:    expiresAt.UTC(),
		Engine:       creds.Engine,
		Database:     rawCfg.Database,
		EnforcedPort: prov.EnforcedPort,
	})
}

// openapi:operation
// summary: List active dynamic leases
// description: Returns active credential leases issued under this provider.
// responses:
//   '200': { description: Active leases, schema: { type: array, items: { $ref: '#/components/schemas/DynamicLease' } } }

func (s *Server) listDynamicLeases(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	providerID := r.PathValue("provider_id")
	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}

	if _, err := s.getScopedDynamicProvider(r.Context(), projectID, envSlug, providerID); err != nil {
		return err
	}

	leases, err := s.Store.Q.ListActiveLeasesByProvider(r.Context(), providerID)
	if err != nil {
		return fmt.Errorf("listing active leases: %w", err)
	}

	res := make([]dynamicLeaseDTO, len(leases))
	for i, l := range leases {
		dto := dynamicLeaseDTO{
			ID:         l.ID,
			ProviderID: l.ProviderID,
			Username:   l.Username,
			IssuedTo:   l.IssuedTo,
			ExpiresAt:  l.ExpiresAt.UTC(),
			CreatedAt:  l.CreatedAt.UTC(),
		}
		if l.RevokedAt.Valid {
			t := l.RevokedAt.Time.UTC()
			dto.RevokedAt = &t
		}
		res[i] = dto
	}
	return ok(w, res)
}

// openapi:operation
// summary: Revoke dynamic lease immediately
// description: Immediately drops and disables the temporary credentials on the target engine.
// responses:
//   '204': { description: Lease revoked }

func (s *Server) revokeDynamicLease(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	providerID := r.PathValue("provider_id")
	leaseID := r.PathValue("lease_id")
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}

	prov, err := s.getScopedDynamicProvider(r.Context(), projectID, envSlug, providerID)
	if err != nil {
		return err
	}

	lease, err := s.Store.Q.GetDynamicLease(r.Context(), leaseID)
	if err != nil {
		return fromStore(err, "dynamic lease")
	}
	if lease.ProviderID != prov.ID {
		return notFound("dynamic lease")
	}
	if lease.RevokedAt.Valid {
		return noContent(w)
	}

	pv, err := s.projectVault(projectID)
	if err != nil {
		return fmt.Errorf("deriving project vault: %w", err)
	}
	configJSON, err := pv.Decrypt(prov.ConfigEncrypted, prov.ConfigNonce)
	if err == nil {
		if err := s.allowDynamicExecution(prov.Engine, configJSON, nil); err == nil {
			if driver, err := dynamic.GetDriver(prov.Engine); err == nil {
				_ = driver.RevokeLease(r.Context(), configJSON, lease.Username)
			}
		}
	}

	now := store.Now()
	_ = s.Store.Q.RevokeDynamicLease(r.Context(), db.RevokeDynamicLeaseParams{
		ID:        leaseID,
		RevokedAt: store.NullTime(now),
	})

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "dynamic.lease_revoke", "dynamic_lease", leaseID, map[string]any{"username": lease.Username})
	return noContent(w)
}

// ReapExpiredLeases revokes all leases past their expiration. Called by the background ticker.
func (s *Server) ReapExpiredLeases(ctx context.Context) {
	now := store.Now()
	expired, err := s.Store.Q.ListExpiredUnrevokedLeases(ctx, now)
	if err != nil {
		return
	}
	for _, l := range expired {
		prov, err := s.Store.Q.GetDynamicProvider(ctx, l.ProviderID)
		if err != nil {
			continue
		}
		pv, err := s.projectVault(prov.ProjectID)
		if err != nil {
			continue
		}
		configJSON, err := pv.Decrypt(prov.ConfigEncrypted, prov.ConfigNonce)
		if err == nil {
			if err := s.allowDynamicExecution(prov.Engine, configJSON, nil); err == nil {
				if driver, err := dynamic.GetDriver(prov.Engine); err == nil {
					_ = driver.RevokeLease(ctx, configJSON, l.Username)
				}
			}
		}
		_ = s.Store.Q.RevokeDynamicLease(ctx, db.RevokeDynamicLeaseParams{
			ID:        l.ID,
			RevokedAt: store.NullTime(now),
		})
	}
}

// openapi:operation
// summary: Managed TCP tunnel over WebSocket
// description: Bridges local client TCP connection to target private database/server over WebSocket.
// responses:
//   '101': { description: Switching to WebSocket tunnel }

func (s *Server) tunnelDynamicConnection(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	providerID := r.PathValue("provider_id")
	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}

	leaseID := r.URL.Query().Get("lease_id")
	if leaseID == "" {
		return badRequest("lease_id query parameter is required")
	}

	lease, err := s.Store.Q.GetDynamicLease(r.Context(), leaseID)
	if err != nil {
		return fromStore(err, "dynamic lease")
	}
	if lease.RevokedAt.Valid {
		return badRequest("dynamic lease has been revoked")
	}
	if lease.ExpiresAt.Before(time.Now()) {
		return badRequest("dynamic lease has expired")
	}

	prov, err := s.getScopedDynamicProvider(r.Context(), projectID, envSlug, providerID)
	if err != nil {
		return err
	}
	if lease.ProviderID != prov.ID {
		return notFound("dynamic lease")
	}

	pv, err := s.projectVault(projectID)
	if err != nil {
		return fmt.Errorf("deriving project vault: %w", err)
	}
	configJSON, err := pv.Decrypt(prov.ConfigEncrypted, prov.ConfigNonce)
	if err != nil {
		return fmt.Errorf("decrypting provider config: %w", err)
	}
	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}

	targetHost, targetPort := extractDynamicTargetHostPort(prov.Engine, configJSON)

	var targetConn net.Conn
	if prov.SiteID.Valid && prov.SiteID.String != "" {
		if s.Sites == nil {
			return fmt.Errorf("sites manager is not initialized")
		}
		var err error
		targetConn, err = s.Sites.Dial(r.Context(), prov.SiteID.String, targetHost, targetPort)
		if err != nil {
			return fmt.Errorf("reverse tunnel dial failed via site %s: %w", prov.SiteID.String, err)
		}
	} else {
		targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
		dialCtx, dialCancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer dialCancel()

		var err error
		targetConn, err = (&net.Dialer{}).DialContext(dialCtx, "tcp", targetAddr)
		if err != nil {
			return fmt.Errorf("dialing target %s (%s): %w", prov.Engine, targetAddr, err)
		}
	}
	defer targetConn.Close()

	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil // Accept already answered
	}
	defer ws.Close(websocket.StatusNormalClosure, "tunnel closed")

	netConn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
	defer netConn.Close()

	errc := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(targetConn, netConn)
		errc <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(netConn, targetConn)
		errc <- copyErr
	}()

	select {
	case <-r.Context().Done():
	case <-errc:
	}

	return nil
}

func extractDynamicTargetHostPort(engine string, configJSON []byte) (string, int) {
	defaultPort := 5432
	switch engine {
	case "postgres":
		defaultPort = 5432
	case "mysql":
		defaultPort = 3306
	case "redis":
		defaultPort = 6379
	case "pam":
		defaultPort = 22
	}

	var cfg struct {
		Host          string `json:"host"`
		Port          int    `json:"port"`
		ConnectionURL string `json:"connection_url"`
		DSN           string `json:"dsn"`
		Address       string `json:"address"`
	}
	_ = json.Unmarshal(configJSON, &cfg)

	host := cfg.Host
	port := cfg.Port

	parseAddr := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		if h, pStr, err := net.SplitHostPort(addr); err == nil {
			if h != "" {
				host = h
			}
			if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
				port = p
			}
			return
		}
		if host == "" {
			host = strings.Trim(addr, "[]")
		}
	}

	switch engine {
	case "postgres":
		if cfg.ConnectionURL != "" {
			if u, err := url.Parse(cfg.ConnectionURL); err == nil {
				if h := u.Hostname(); h != "" {
					host = h
				}
				if pStr := u.Port(); pStr != "" {
					if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
						port = p
					}
				}
			}
		}
	case "mysql":
		if cfg.DSN != "" {
			if idx := strings.Index(cfg.DSN, "@tcp("); idx != -1 {
				rest := cfg.DSN[idx+len("@tcp("):]
				if end := strings.Index(rest, ")"); end != -1 {
					parseAddr(rest[:end])
				}
			}
		}
	case "redis":
		parseAddr(cfg.Address)
	}

	if host == "" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		port = defaultPort
	}
	return host, port
}
