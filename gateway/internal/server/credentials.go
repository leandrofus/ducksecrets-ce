package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// openapi:schema CredentialPayload
// type: object
// properties:
//   private_key: { type: string }
//   public_key: { type: string }
//   passphrase: { type: string }
//   key_type: { type: string }
//   fingerprint: { type: string }
//   host: { type: string }
//   port: { type: integer }
//   username: { type: string }
//   certificate: { type: string }
//   ca_chain: { type: string }
//   subject: { type: string }
//   issuer: { type: string }
//   provider: { type: string }
//   client_id: { type: string }
//   client_secret: { type: string }
//   api_key: { type: string }
//   token_url: { type: string }
//   endpoint_url: { type: string }
//   scopes: { type: string }
//   password: { type: string }
//   url: { type: string }
//   database: { type: string }
//   notes: { type: string }

type credentialPayload struct {
	// SSH Keys & TLS Certificates
	PrivateKey  string `json:"private_key,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	Passphrase  string `json:"passphrase,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Username    string `json:"username,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	CAChain     string `json:"ca_chain,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Issuer      string `json:"issuer,omitempty"`

	// API Keys & OAuth
	Provider     string `json:"provider,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	APIKey       string `json:"api_key,omitempty"`
	TokenURL     string `json:"token_url,omitempty"`
	EndpointURL  string `json:"endpoint_url,omitempty"`
	Scopes       string `json:"scopes,omitempty"`

	// Login / DB / Extra
	Password string `json:"password,omitempty"`
	URL      string `json:"url,omitempty"`
	Database string `json:"database,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// openapi:schema Credential
// type: object
// required: [id, environment_slug, name, kind, description, summary, created_by, created_at, updated_at]
// properties:
//   id: { type: string, format: uuid }
//   project_id: { type: string, format: uuid, nullable: true }
//   project_name: { type: string }
//   project_slug: { type: string }
//   environment_slug: { type: string }
//   name: { type: string }
//   kind: { type: string, enum: [ssh_key, tls_cert, oauth_api, login] }
//   description: { type: string }
//   summary: { type: string }
//   payload: { $ref: '#/components/schemas/CredentialPayload' }
//   expires_at: { type: string, format: date-time, nullable: true }
//   created_by: { type: string }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }

type credentialDTO struct {
	ID              string             `json:"id"`
	ProjectID       *string            `json:"project_id,omitempty"`
	ProjectName     string             `json:"project_name,omitempty"`
	ProjectSlug     string             `json:"project_slug,omitempty"`
	EnvironmentSlug string             `json:"environment_slug"`
	Name            string             `json:"name"`
	Kind            string             `json:"kind"`
	Description     string             `json:"description"`
	Summary         string             `json:"summary"`
	Payload         *credentialPayload `json:"payload,omitempty"`
	ExpiresAt       *time.Time         `json:"expires_at,omitempty"`
	CreatedBy       string             `json:"created_by"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}

// openapi:schema CredentialList
// type: object
// required: [items, total]
// properties:
//   items: { type: array, items: { $ref: '#/components/schemas/Credential' } }
//   total: { type: integer }

type credentialListDTO struct {
	Items []credentialDTO `json:"items"`
	Total int             `json:"total"`
}

// openapi:schema CreateCredentialRequest
// type: object
// required: [name, kind, payload]
// additionalProperties: false
// properties:
//   project_id: { type: string, nullable: true }
//   environment_slug: { type: string }
//   name: { type: string, minLength: 1, maxLength: 160 }
//   kind: { type: string, enum: [ssh_key, tls_cert, oauth_api, login] }
//   description: { type: string, maxLength: 500 }
//   expires_at: { type: string, format: date-time, nullable: true }
//   payload: { $ref: '#/components/schemas/CredentialPayload' }

type createCredentialRequest struct {
	ProjectID       string            `json:"project_id,omitempty"`
	EnvironmentSlug string            `json:"environment_slug,omitempty"`
	Name            string            `json:"name"`
	Kind            string            `json:"kind"`
	Description     string            `json:"description,omitempty"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
	Payload         credentialPayload `json:"payload"`
}

// openapi:schema UpdateCredentialRequest
// type: object
// additionalProperties: false
// properties:
//   project_id: { type: string, nullable: true }
//   environment_slug: { type: string }
//   name: { type: string, minLength: 1, maxLength: 160 }
//   kind: { type: string, enum: [ssh_key, tls_cert, oauth_api, login] }
//   description: { type: string, maxLength: 500 }
//   expires_at: { type: string, format: date-time, nullable: true }
//   payload: { $ref: '#/components/schemas/CredentialPayload' }

type updateCredentialRequest struct {
	ProjectID       opt[string]            `json:"project_id"`
	EnvironmentSlug opt[string]            `json:"environment_slug"`
	Name            opt[string]            `json:"name"`
	Kind            opt[string]            `json:"kind"`
	Description     opt[string]            `json:"description"`
	ExpiresAt       opt[time.Time]         `json:"expires_at"`
	Payload         opt[credentialPayload] `json:"payload"`
}

// openapi:schema SyncCredentialEnvRequest
// type: object
// required: [project_id, environment_slug]
// additionalProperties: false
// properties:
//   project_id: { type: string }
//   environment_slug: { type: string }
//   prefix: { type: string }
//   path: { type: string }
//   overwrite: { type: boolean }

type syncCredentialEnvRequest struct {
	ProjectID       string `json:"project_id"`
	EnvironmentSlug string `json:"environment_slug"`
	Prefix          string `json:"prefix,omitempty"`
	Path            string `json:"path,omitempty"`
	Overwrite       bool   `json:"overwrite"`
}

// openapi:schema SyncCredentialEnvResponse
// type: object
// required: [created, updated, keys]
// properties:
//   created: { type: integer }
//   updated: { type: integer }
//   keys: { type: array, items: { type: string } }

type syncCredentialEnvResponse struct {
	Created int      `json:"created"`
	Updated int      `json:"updated"`
	Keys    []string `json:"keys"`
}

// openapi:schema GenerateSSHKeyRequest
// type: object
// additionalProperties: false
// properties:
//   algorithm: { type: string, enum: [ed25519, rsa4096, ecdsa256] }
//   comment: { type: string }

type generateSSHKeyRequest struct {
	Algorithm string `json:"algorithm,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

// openapi:schema GenerateSSHKeyResponse
// type: object
// required: [private_key, public_key, fingerprint, key_type]
// properties:
//   private_key: { type: string }
//   public_key: { type: string }
//   fingerprint: { type: string }
//   key_type: { type: string }

type generateSSHKeyResponse struct {
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"key_type"`
}

func (s *Server) credentialVault(projectID string) (*crypto.Vault, error) {
	if s.Vault == nil {
		return nil, errors.New("crypto vault not initialized")
	}
	if strings.TrimSpace(projectID) != "" {
		return s.Vault.DeriveSubVault("project", strings.TrimSpace(projectID))
	}
	return s.Vault.DeriveSubVault("credentials", "global")
}

func validCredentialKind(kind string) bool {
	switch kind {
	case "ssh_key", "tls_cert", "oauth_api", "login":
		return true
	default:
		return false
	}
}

func enrichAndSummarizeCredential(kind string, pay *credentialPayload, currentExpires *time.Time) (string, *time.Time) {
	expires := currentExpires
	switch kind {
	case "ssh_key":
		// Parse public key or derive from private key if possible
		if strings.TrimSpace(pay.PublicKey) != "" {
			if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(pay.PublicKey))); err == nil {
				pay.Fingerprint = ssh.FingerprintSHA256(pk)
				if pay.KeyType == "" {
					pay.KeyType = pk.Type()
				}
			}
		} else if strings.TrimSpace(pay.PrivateKey) != "" && pay.Passphrase == "" {
			if signer, err := ssh.ParsePrivateKey([]byte(strings.TrimSpace(pay.PrivateKey))); err == nil {
				pk := signer.PublicKey()
				pay.Fingerprint = ssh.FingerprintSHA256(pk)
				if pay.KeyType == "" {
					pay.KeyType = pk.Type()
				}
				if pay.PublicKey == "" {
					pay.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
				}
			}
		}
		var parts []string
		if pay.KeyType != "" {
			parts = append(parts, pay.KeyType)
		}
		if pay.Username != "" && pay.Host != "" {
			parts = append(parts, fmt.Sprintf("%s@%s", pay.Username, pay.Host))
		} else if pay.Host != "" {
			parts = append(parts, pay.Host)
		} else if pay.Username != "" {
			parts = append(parts, pay.Username)
		}
		if pay.Fingerprint != "" {
			fp := pay.Fingerprint
			if len(fp) > 22 {
				fp = fp[:22] + "…"
			}
			parts = append(parts, fp)
		}
		if len(parts) == 0 {
			return "SSH Key", expires
		}
		return strings.Join(parts, " · "), expires

	case "tls_cert":
		if strings.TrimSpace(pay.Certificate) != "" {
			if block, _ := pem.Decode([]byte(pay.Certificate)); block != nil && block.Type == "CERTIFICATE" {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if pay.Subject == "" {
						if cert.Subject.CommonName != "" {
							pay.Subject = cert.Subject.CommonName
						} else if len(cert.DNSNames) > 0 {
							pay.Subject = cert.DNSNames[0]
						} else {
							pay.Subject = cert.Subject.String()
						}
					}
					if pay.Issuer == "" {
						if cert.Issuer.CommonName != "" {
							pay.Issuer = cert.Issuer.CommonName
						} else {
							pay.Issuer = cert.Issuer.String()
						}
					}
					sum := sha256.Sum256(cert.Raw)
					pay.Fingerprint = fmt.Sprintf("SHA256:%s", base64.RawStdEncoding.EncodeToString(sum[:]))
					if expires == nil {
						exp := cert.NotAfter.UTC()
						expires = &exp
					}
				}
			}
		}
		var parts []string
		if pay.Subject != "" {
			parts = append(parts, pay.Subject)
		}
		if pay.Issuer != "" && pay.Issuer != pay.Subject {
			parts = append(parts, "CA: "+pay.Issuer)
		}
		if len(parts) == 0 {
			return "TLS Certificate", expires
		}
		return strings.Join(parts, " · "), expires

	case "oauth_api":
		var parts []string
		if pay.Provider != "" {
			parts = append(parts, pay.Provider)
		}
		if pay.ClientID != "" {
			cid := pay.ClientID
			if len(cid) > 16 {
				cid = cid[:14] + "…"
			}
			parts = append(parts, "ID: "+cid)
		} else if pay.APIKey != "" {
			ak := pay.APIKey
			if len(ak) > 8 {
				ak = ak[:6] + "••••"
			} else {
				ak = "••••"
			}
			parts = append(parts, "Key: "+ak)
		}
		if pay.Scopes != "" {
			parts = append(parts, pay.Scopes)
		}
		if len(parts) == 0 {
			return "API / OAuth Credential", expires
		}
		return strings.Join(parts, " · "), expires

	case "login":
		var parts []string
		if pay.Username != "" {
			parts = append(parts, pay.Username)
		}
		if pay.Host != "" {
			if pay.Port > 0 {
				parts = append(parts, fmt.Sprintf("%s:%d", pay.Host, pay.Port))
			} else {
				parts = append(parts, pay.Host)
			}
		} else if pay.URL != "" {
			parts = append(parts, pay.URL)
		}
		if pay.Database != "" {
			parts = append(parts, pay.Database)
		}
		if len(parts) == 0 {
			return "Login / Account", expires
		}
		return strings.Join(parts, " · "), expires
	}
	return kind, expires
}

func toCredentialDTO(c db.Credential, projMap map[string]db.Project, payload *credentialPayload) credentialDTO {
	dto := credentialDTO{
		ID:              c.ID,
		EnvironmentSlug: c.EnvironmentSlug,
		Name:            c.Name,
		Kind:            c.Kind,
		Description:     c.Description,
		Summary:         c.Summary,
		Payload:         payload,
		CreatedBy:       c.CreatedBy,
		CreatedAt:       c.CreatedAt.UTC(),
		UpdatedAt:       c.UpdatedAt.UTC(),
	}
	if c.ProjectID.Valid && c.ProjectID.String != "" {
		pid := c.ProjectID.String
		dto.ProjectID = &pid
		if prj, ok := projMap[pid]; ok {
			dto.ProjectName = prj.Name
			dto.ProjectSlug = prj.Slug
		}
	}
	if c.ExpiresAt.Valid {
		t := c.ExpiresAt.Time.UTC()
		dto.ExpiresAt = &t
	}
	return dto
}

func (s *Server) canReadCredential(r *http.Request, p principal, c db.Credential) bool {
	if c.ProjectID.Valid && c.ProjectID.String != "" {
		return s.allowEnv(r, p, auth.PermCredentialsRead, c.ProjectID.String, c.EnvironmentSlug) == nil
	}
	if p.ServiceToken != nil {
		return false
	}
	return auth.Has(p.Perms, auth.PermCredentialsRead)
}

func (s *Server) canWriteCredential(r *http.Request, p principal, projectID, envSlug string) error {
	if strings.TrimSpace(projectID) != "" {
		return s.allowEnv(r, p, auth.PermCredentialsWrite, projectID, envSlug)
	}
	if p.ServiceToken != nil {
		return forbidden("service tokens cannot manage global credentials")
	}
	if !auth.Has(p.Perms, auth.PermCredentialsWrite) {
		return forbidden("missing permission credentials.write")
	}
	return nil
}

// openapi:operation
// summary: List credentials
// description: Returns all credentials accessible to the caller (global vault and accessible projects). Payloads are omitted unless reveal=1.
// responses:
//   '200': { description: Credentials list, schema: CredentialList }

func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request, p principal) error {
	projectFilter := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectFilter == "" && r.PathValue("id") != "" {
		proj, err := s.resolveProject(r.Context(), r.PathValue("id"))
		if err != nil {
			return fromStore(err, "project")
		}
		projectFilter = proj.ID
	}
	envFilter := strings.TrimSpace(r.URL.Query().Get("environment_slug"))
	kindFilter := strings.TrimSpace(r.URL.Query().Get("kind"))
	reveal := r.URL.Query().Get("reveal") == "1" || r.URL.Query().Get("reveal") == "true"

	var rows []db.Credential
	var err error
	if projectFilter != "" {
		rows, err = s.Store.Q.ListProjectCredentials(r.Context(), store.NullString(projectFilter))
	} else {
		rows, err = s.Store.Q.ListAllCredentials(r.Context())
	}
	if err != nil {
		return err
	}

	projects, _ := s.Store.Q.ListProjects(r.Context())
	projMap := make(map[string]db.Project, len(projects))
	for _, prj := range projects {
		projMap[prj.ID] = prj
	}

	out := make([]credentialDTO, 0, len(rows))
	for _, row := range rows {
		if !s.canReadCredential(r, p, row) {
			continue
		}
		if envFilter != "" && row.EnvironmentSlug != "" && row.EnvironmentSlug != envFilter {
			continue
		}
		if kindFilter != "" && row.Kind != kindFilter {
			continue
		}
		var pay *credentialPayload
		if reveal {
			if v, vErr := s.credentialVault(row.ProjectID.String); vErr == nil {
				if plain, dErr := v.Decrypt(row.PayloadEncrypted, row.PayloadNonce); dErr == nil {
					var parsed credentialPayload
					if json.Unmarshal(plain, &parsed) == nil {
						pay = &parsed
					}
				}
			}
		}
		out = append(out, toCredentialDTO(row, projMap, pay))
	}

	return ok(w, credentialListDTO{
		Items: out,
		Total: len(out),
	})
}

// openapi:operation
// summary: List project credentials
// description: Returns all credentials linked to a specific project.
// responses:
//   '200': { description: Project credentials list, schema: CredentialList }

func (s *Server) listProjectCredentials(w http.ResponseWriter, r *http.Request, p principal) error {
	return s.listCredentials(w, r, p)
}

// openapi:operation
// summary: Get credential
// description: Retrieves and decrypts a single credential by ID.
// responses:
//   '200': { description: Decrypted credential, schema: Credential }

func (s *Server) getCredential(w http.ResponseWriter, r *http.Request, p principal) error {
	credID := r.PathValue("cred_id")
	if credID == "" {
		credID = r.PathValue("id")
	}
	row, err := s.Store.Q.GetCredential(r.Context(), credID)
	if err != nil {
		return fromStore(err, "credential")
	}
	if !s.canReadCredential(r, p, row) {
		return forbidden("not authorized to read this credential")
	}
	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}

	v, err := s.credentialVault(row.ProjectID.String)
	if err != nil {
		return err
	}
	plain, err := v.Decrypt(row.PayloadEncrypted, row.PayloadNonce)
	if err != nil {
		return fmt.Errorf("decrypting credential: %w", err)
	}
	var pay credentialPayload
	if err := json.Unmarshal(plain, &pay); err != nil {
		return fmt.Errorf("decoding credential payload: %w", err)
	}

	projects, _ := s.Store.Q.ListProjects(r.Context())
	projMap := make(map[string]db.Project, len(projects))
	for _, prj := range projects {
		projMap[prj.ID] = prj
	}

	s.record(r, p, "credential.read", "credential", row.ID, map[string]any{
		"name":       row.Name,
		"kind":       row.Kind,
		"project_id": row.ProjectID.String,
	})

	return ok(w, toCredentialDTO(row, projMap, &pay))
}

// openapi:operation
// summary: Create credential
// description: Encrypts and stores a structured credential (SSH key, TLS certificate, API/OAuth key, or Login).
// requestBody: { schema: CreateCredentialRequest }
// responses:
//   '201': { description: Credential created, schema: Credential }

func (s *Server) createCredential(w http.ResponseWriter, r *http.Request, p principal) error {
	var in createCredentialRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	if pathProjID := r.PathValue("id"); pathProjID != "" && in.ProjectID == "" {
		in.ProjectID = pathProjID
	}

	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 160 {
		return badRequest("credential name must be between 1 and 160 characters")
	}
	if !validCredentialKind(in.Kind) {
		return badRequest("kind must be ssh_key, tls_cert, oauth_api, or login")
	}

	var projectID string
	var projMap = make(map[string]db.Project)
	if strings.TrimSpace(in.ProjectID) != "" {
		proj, err := s.resolveProject(r.Context(), strings.TrimSpace(in.ProjectID))
		if err != nil {
			return fromStore(err, "project")
		}
		projectID = proj.ID
		projMap[proj.ID] = proj
	}

	envSlug := strings.TrimSpace(in.EnvironmentSlug)
	if projectID == "" {
		envSlug = ""
	}
	if err := s.canWriteCredential(r, p, projectID, envSlug); err != nil {
		return err
	}

	summary, expiresAt := enrichAndSummarizeCredential(in.Kind, &in.Payload, in.ExpiresAt)
	rawPayload, err := json.Marshal(in.Payload)
	if err != nil {
		return badRequest("invalid credential payload")
	}

	v, err := s.credentialVault(projectID)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := v.Encrypt(rawPayload)
	if err != nil {
		return err
	}

	credID := store.NewID()
	now := store.Now()
	var expNull sql.NullTime
	if expiresAt != nil && !expiresAt.IsZero() {
		expNull = store.NullTime(*expiresAt)
	}

	if err := s.Store.Q.CreateCredential(r.Context(), db.CreateCredentialParams{
		ID:               credID,
		ProjectID:        store.NullString(projectID),
		EnvironmentSlug:  envSlug,
		Name:             name,
		Kind:             in.Kind,
		Description:      strings.TrimSpace(in.Description),
		Summary:          summary,
		PayloadEncrypted: ciphertext,
		PayloadNonce:     nonce,
		ExpiresAt:        expNull,
		CreatedBy:        p.User.Username,
		Now:              now,
	}); err != nil {
		return fromStore(err, "credential")
	}

	s.record(r, p, "credential.create", "credential", credID, map[string]any{
		"name":        name,
		"kind":        in.Kind,
		"project_id":  projectID,
		"environment": envSlug,
	})
	s.changed(r, "credential", credID)

	row, err := s.Store.Q.GetCredential(r.Context(), credID)
	if err != nil {
		return err
	}
	return created(w, toCredentialDTO(row, projMap, &in.Payload))
}

// openapi:operation
// summary: Create project credential
// description: Encrypts and stores a structured credential linked to a specific project.
// requestBody: { schema: CreateCredentialRequest }
// responses:
//   '201': { description: Credential created, schema: Credential }

func (s *Server) createProjectCredential(w http.ResponseWriter, r *http.Request, p principal) error {
	return s.createCredential(w, r, p)
}

// openapi:operation
// summary: Update credential
// description: Updates metadata, project/environment binding, or encrypted payload of a credential.
// requestBody: { schema: UpdateCredentialRequest }
// responses:
//   '200': { description: Credential updated, schema: Credential }

func (s *Server) updateCredential(w http.ResponseWriter, r *http.Request, p principal) error {
	credID := r.PathValue("cred_id")
	if credID == "" {
		credID = r.PathValue("id")
	}
	cur, err := s.Store.Q.GetCredential(r.Context(), credID)
	if err != nil {
		return fromStore(err, "credential")
	}
	if err := s.canWriteCredential(r, p, cur.ProjectID.String, cur.EnvironmentSlug); err != nil {
		return err
	}

	var in updateCredentialRequest
	if err := decode(r, &in); err != nil {
		return err
	}

	targetProjID := cur.ProjectID.String
	if in.ProjectID.Set {
		rawProj := strings.TrimSpace(in.ProjectID.V)
		if rawProj == "" {
			targetProjID = ""
		} else {
			proj, err := s.resolveProject(r.Context(), rawProj)
			if err != nil {
				return fromStore(err, "project")
			}
			targetProjID = proj.ID
		}
	}

	targetEnv := cur.EnvironmentSlug
	if in.EnvironmentSlug.Set {
		targetEnv = strings.TrimSpace(in.EnvironmentSlug.V)
	}
	if targetProjID == "" {
		targetEnv = ""
	}

	if targetProjID != cur.ProjectID.String || targetEnv != cur.EnvironmentSlug {
		if err := s.canWriteCredential(r, p, targetProjID, targetEnv); err != nil {
			return err
		}
	}

	name := cur.Name
	if in.Name.Set {
		name = strings.TrimSpace(in.Name.V)
		if name == "" || len(name) > 160 {
			return badRequest("credential name must be between 1 and 160 characters")
		}
	}

	kind := cur.Kind
	if in.Kind.Set {
		if !validCredentialKind(in.Kind.V) {
			return badRequest("kind must be ssh_key, tls_cert, oauth_api, or login")
		}
		kind = in.Kind.V
	}

	desc := cur.Description
	if in.Description.Set {
		desc = strings.TrimSpace(in.Description.V)
	}

	// Decrypt existing payload so we can re-encrypt if project changed or payload updated
	oldVault, err := s.credentialVault(cur.ProjectID.String)
	if err != nil {
		return err
	}
	plainOld, err := oldVault.Decrypt(cur.PayloadEncrypted, cur.PayloadNonce)
	if err != nil {
		return fmt.Errorf("decrypting existing credential: %w", err)
	}
	var pay credentialPayload
	_ = json.Unmarshal(plainOld, &pay)
	if in.Payload.Set {
		pay = in.Payload.V
	}

	var expPtr *time.Time
	if in.ExpiresAt.Set {
		if !in.ExpiresAt.V.IsZero() {
			t := in.ExpiresAt.V.UTC()
			expPtr = &t
		}
	} else if cur.ExpiresAt.Valid {
		t := cur.ExpiresAt.Time.UTC()
		expPtr = &t
	}

	summary, finalExp := enrichAndSummarizeCredential(kind, &pay, expPtr)
	rawPayload, err := json.Marshal(pay)
	if err != nil {
		return badRequest("invalid credential payload")
	}

	newVault, err := s.credentialVault(targetProjID)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := newVault.Encrypt(rawPayload)
	if err != nil {
		return err
	}

	var expNull sql.NullTime
	if finalExp != nil && !finalExp.IsZero() {
		expNull = store.NullTime(*finalExp)
	}

	now := store.Now()
	if err := s.Store.Q.UpdateCredential(r.Context(), db.UpdateCredentialParams{
		ProjectID:        store.NullString(targetProjID),
		EnvironmentSlug:  targetEnv,
		Name:             name,
		Kind:             kind,
		Description:      desc,
		Summary:          summary,
		PayloadEncrypted: ciphertext,
		PayloadNonce:     nonce,
		ExpiresAt:        expNull,
		Now:              now,
		ID:               cur.ID,
	}); err != nil {
		return fromStore(err, "credential")
	}

	s.record(r, p, "credential.update", "credential", cur.ID, map[string]any{
		"name":        name,
		"kind":        kind,
		"project_id":  targetProjID,
		"environment": targetEnv,
	})
	s.changed(r, "credential", cur.ID)

	projects, _ := s.Store.Q.ListProjects(r.Context())
	projMap := make(map[string]db.Project, len(projects))
	for _, prj := range projects {
		projMap[prj.ID] = prj
	}

	updated, err := s.Store.Q.GetCredential(r.Context(), cur.ID)
	if err != nil {
		return err
	}
	return ok(w, toCredentialDTO(updated, projMap, &pay))
}

// openapi:operation
// summary: Delete credential
// description: Permanently deletes a stored credential.
// responses:
//   '204': { description: Credential deleted }

func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request, p principal) error {
	credID := r.PathValue("cred_id")
	if credID == "" {
		credID = r.PathValue("id")
	}
	cur, err := s.Store.Q.GetCredential(r.Context(), credID)
	if err != nil {
		return fromStore(err, "credential")
	}
	if err := s.canWriteCredential(r, p, cur.ProjectID.String, cur.EnvironmentSlug); err != nil {
		return err
	}
	if _, err := s.Store.Q.DeleteCredential(r.Context(), cur.ID); err != nil {
		return err
	}
	s.record(r, p, "credential.delete", "credential", cur.ID, map[string]any{
		"name":       cur.Name,
		"kind":       cur.Kind,
		"project_id": cur.ProjectID.String,
	})
	s.changed(r, "credential", cur.ID)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

var envPrefixSanitizer = regexp.MustCompile(`[^A-Z0-9_]+`)

func sanitizeEnvPrefix(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = envPrefixSanitizer.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "CRED"
	}
	return s
}

func credentialEnvPairs(kind, prefix string, pay credentialPayload) []struct{ k, v string } {
	p := sanitizeEnvPrefix(prefix)
	var pairs []struct{ k, v string }
	add := func(suffix, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		pairs = append(pairs, struct{ k, v string }{k: p + "_" + suffix, v: val})
	}

	switch kind {
	case "ssh_key":
		add("PRIVATE_KEY", pay.PrivateKey)
		add("PUBLIC_KEY", pay.PublicKey)
		add("PASSPHRASE", pay.Passphrase)
		add("HOST", pay.Host)
		if pay.Port > 0 {
			add("PORT", fmt.Sprintf("%d", pay.Port))
		}
		add("USER", pay.Username)
		add("FINGERPRINT", pay.Fingerprint)
	case "tls_cert":
		add("CERT", pay.Certificate)
		add("PRIVATE_KEY", pay.PrivateKey)
		add("CA_CHAIN", pay.CAChain)
		add("PASSPHRASE", pay.Passphrase)
	case "oauth_api":
		add("CLIENT_ID", pay.ClientID)
		add("CLIENT_SECRET", pay.ClientSecret)
		add("API_KEY", pay.APIKey)
		add("TOKEN_URL", pay.TokenURL)
		add("ENDPOINT_URL", pay.EndpointURL)
		add("SCOPES", pay.Scopes)
	case "login":
		add("USERNAME", pay.Username)
		add("PASSWORD", pay.Password)
		add("URL", pay.URL)
		add("HOST", pay.Host)
		if pay.Port > 0 {
			add("PORT", fmt.Sprintf("%d", pay.Port))
		}
		add("DATABASE", pay.Database)
	}
	return pairs
}

// openapi:operation
// summary: Sync credential fields into environment secrets
// description: Projects a structured credential's fields (e.g. CLIENT_ID, CLIENT_SECRET, PRIVATE_KEY) as encrypted environment secrets inside a target project and environment.
// requestBody: { schema: SyncCredentialEnvRequest }
// responses:
//   '200': { description: Sync summary, schema: SyncCredentialEnvResponse }

func (s *Server) syncCredentialToEnv(w http.ResponseWriter, r *http.Request, p principal) error {
	credID := r.PathValue("cred_id")
	if credID == "" {
		credID = r.PathValue("id")
	}
	cur, err := s.Store.Q.GetCredential(r.Context(), credID)
	if err != nil {
		return fromStore(err, "credential")
	}
	if !s.canReadCredential(r, p, cur) {
		return forbidden("not authorized to read this credential")
	}

	var in syncCredentialEnvRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	proj, err := s.resolveProject(r.Context(), strings.TrimSpace(in.ProjectID))
	if err != nil {
		return fromStore(err, "project")
	}
	envSlug := strings.TrimSpace(in.EnvironmentSlug)
	if envSlug == "" {
		return badRequest("environment_slug is required")
	}
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, proj.ID, envSlug); err != nil {
		return err
	}
	if _, err := s.Store.Q.GetEnvironmentBySlug(r.Context(), db.GetEnvironmentBySlugParams{
		ProjectID: proj.ID,
		Slug:      envSlug,
	}); err != nil {
		return fromStore(err, "environment")
	}

	credVault, err := s.credentialVault(cur.ProjectID.String)
	if err != nil {
		return err
	}
	plain, err := credVault.Decrypt(cur.PayloadEncrypted, cur.PayloadNonce)
	if err != nil {
		return fmt.Errorf("decrypting credential: %w", err)
	}
	var pay credentialPayload
	if err := json.Unmarshal(plain, &pay); err != nil {
		return fmt.Errorf("decoding credential: %w", err)
	}

	prefix := in.Prefix
	if strings.TrimSpace(prefix) == "" {
		prefix = cur.Name
	}
	pairs := credentialEnvPairs(cur.Kind, prefix, pay)
	if len(pairs) == 0 {
		return badRequest("credential has no non-empty fields to project as secrets")
	}

	targetPath := normalizePath(in.Path)
	projVault, err := s.projectVault(proj.ID)
	if err != nil {
		return err
	}

	var createdCount, updatedCount int
	var writtenKeys []string
	now := store.Now()
	comment := fmt.Sprintf("Synced from credential %q (%s)", cur.Name, cur.Kind)

	err = s.Store.Tx(r.Context(), func(q *db.Queries) error {
		for _, item := range pairs {
			ciphertext, nonce, encErr := projVault.Encrypt([]byte(item.v))
			if encErr != nil {
				return encErr
			}
			existing, getErr := q.GetSecretByKey(r.Context(), db.GetSecretByKeyParams{
				ProjectID:       proj.ID,
				EnvironmentSlug: envSlug,
				Path:            targetPath,
				Key:             item.k,
			})
			if getErr != nil {
				newSecID := store.NewID()
				if err := q.CreateSecret(r.Context(), db.CreateSecretParams{
					ID:              newSecID,
					ProjectID:       proj.ID,
					EnvironmentSlug: envSlug,
					Path:            targetPath,
					Key:             item.k,
					ValueEncrypted:  ciphertext,
					ValueNonce:      nonce,
					Comment:         comment,
					Version:         1,
					Now:             now,
				}); err != nil {
					return err
				}
				if err := q.CreateSecretVersion(r.Context(), db.CreateSecretVersionParams{
					ID:             store.NewID(),
					SecretID:       newSecID,
					Version:        1,
					ValueEncrypted: ciphertext,
					ValueNonce:     nonce,
					Comment:        comment,
					Now:            now,
					CreatedBy:      p.User.Username,
				}); err != nil {
					return err
				}
				createdCount++
				writtenKeys = append(writtenKeys, item.k)
			} else if in.Overwrite {
				if err := q.UpdateSecret(r.Context(), db.UpdateSecretParams{
					ValueEncrypted: ciphertext,
					ValueNonce:     nonce,
					Comment:        comment,
					Now:            now,
					ID:             existing.ID,
				}); err != nil {
					return err
				}
				if err := q.CreateSecretVersion(r.Context(), db.CreateSecretVersionParams{
					ID:             store.NewID(),
					SecretID:       existing.ID,
					Version:        existing.Version + 1,
					ValueEncrypted: ciphertext,
					ValueNonce:     nonce,
					Comment:        comment,
					Now:            now,
					CreatedBy:      p.User.Username,
				}); err != nil {
					return err
				}
				updatedCount++
				writtenKeys = append(writtenKeys, item.k)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.record(r, p, "credential.sync_env", "credential", cur.ID, map[string]any{
		"project_id":  proj.ID,
		"environment": envSlug,
		"keys":        writtenKeys,
	})
	s.changed(r, "secret", proj.ID)

	return ok(w, syncCredentialEnvResponse{
		Created: createdCount,
		Updated: updatedCount,
		Keys:    writtenKeys,
	})
}

// openapi:operation
// summary: Generate SSH keypair
// description: Generates a fresh cryptographic SSH keypair (Ed25519, RSA-4096, or ECDSA-P256) in OpenSSH format.
// requestBody: { schema: GenerateSSHKeyRequest }
// responses:
//   '200': { description: Generated SSH keypair, schema: GenerateSSHKeyResponse }

func (s *Server) generateSSHKeypair(w http.ResponseWriter, r *http.Request, p principal) error {
	var in generateSSHKeyRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	algo := strings.ToLower(strings.TrimSpace(in.Algorithm))
	if algo == "" {
		algo = "ed25519"
	}
	comment := strings.TrimSpace(in.Comment)
	if comment == "" {
		comment = "ducksecrets"
	}

	var privKey any
	switch algo {
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privKey = priv
	case "rsa4096", "rsa":
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return err
		}
		privKey = priv
	case "ecdsa256", "ecdsa":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		privKey = priv
	default:
		return badRequest("algorithm must be ed25519, rsa4096, or ecdsa256")
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		return fmt.Errorf("marshaling ssh private key: %w", err)
	}
	privPEM := string(pem.EncodeToMemory(pemBlock))

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return fmt.Errorf("creating ssh signer: %w", err)
	}
	pubKey := signer.PublicKey()
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
	if comment != "" {
		authorized = authorized + " " + comment
	}

	return ok(w, generateSSHKeyResponse{
		PrivateKey:  privPEM,
		PublicKey:   authorized,
		Fingerprint: ssh.FingerprintSHA256(pubKey),
		KeyType:     pubKey.Type(),
	})
}
