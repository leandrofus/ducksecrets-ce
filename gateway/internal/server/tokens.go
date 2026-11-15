package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// openapi:schema ServiceToken
// type: object
// required: [id, name, token_prefix, project_id, environment_slug, path, permissions, allowed_cidrs, single_use, created_by, created_at]
// properties:
//   id: { type: string, format: uuid }
//   name: { type: string }
//   token_prefix: { type: string }
//   project_id: { type: string, format: uuid }
//   environment_slug: { type: string }
//   path: { type: string }
//   permissions: { type: string }
//   allowed_cidrs: { type: string }
//   single_use: { type: boolean }
//   burned_at: { type: string, format: date-time, nullable: true }
//   created_by: { type: string }
//   created_at: { type: string, format: date-time }
//   expires_at: { type: string, format: date-time, nullable: true }
//   last_used_at: { type: string, format: date-time, nullable: true }

type serviceTokenDTO struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	TokenPrefix     string     `json:"token_prefix"`
	ProjectID       string     `json:"project_id"`
	EnvironmentSlug string     `json:"environment_slug"`
	Path            string     `json:"path"`
	Permissions     string     `json:"permissions"`
	AllowedCidrs    string     `json:"allowed_cidrs"`
	SingleUse       bool       `json:"single_use"`
	BurnedAt        *time.Time `json:"burned_at,omitempty"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
}

func toServiceToken(st db.ServiceToken) serviceTokenDTO {
	dto := serviceTokenDTO{
		ID:              st.ID,
		Name:            st.Name,
		TokenPrefix:     st.TokenPrefix,
		ProjectID:       st.ProjectID,
		EnvironmentSlug: st.EnvironmentSlug,
		Path:            st.Path,
		Permissions:     st.Permissions,
		AllowedCidrs:    st.AllowedCidrs,
		SingleUse:       st.SingleUse,
		CreatedBy:       st.CreatedBy,
		CreatedAt:       st.CreatedAt.UTC(),
	}
	if st.ExpiresAt.Valid {
		t := st.ExpiresAt.Time.UTC()
		dto.ExpiresAt = &t
	}
	if st.LastUsedAt.Valid {
		t := st.LastUsedAt.Time.UTC()
		dto.LastUsedAt = &t
	}
	if st.BurnedAt.Valid {
		t := st.BurnedAt.Time.UTC()
		dto.BurnedAt = &t
	}
	return dto
}

// openapi:schema CreatedServiceToken
// type: object
// required: [id, name, token_prefix, project_id, environment_slug, path, permissions, raw_token, allowed_cidrs, single_use, created_at]
// properties:
//   id: { type: string, format: uuid }
//   name: { type: string }
//   token_prefix: { type: string }
//   project_id: { type: string, format: uuid }
//   environment_slug: { type: string }
//   path: { type: string }
//   permissions: { type: string }
//   raw_token: { type: string }
//   allowed_cidrs: { type: string }
//   single_use: { type: boolean }
//   created_at: { type: string, format: date-time }

type createdServiceTokenDTO struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	TokenPrefix     string    `json:"token_prefix"`
	ProjectID       string    `json:"project_id"`
	EnvironmentSlug string    `json:"environment_slug"`
	Path            string    `json:"path"`
	Permissions     string    `json:"permissions"`
	RawToken        string    `json:"raw_token"`
	AllowedCidrs    string    `json:"allowed_cidrs"`
	SingleUse       bool      `json:"single_use"`
	CreatedAt       time.Time `json:"created_at"`
}

// openapi:schema CreateServiceTokenRequest
// type: object
// required: [name]
// additionalProperties: false
// properties:
//   name: { type: string, minLength: 1, maxLength: 100 }
//   environment_slug: { type: string }
//   path: { type: string }
//   permissions: { type: string }
//   allowed_cidrs: { type: string }
//   single_use: { type: boolean }
//   expires_in_days: { type: integer }

type createServiceTokenRequest struct {
	Name            string `json:"name"`
	EnvironmentSlug string `json:"environment_slug"`
	Path            string `json:"path"`
	Permissions     string `json:"permissions"`
	AllowedCidrs    string `json:"allowed_cidrs"`
	SingleUse       bool   `json:"single_use"`
	ExpiresInDays   int    `json:"expires_in_days"`
}

func generateServiceToken() (rawToken, tokenPrefix, tokenHash string, err error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", "", "", fmt.Errorf("generating token: %w", err)
	}
	rawToken = "duck_st_" + hex.EncodeToString(b)
	tokenPrefix = rawToken[:16] + "..."
	h := sha256.Sum256([]byte(rawToken))
	tokenHash = hex.EncodeToString(h[:])
	return rawToken, tokenPrefix, tokenHash, nil
}

// openapi:operation
// summary: List project service tokens
// description: Returns all service tokens provisioned for a project.
// responses:
//   '200': { description: Service tokens list, schema: { type: array, items: { $ref: '#/components/schemas/ServiceToken' } } }

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	if err := s.allow(r, p, auth.PermProjectsRead, "project", projectID); err != nil {
		return err
	}
	if _, err := s.Store.Q.GetProject(r.Context(), projectID); err != nil {
		return fromStore(err, "project")
	}

	tokens, err := s.Store.Q.ListServiceTokensByProject(r.Context(), projectID)
	if err != nil {
		return err
	}

	out := make([]serviceTokenDTO, 0, len(tokens))
	for _, tk := range tokens {
		out = append(out, toServiceToken(tk))
	}
	return ok(w, out)
}

var allowedTokenPerms = map[string]bool{
	auth.PermProjectsRead:      true,
	auth.PermProjectsWrite:     true,
	auth.PermEnvironmentsRead:  true,
	auth.PermEnvironmentsWrite: true,
	auth.PermSecretsRead:       true,
	auth.PermSecretsWrite:      true,
}

// openapi:operation
// summary: Create service token
// description: Creates a scoped machine token (duck_st_*) for CI/CD and containers. The raw token is returned once.
// requestBody: { schema: CreateServiceTokenRequest }
// responses:
//   '201': { description: Created token with raw secret, schema: CreatedServiceToken }

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, p principal) error {
	if p.ServiceToken != nil {
		return forbidden("service tokens cannot create service tokens")
	}
	projectID := r.PathValue("id")
	if err := s.allow(r, p, auth.PermProjectsWrite, "project", projectID); err != nil {
		return err
	}
	if _, err := s.Store.Q.GetProject(r.Context(), projectID); err != nil {
		return fromStore(err, "project")
	}

	var in createServiceTokenRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		return badRequest("token name must be between 1 and 100 characters")
	}

	envSlug := strings.TrimSpace(in.EnvironmentSlug)
	if envSlug == "" {
		envSlug = "*"
	}
	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = "/"
	} else if path != "*" {
		path = normalizePath(path)
	}

	rawPerms := strings.Fields(strings.TrimSpace(in.Permissions))
	if len(rawPerms) == 0 {
		rawPerms = []string{auth.PermSecretsRead}
	}
	for _, rp := range rawPerms {
		if !allowedTokenPerms[rp] {
			return badRequest("permission %q is not valid for a service token", rp)
		}
		var err error
		if envSlug == "*" {
			err = s.allowWildcardEnv(r, p, rp, projectID)
		} else {
			err = s.allowEnv(r, p, rp, projectID, envSlug)
		}
		if err != nil {
			return forbidden("cannot grant permission %s for environment %s: %v", rp, envSlug, err)
		}
	}
	perms := strings.Join(rawPerms, " ")

	allowedCidrs := strings.TrimSpace(in.AllowedCidrs)
	if allowedCidrs != "" {
		if err := validateCIDRs(allowedCidrs); err != nil {
			return badRequest("invalid allowed_cidrs: %v", err)
		}
	}

	var expiresAt sql.NullTime
	if in.ExpiresInDays > 0 {
		expiresAt = sql.NullTime{
			Time:  store.Now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour),
			Valid: true,
		}
	}

	rawToken, prefix, tokenHash, err := generateServiceToken()
	if err != nil {
		return err
	}

	id := store.NewID()
	now := store.Now()

	if err := s.Store.Q.CreateServiceToken(r.Context(), db.CreateServiceTokenParams{
		ID:              id,
		Name:            name,
		TokenHash:       tokenHash,
		TokenPrefix:     prefix,
		ProjectID:       projectID,
		EnvironmentSlug: envSlug,
		Path:            path,
		Permissions:     perms,
		AllowedCidrs:    allowedCidrs,
		SingleUse:       in.SingleUse,
		CreatedBy:       p.User.Username,
		Now:             now,
		ExpiresAt:       expiresAt,
	}); err != nil {
		return fromStore(err, "service_token")
	}

	s.record(r, p, "token.create", "service_token", id, map[string]any{
		"project_id":    projectID,
		"name":          name,
		"prefix":        prefix,
		"environment":   envSlug,
		"allowed_cidrs": allowedCidrs,
		"single_use":    in.SingleUse,
	})

	return created(w, createdServiceTokenDTO{
		ID:              id,
		Name:            name,
		TokenPrefix:     prefix,
		ProjectID:       projectID,
		EnvironmentSlug: envSlug,
		Path:            path,
		Permissions:     perms,
		RawToken:        rawToken,
		AllowedCidrs:    allowedCidrs,
		SingleUse:       in.SingleUse,
		CreatedAt:       now,
	})
}

func validateCIDRs(raw string) error {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			if _, err := netip.ParsePrefix(part); err != nil {
				return fmt.Errorf("invalid CIDR prefix %q: %w", part, err)
			}
		} else {
			if _, err := netip.ParseAddr(part); err != nil {
				return fmt.Errorf("invalid IP address %q: %w", part, err)
			}
		}
	}
	return nil
}

// openapi:operation
// summary: Delete service token
// description: Revokes a service token immediately.
// responses:
//   '204': { description: Token revoked }

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	tokenID := r.PathValue("token_id")
	if err := s.allow(r, p, auth.PermProjectsWrite, "project", projectID); err != nil {
		return err
	}

	tk, err := s.Store.Q.GetServiceToken(r.Context(), tokenID)
	if err != nil {
		return fromStore(err, "service_token")
	}
	if tk.ProjectID != projectID {
		return notFound("service_token")
	}

	return handleCommand(w, func() error {
		n, err := s.Store.Q.DeleteServiceToken(r.Context(), tokenID)
		if err != nil {
			return err
		}
		if n == 0 {
			return notFound("service_token")
		}
		s.record(r, p, "token.delete", "service_token", tokenID, map[string]any{
			"project_id": projectID,
			"name":       tk.Name,
		})
		return nil
	})
}
