package server

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// openapi:schema ProjectPolicy
// type: object
// required: [id, project_id, subject_type, subject_id, environment_slug, can_read, can_write, can_admin, can_view_creds, can_edit_creds, description, created_at]
// properties:
//   id: { type: string, format: uuid }
//   project_id: { type: string, format: uuid }
//   subject_type: { type: string, enum: [user, role] }
//   subject_id: { type: string }
//   environment_slug: { type: string }
//   can_read: { type: boolean }
//   can_write: { type: boolean }
//   can_admin: { type: boolean }
//   can_view_creds: { type: boolean }
//   can_edit_creds: { type: boolean }
//   starts_at: { type: string, format: date-time, nullable: true }
//   expires_at: { type: string, format: date-time, nullable: true }
//   description: { type: string }
//   created_by: { type: string, nullable: true }
//   created_at: { type: string, format: date-time }

type projectPolicyDTO struct {
	ID              string     `json:"id"`
	ProjectID       string     `json:"project_id"`
	SubjectType     string     `json:"subject_type"`
	SubjectID       string     `json:"subject_id"`
	EnvironmentSlug string     `json:"environment_slug"`
	CanRead         bool       `json:"can_read"`
	CanWrite        bool       `json:"can_write"`
	CanAdmin        bool       `json:"can_admin"`
	CanViewCreds    bool       `json:"can_view_creds"`
	CanEditCreds    bool       `json:"can_edit_creds"`
	StartsAt        *time.Time `json:"starts_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	Description     string     `json:"description"`
	CreatedBy       *string    `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

func toProjectPolicyDTO(p db.ProjectPolicy) projectPolicyDTO {
	dto := projectPolicyDTO{
		ID:              p.ID,
		ProjectID:       p.ProjectID,
		SubjectType:     p.SubjectType,
		SubjectID:       p.SubjectID,
		EnvironmentSlug: p.EnvironmentSlug,
		CanRead:         p.CanRead,
		CanWrite:        p.CanWrite,
		CanAdmin:        p.CanAdmin,
		CanViewCreds:    p.CanViewCreds,
		CanEditCreds:    p.CanEditCreds,
		Description:     p.Description,
		CreatedAt:       p.CreatedAt.UTC(),
	}
	if p.StartsAt.Valid {
		t := p.StartsAt.Time.UTC()
		dto.StartsAt = &t
	}
	if p.ExpiresAt.Valid {
		t := p.ExpiresAt.Time.UTC()
		dto.ExpiresAt = &t
	}
	if p.CreatedBy.Valid {
		s := p.CreatedBy.String
		dto.CreatedBy = &s
	}
	return dto
}

// openapi:schema CreateProjectPolicyRequest
// type: object
// required: [subject_type, subject_id]
// additionalProperties: false
// properties:
//   subject_type: { type: string, enum: [user, role] }
//   subject_id: { type: string }
//   environment_slug: { type: string, default: '*' }
//   can_read: { type: boolean, default: true }
//   can_write: { type: boolean, default: false }
//   can_admin: { type: boolean, default: false }
//   can_view_creds: { type: boolean, default: true }
//   can_edit_creds: { type: boolean, default: false }
//   starts_at: { type: string, format: date-time, nullable: true }
//   expires_at: { type: string, format: date-time, nullable: true }
//   ttl_seconds: { type: integer, minimum: 60 }
//   description: { type: string, maxLength: 500 }

type createProjectPolicyRequest struct {
	SubjectType     string     `json:"subject_type"`
	SubjectID       string     `json:"subject_id"`
	EnvironmentSlug string     `json:"environment_slug"`
	CanRead         *bool      `json:"can_read"`
	CanWrite        bool       `json:"can_write"`
	CanAdmin        bool       `json:"can_admin"`
	CanViewCreds    *bool      `json:"can_view_creds"`
	CanEditCreds    bool       `json:"can_edit_creds"`
	StartsAt        *time.Time `json:"starts_at"`
	ExpiresAt       *time.Time `json:"expires_at"`
	TTLSeconds      int64      `json:"ttl_seconds"`
	Description     string     `json:"description"`
}

// openapi:schema UpdateProjectPolicyRequest
// type: object
// additionalProperties: false
// properties:
//   environment_slug: { type: string }
//   can_read: { type: boolean }
//   can_write: { type: boolean }
//   can_admin: { type: boolean }
//   can_view_creds: { type: boolean }
//   can_edit_creds: { type: boolean }
//   starts_at: { type: string, format: date-time, nullable: true }
//   expires_at: { type: string, format: date-time, nullable: true }
//   description: { type: string, maxLength: 500 }

type updateProjectPolicyRequest struct {
	EnvironmentSlug opt[string]    `json:"environment_slug"`
	CanRead         opt[bool]      `json:"can_read"`
	CanWrite        opt[bool]      `json:"can_write"`
	CanAdmin        opt[bool]      `json:"can_admin"`
	CanViewCreds    opt[bool]      `json:"can_view_creds"`
	CanEditCreds    opt[bool]      `json:"can_edit_creds"`
	StartsAt        opt[time.Time] `json:"starts_at"`
	ExpiresAt       opt[time.Time] `json:"expires_at"`
	Description     opt[string]    `json:"description"`
}

// openapi:operation
// summary: List project access policies
// description: Returns all access control policies for a project, including subject roles and environment scopes.
// responses:
//   '200': { description: Policies list, schema: '[]ProjectPolicy' }

func (s *Server) listProjectPolicies(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	if err := s.allow(r, p, auth.PermProjectsRead, "project", projectID); err != nil {
		return err
	}

	policies, err := s.Store.Q.ListProjectPolicies(r.Context(), projectID)
	if err != nil {
		return err
	}

	out := make([]projectPolicyDTO, 0, len(policies))
	for _, pol := range policies {
		out = append(out, toProjectPolicyDTO(pol))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Create project access policy
// description: Grants a user or role specific permissions (read, write, admin) on a project and optional environment.
// responses:
//   '201': { description: Policy created, schema: ProjectPolicy }

func (s *Server) createProjectPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	if err := s.allow(r, p, auth.PermProjectsWrite, "project", projectID); err != nil {
		return err
	}

	var req createProjectPolicyRequest
	if err := decode(r, &req); err != nil {
		return err
	}

	if req.SubjectType != "user" && req.SubjectType != "role" {
		return badRequest("subject_type must be user or role")
	}
	if req.SubjectID == "" {
		return badRequest("subject_id is required")
	}

	envSlug := req.EnvironmentSlug
	if envSlug == "" {
		envSlug = "*"
	}

	canRead := true
	if req.CanRead != nil {
		canRead = *req.CanRead
	}
	canViewCreds := true
	if req.CanViewCreds != nil {
		canViewCreds = *req.CanViewCreds
	}

	now := store.Now()
	var startsAt sql.NullTime
	if req.StartsAt != nil {
		startsAt = store.NullTime(*req.StartsAt)
	}

	var expiresAt sql.NullTime
	if req.TTLSeconds > 0 {
		exp := now.Add(time.Duration(req.TTLSeconds) * time.Second)
		expiresAt = store.NullTime(exp)
	} else if req.ExpiresAt != nil {
		expiresAt = store.NullTime(*req.ExpiresAt)
	}

	createdBy := p.User.Username
	if createdBy == "" {
		createdBy = "admin"
	}

	policy, err := s.Store.Q.CreateProjectPolicy(r.Context(), db.CreateProjectPolicyParams{
		ID:              uuid.New().String(),
		ProjectID:       projectID,
		SubjectType:     req.SubjectType,
		SubjectID:       req.SubjectID,
		EnvironmentSlug: envSlug,
		CanRead:         canRead,
		CanWrite:        req.CanWrite,
		CanAdmin:        req.CanAdmin,
		CanViewCreds:    canViewCreds,
		CanEditCreds:    req.CanEditCreds,
		StartsAt:        startsAt,
		ExpiresAt:       expiresAt,
		Description:     req.Description,
		CreatedBy:       sql.NullString{String: createdBy, Valid: true},
		CreatedAt:       now,
	})
	if err != nil {
		return badRequest("failed to create policy (may already exist for this subject/environment): %v", err)
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "policy.create", "project_policy", policy.ID, map[string]any{
		"project_id":       projectID,
		"subject":          req.SubjectType + ":" + req.SubjectID,
		"environment_slug": envSlug,
		"can_read":         canRead,
		"can_write":        req.CanWrite,
		"can_admin":        req.CanAdmin,
		"can_view_creds":   canViewCreds,
		"can_edit_creds":   req.CanEditCreds,
	})

	return created(w, toProjectPolicyDTO(policy))
}

// openapi:operation
// summary: Update project access policy
// description: Updates permissions, environment scope, or expiration for an existing policy.
// responses:
//   '200': { description: Policy updated, schema: ProjectPolicy }

func (s *Server) updateProjectPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	policyID := r.PathValue("policy_id")
	if err := s.allow(r, p, auth.PermProjectsWrite, "project", projectID); err != nil {
		return err
	}

	pol, err := s.Store.Q.GetProjectPolicy(r.Context(), policyID)
	if err != nil {
		return fromStore(err, "policy")
	}
	if pol.ProjectID != projectID {
		return notFound("policy not found in this project")
	}

	var req updateProjectPolicyRequest
	if err := decode(r, &req); err != nil {
		return err
	}

	envSlug := pol.EnvironmentSlug
	if req.EnvironmentSlug.Set {
		envSlug = req.EnvironmentSlug.V
		if envSlug == "" {
			envSlug = "*"
		}
	}

	canRead := pol.CanRead
	if req.CanRead.Set {
		canRead = req.CanRead.V
	}

	canWrite := pol.CanWrite
	if req.CanWrite.Set {
		canWrite = req.CanWrite.V
	}

	canAdmin := pol.CanAdmin
	if req.CanAdmin.Set {
		canAdmin = req.CanAdmin.V
	}

	canViewCreds := pol.CanViewCreds
	if req.CanViewCreds.Set {
		canViewCreds = req.CanViewCreds.V
	}

	canEditCreds := pol.CanEditCreds
	if req.CanEditCreds.Set {
		canEditCreds = req.CanEditCreds.V
	}

	startsAt := pol.StartsAt
	if req.StartsAt.Set {
		startsAt = store.NullTime(req.StartsAt.V)
	}

	expiresAt := pol.ExpiresAt
	if req.ExpiresAt.Set {
		expiresAt = store.NullTime(req.ExpiresAt.V)
	}

	description := pol.Description
	if req.Description.Set {
		description = req.Description.V
	}

	updated, err := s.Store.Q.UpdateProjectPolicy(r.Context(), db.UpdateProjectPolicyParams{
		ID:              policyID,
		EnvironmentSlug: envSlug,
		CanRead:         canRead,
		CanWrite:        canWrite,
		CanAdmin:        canAdmin,
		CanViewCreds:    canViewCreds,
		CanEditCreds:    canEditCreds,
		StartsAt:        startsAt,
		ExpiresAt:       expiresAt,
		Description:     description,
	})
	if err != nil {
		return err
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "policy.update", "project_policy", policyID, map[string]any{
		"project_id":       projectID,
		"environment_slug": envSlug,
		"can_read":         canRead,
		"can_write":        canWrite,
		"can_admin":        canAdmin,
		"can_view_creds":   canViewCreds,
		"can_edit_creds":   canEditCreds,
	})

	return ok(w, toProjectPolicyDTO(updated))
}

// openapi:operation
// summary: Delete project access policy
// description: Revokes a project policy and removes access.
// responses:
//   '204': { description: Policy deleted }

func (s *Server) deleteProjectPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	policyID := r.PathValue("policy_id")
	if err := s.allow(r, p, auth.PermProjectsWrite, "project", projectID); err != nil {
		return err
	}

	pol, err := s.Store.Q.GetProjectPolicy(r.Context(), policyID)
	if err != nil {
		return fromStore(err, "policy")
	}
	if pol.ProjectID != projectID {
		return notFound("policy not found in this project")
	}

	if err := s.Store.Q.DeleteProjectPolicy(r.Context(), policyID); err != nil {
		return err
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "policy.delete", "project_policy", policyID, map[string]any{
		"project_id": projectID,
		"subject":    pol.SubjectType + ":" + pol.SubjectID,
	})

	return noContent(w)
}
