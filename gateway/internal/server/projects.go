package server

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// openapi:schema Project
// type: object
// required: [id, name, slug, description, created_at, updated_at]
// properties:
//   id: { type: string, format: uuid }
//   name: { type: string }
//   slug: { type: string }
//   description: { type: string }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }

type projectDTO struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func toProject(p db.Project) projectDTO {
	return projectDTO{
		ID:          p.ID,
		Name:        p.Name,
		Slug:        p.Slug,
		Description: p.Description,
		CreatedAt:   p.CreatedAt.UTC(),
		UpdatedAt:   p.UpdatedAt.UTC(),
	}
}

func (s *Server) resolveProject(ctx context.Context, idOrSlug string) (db.Project, error) {
	if p, err := s.Store.Q.GetProject(ctx, idOrSlug); err == nil {
		return p, nil
	}
	return s.Store.Q.GetProjectBySlug(ctx, idOrSlug)
}

// openapi:schema ProjectList
// type: object
// required: [items, total]
// properties:
//   items: { type: array, items: { $ref: '#/components/schemas/Project' } }
//   total: { type: integer }

type projectListDTO struct {
	Items []projectDTO `json:"items"`
	Total int          `json:"total"`
}

// openapi:schema CreateProjectRequest
// type: object
// required: [name]
// additionalProperties: false
// properties:
//   name: { type: string, minLength: 1, maxLength: 100 }
//   slug: { type: string, minLength: 1, maxLength: 50 }
//   description: { type: string, maxLength: 500 }

type createProjectRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
}

// openapi:schema UpdateProjectRequest
// type: object
// additionalProperties: false
// properties:
//   name: { type: string, minLength: 1, maxLength: 100 }
//   description: { type: string, maxLength: 500 }

type updateProjectRequest struct {
	Name        opt[string] `json:"name"`
	Description opt[string] `json:"description"`
}

// openapi:schema Environment
// type: object
// required: [id, project_id, name, slug, position, created_at]
// properties:
//   id: { type: string, format: uuid }
//   project_id: { type: string, format: uuid }
//   name: { type: string }
//   slug: { type: string }
//   position: { type: integer }
//   created_at: { type: string, format: date-time }

type environmentDTO struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Position  int32     `json:"position"`
	CreatedAt time.Time `json:"created_at"`
}

func toEnvironment(e db.Environment) environmentDTO {
	return environmentDTO{
		ID:        e.ID,
		ProjectID: e.ProjectID,
		Name:      e.Name,
		Slug:      e.Slug,
		Position:  e.Position,
		CreatedAt: e.CreatedAt.UTC(),
	}
}

// openapi:schema CreateEnvironmentRequest
// type: object
// required: [name]
// additionalProperties: false
// properties:
//   name: { type: string, minLength: 1, maxLength: 50 }
//   slug: { type: string, minLength: 1, maxLength: 30 }
//   position: { type: integer }

type createEnvironmentRequest struct {
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Position int32  `json:"position"`
}

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '_' {
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" {
		return "project"
	}
	return res
}

// openapi:operation
// summary: List projects
// description: Returns all accessible projects.
// responses:
//   '200': { description: Projects list, schema: ProjectList }

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request, p principal) error {
	all, ids, err := s.visible(r, p, auth.PermProjectsRead, "project")
	if err != nil {
		return err
	}
	ps, err := s.Store.Q.ListProjects(r.Context())
	if err != nil {
		return err
	}
	out := make([]projectDTO, 0, len(ps))
	for _, prj := range ps {
		if all || ids[prj.ID] {
			out = append(out, toProject(prj))
		}
	}
	return ok(w, projectListDTO{Items: out, Total: len(out)})
}

// openapi:operation
// summary: Create project
// description: Creates a project with default environments (dev, staging, prod).
// requestBody: { schema: CreateProjectRequest }
// responses:
//   '201': { description: Created project, schema: Project }

func (s *Server) createProject(w http.ResponseWriter, r *http.Request, p principal) error {
	var in createProjectRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		return badRequest("project name must be between 1 and 100 characters")
	}
	slug := in.Slug
	if slug == "" {
		slug = slugify(name)
	}
	if !slugRegex.MatchString(slug) {
		return badRequest("slug must consist of lowercase letters, digits, and hyphens")
	}

	id := store.NewID()
	now := store.Now()

	err := s.Store.Tx(r.Context(), func(q *db.Queries) error {
		if err := q.CreateProject(r.Context(), db.CreateProjectParams{
			ID:          id,
			Name:        name,
			Slug:        slug,
			Description: in.Description,
			Now:         now,
		}); err != nil {
			return fromStore(err, "project")
		}

		// Create default environments
		defaults := []struct {
			name string
			slug string
			pos  int32
		}{
			{"Development", "dev", 0},
			{"Staging", "staging", 1},
			{"Production", "prod", 2},
		}
		for _, d := range defaults {
			if err := q.CreateEnvironment(r.Context(), db.CreateEnvironmentParams{
				ID:        store.NewID(),
				ProjectID: id,
				Name:      d.name,
				Slug:      d.slug,
				Position:  d.pos,
				Now:       now,
			}); err != nil {
				return fromStore(err, "environment")
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.record(r, p, "project.create", "project", id, map[string]any{"name": name, "slug": slug})
	s.changed(r, "project", id)

	pRow, err := s.Store.Q.GetProject(r.Context(), id)
	if err != nil {
		return err
	}
	return created(w, toProject(pRow))
}

// openapi:operation
// summary: Get project
// description: Retrieves a project by ID.
// responses:
//   '200': { description: Project, schema: Project }

func (s *Server) getProject(w http.ResponseWriter, r *http.Request, p principal) error {
	id := r.PathValue("id")
	if err := s.allow(r, p, auth.PermProjectsRead, "project", id); err != nil {
		return err
	}
	row, err := s.Store.Q.GetProject(r.Context(), id)
	if err != nil {
		return fromStore(err, "project")
	}
	return ok(w, toProject(row))
}

// openapi:operation
// summary: Update project
// description: Updates a project's name or description.
// requestBody: { schema: UpdateProjectRequest }
// responses:
//   '200': { description: Updated project, schema: Project }

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request, p principal) error {
	id := r.PathValue("id")
	if err := s.allow(r, p, auth.PermProjectsWrite, "project", id); err != nil {
		return err
	}
	var in updateProjectRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	cur, err := s.Store.Q.GetProject(r.Context(), id)
	if err != nil {
		return fromStore(err, "project")
	}
	name := cur.Name
	if in.Name.Set {
		name = strings.TrimSpace(in.Name.V)
		if name == "" || len(name) > 100 {
			return badRequest("project name must be between 1 and 100 characters")
		}
	}
	desc := cur.Description
	if in.Description.Set {
		desc = in.Description.V
	}

	now := store.Now()
	if err := s.Store.Q.UpdateProject(r.Context(), db.UpdateProjectParams{
		ID:          id,
		Name:        name,
		Description: desc,
		Now:         now,
	}); err != nil {
		return fromStore(err, "project")
	}

	s.record(r, p, "project.update", "project", id, map[string]any{"name": name})
	s.changed(r, "project", id)

	cur, err = s.Store.Q.GetProject(r.Context(), id)
	if err != nil {
		return err
	}
	return ok(w, toProject(cur))
}

// openapi:operation
// summary: Delete project
// description: Deletes a project and its associated environments and secrets.
// responses:
//   '200': { description: Deleted project, schema: Project }

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request, p principal) error {
	id := r.PathValue("id")
	if err := s.allow(r, p, auth.PermProjectsWrite, "project", id); err != nil {
		return err
	}
	cur, err := s.Store.Q.GetProject(r.Context(), id)
	if err != nil {
		return fromStore(err, "project")
	}
	_ = s.Store.Q.DeleteObjectGrants(r.Context(), db.DeleteObjectGrantsParams{ObjectType: "project", ObjectID: id})
	n, err := s.Store.Q.DeleteProject(r.Context(), id)
	if err != nil {
		return fromStore(err, "project")
	}
	if n == 0 {
		return notFound("project")
	}
	s.record(r, p, "project.delete", "project", id, map[string]any{"name": cur.Name, "slug": cur.Slug})
	s.changed(r, "project", id)
	return ok(w, toProject(cur))
}

// openapi:operation
// summary: List project environments
// description: Returns all environments for a given project.
// responses:
//   '200': { description: List of environments, schema: { type: array, items: { $ref: '#/components/schemas/Environment' } } }

func (s *Server) listEnvironments(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	if err := s.allow(r, p, auth.PermEnvironmentsRead, "project", projectID); err != nil {
		return err
	}
	envs, err := s.Store.Q.ListEnvironmentsByProject(r.Context(), projectID)
	if err != nil {
		return err
	}
	out := make([]environmentDTO, 0, len(envs))
	for _, envRow := range envs {
		out = append(out, toEnvironment(envRow))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Create environment
// description: Creates a new environment in a project.
// requestBody: { schema: CreateEnvironmentRequest }
// responses:
//   '201': { description: Created environment, schema: Environment }

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	if err := s.allow(r, p, auth.PermEnvironmentsWrite, "project", projectID); err != nil {
		return err
	}
	// Verify project exists
	if _, err := s.Store.Q.GetProject(r.Context(), projectID); err != nil {
		return fromStore(err, "project")
	}

	var in createEnvironmentRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 50 {
		return badRequest("environment name must be between 1 and 50 characters")
	}
	slug := in.Slug
	if slug == "" {
		slug = slugify(name)
	}
	if !slugRegex.MatchString(slug) {
		return badRequest("slug must consist of lowercase letters, digits, and hyphens")
	}

	id := store.NewID()
	now := store.Now()
	if err := s.Store.Q.CreateEnvironment(r.Context(), db.CreateEnvironmentParams{
		ID:        id,
		ProjectID: projectID,
		Name:      name,
		Slug:      slug,
		Position:  in.Position,
		Now:       now,
	}); err != nil {
		return fromStore(err, "environment")
	}

	s.record(r, p, "environment.create", "environment", id, map[string]any{"project_id": projectID, "slug": slug})
	s.changed(r, "environment", id)

	row, err := s.Store.Q.GetEnvironment(r.Context(), id)
	if err != nil {
		return err
	}
	return created(w, toEnvironment(row))
}

// openapi:operation
// summary: Delete environment
// description: Deletes an environment.
// responses:
//   '200': { description: Deleted environment, schema: Environment }

func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envID := r.PathValue("env_id")
	if err := s.allow(r, p, auth.PermEnvironmentsWrite, "project", projectID); err != nil {
		return err
	}
	cur, err := s.Store.Q.GetEnvironment(r.Context(), envID)
	if err != nil {
		return fromStore(err, "environment")
	}
	if cur.ProjectID != projectID {
		return notFound("environment")
	}
	n, err := s.Store.Q.DeleteEnvironment(r.Context(), envID)
	if err != nil {
		return fromStore(err, "environment")
	}
	if n == 0 {
		return notFound("environment")
	}
	s.record(r, p, "environment.delete", "environment", envID, map[string]any{"slug": cur.Slug})
	s.changed(r, "environment", envID)
	return ok(w, toEnvironment(cur))
}

// Ensure context import is used
var _ = context.Background
