package server

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// Access is two layers: a role's global permissions (roles table), and
// grants/policies on specific projects, environments, or objects.

// allow checks perm on one object: globally, through project_policies, or through grants.
func (s *Server) allow(r *http.Request, p principal, perm, objType, objID string) error {
	if objType == "project" {
		err := s.allowEnv(r, p, perm, objID, "")
		if err == nil {
			return nil
		}
		if p.ServiceToken != nil {
			return err
		}
		var ae *apiError
		if !errors.As(err, &ae) {
			return err
		}
		// allowEnv already evaluated project_policies and the 0-policies global
		// role fallback; only an explicit object grant may authorize past it.
		ok, gerr := s.Store.Q.HasGrant(r.Context(), db.HasGrantParams{
			ObjectType: objType, ObjectID: objID, Permission: perm, UserID: p.User.ID, Role: p.User.Role,
		})
		if gerr != nil {
			return gerr
		}
		if !ok {
			return err
		}
		return nil
	}
	if p.ServiceToken != nil {
		return forbidden("service tokens are scoped to projects")
	}
	if auth.Has(p.Perms, perm) {
		return nil
	}
	ok, err := s.Store.Q.HasGrant(r.Context(), db.HasGrantParams{
		ObjectType: objType, ObjectID: objID, Permission: perm, UserID: p.User.ID, Role: p.User.Role,
	})
	if err != nil {
		return err
	}
	if !ok {
		return forbidden("missing permission %s on this %s", perm, objType)
	}
	return nil
}

func policyGrantsPerm(pol db.ProjectPolicy, perm string) bool {
	switch perm {
	case auth.PermSecretsRead, auth.PermEnvironmentsRead, auth.PermProjectsRead:
		return pol.CanRead || pol.CanWrite || pol.CanAdmin
	case auth.PermSecretsWrite, auth.PermEnvironmentsWrite:
		return pol.CanWrite || pol.CanAdmin
	default:
		return pol.CanAdmin
	}
}

// allowWildcardEnv checks whether the caller holds perm across all environments ("*") of a project.
func (s *Server) allowWildcardEnv(r *http.Request, p principal, perm, projectID string) error {
	if p.ServiceToken != nil {
		return forbidden("service tokens cannot grant wildcard access")
	}
	if auth.Has(p.Perms, auth.PermAll) {
		return nil
	}
	now := store.Now()
	policies, err := s.Store.Q.ActivePoliciesForUserOnProject(r.Context(), db.ActivePoliciesForUserOnProjectParams{
		ProjectID:   projectID,
		SubjectID:   p.User.ID,
		SubjectID_2: p.User.Role,
		StartsAt:    sql.NullTime{Time: now, Valid: true},
	})
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		allPols, err := s.Store.Q.ListProjectPolicies(r.Context(), projectID)
		if err == nil && len(allPols) == 0 && auth.Has(p.Perms, perm) {
			return nil
		}
		return forbidden("not authorized for wildcard environment in project %s", projectID)
	}
	for _, pol := range policies {
		if pol.EnvironmentSlug == "*" && policyGrantsPerm(pol, perm) {
			return nil
		}
	}
	return forbidden("missing wildcard permission %s for project %s", perm, projectID)
}

// allowEnv checks permission on a specific project and optional environment.
func (s *Server) allowEnv(r *http.Request, p principal, perm, projectID, envSlug string) error {
	if p.ServiceToken != nil {
		if !auth.Has(p.Perms, perm) {
			return forbidden("service token lacks permission %s", perm)
		}
		if p.ServiceToken.ProjectID != projectID {
			return forbidden("service token is not authorized for project %s", projectID)
		}
		if envSlug != "" && p.ServiceToken.EnvironmentSlug != "*" && p.ServiceToken.EnvironmentSlug != envSlug {
			return forbidden("service token is not authorized for environment %s", envSlug)
		}
		return nil
	}

	// Global superadmin always has access
	if auth.Has(p.Perms, auth.PermAll) {
		return nil
	}

	now := store.Now()
	policies, err := s.Store.Q.ActivePoliciesForUserOnProject(r.Context(), db.ActivePoliciesForUserOnProjectParams{
		ProjectID:   projectID,
		SubjectID:   p.User.ID,
		SubjectID_2: p.User.Role,
		StartsAt:    sql.NullTime{Time: now, Valid: true},
	})
	if err != nil {
		return err
	}

	if len(policies) == 0 {
		// If project has no policies defined yet, fallback to global role permissions
		allPols, err := s.Store.Q.ListProjectPolicies(r.Context(), projectID)
		if err == nil && len(allPols) == 0 && auth.Has(p.Perms, perm) {
			return nil
		}
		return forbidden("not authorized for project %s", projectID)
	}

	for _, pol := range policies {
		if pol.EnvironmentSlug != "*" && envSlug != "" && pol.EnvironmentSlug != envSlug {
			continue
		}
		if policyGrantsPerm(pol, perm) {
			return nil
		}
	}

	if envSlug != "" {
		return forbidden("missing permission %s for environment %s in project %s", perm, envSlug, projectID)
	}
	return forbidden("missing permission %s for project %s", perm, projectID)
}

// visible reports which objects of a type the caller may see: all of them,
// or only those in ids.
func (s *Server) visible(r *http.Request, p principal, perm, objType string) (all bool, ids map[string]bool, err error) {
	if auth.Has(p.Perms, auth.PermAll) {
		return true, nil, nil
	}
	if objType == "project" {
		now := store.Now()
		pids, err := s.Store.Q.ListProjectIDsWithAccessForUser(r.Context(), db.ListProjectIDsWithAccessForUserParams{
			SubjectID:   p.User.ID,
			SubjectID_2: p.User.Role,
			StartsAt:    sql.NullTime{Time: now, Valid: true},
		})
		if err != nil {
			return false, nil, err
		}
		ids = make(map[string]bool, len(pids))
		for _, id := range pids {
			ids[id] = true
		}
		// Also include any generic grants on project
		genericGrants, err := s.Store.Q.GrantedObjects(r.Context(), db.GrantedObjectsParams{ObjectType: objType, Permission: perm, UserID: p.User.ID, Role: p.User.Role})
		if err == nil {
			for _, id := range genericGrants {
				ids[id] = true
			}
		}
		// If user has global PermProjectsRead, also allow projects that have no policies defined yet
		if auth.Has(p.Perms, perm) {
			allProjects, err := s.Store.Q.ListProjects(r.Context())
			if err == nil {
				for _, prj := range allProjects {
					pols, _ := s.Store.Q.ListProjectPolicies(r.Context(), prj.ID)
					if len(pols) == 0 {
						ids[prj.ID] = true
					}
				}
			}
		}
		return false, ids, nil
	}
	list, err := s.Store.Q.GrantedObjects(r.Context(), db.GrantedObjectsParams{ObjectType: objType, Permission: perm, UserID: p.User.ID, Role: p.User.Role})
	if err != nil {
		return false, nil, err
	}
	ids = make(map[string]bool, len(list))
	for _, id := range list {
		ids[id] = true
	}
	return false, ids, nil
}

// openapi:operation
// summary: Permission catalog
// tags: [roles]
// responses:
//   '200': { description: Every permission a role or grant can hold, schema: '[]Permission' }

func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request, p principal) error {
	return ok(w, auth.Catalog)
}

// openapi:schema Role
// type: object
// required: [name, description, permissions, builtin]
// properties:
//   name: { type: string }
//   description: { type: string }
//   permissions: { type: array, items: { type: string } }
//   builtin: { type: boolean, description: Builtin roles cannot be deleted; admin cannot be changed. }

type roleDTO struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Builtin     bool     `json:"builtin"`
}

func toRole(r db.Role) roleDTO {
	return roleDTO{Name: r.Name, Description: r.Description, Permissions: append([]string{}, strings.Fields(r.Permissions)...), Builtin: r.Builtin}
}

var roleNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func checkPerms(perms []string) (string, error) {
	for _, p := range perms {
		if !auth.Known(p) {
			return "", badRequest("unknown permission %q", p)
		}
	}
	return strings.Join(perms, " "), nil
}

// openapi:operation
// summary: List roles
// tags: [roles]
// responses:
//   '200': { description: All roles, schema: '[]Role' }

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request, p principal) error {
	rs, err := s.Store.Q.ListRoles(r.Context())
	if err != nil {
		return err
	}
	out := make([]roleDTO, 0, len(rs))
	for _, x := range rs {
		out = append(out, toRole(x))
	}
	return ok(w, out)
}

// openapi:schema CreateRoleRequest
// type: object
// required: [name, permissions]
// additionalProperties: false
// properties:
//   name: { type: string, pattern: '^[a-z][a-z0-9_-]{0,31}$' }
//   description: { type: string }
//   permissions: { type: array, items: { type: string } }

type createRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// openapi:operation
// summary: Create a role
// tags: [roles]
// requestBody: { schema: CreateRoleRequest }
// responses:
//   '201': { description: Created, schema: Role }
//   '409': Error

func (s *Server) createRole(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req createRoleRequest) (roleDTO, error) {
		if !roleNameRe.MatchString(req.Name) {
			return roleDTO{}, badRequest("role name: lowercase letters, digits, dash and underscore")
		}
		perms, err := checkPerms(req.Permissions)
		if err != nil {
			return roleDTO{}, err
		}
		if err := s.Store.Q.CreateRole(r.Context(), db.CreateRoleParams{Name: req.Name, Description: req.Description, Permissions: perms}); err != nil {
			return roleDTO{}, fromStore(err, "role")
		}
		s.record(r, p, "role.create", "role", req.Name, map[string]any{"permissions": req.Permissions})
		return toRole(db.Role{Name: req.Name, Description: req.Description, Permissions: perms}), nil
	})
}

// openapi:schema UpdateRoleRequest
// type: object
// additionalProperties: false
// properties:
//   description: { type: string }
//   permissions: { type: array, items: { type: string } }

type updateRoleRequest struct {
	Description opt[string]   `json:"description"`
	Permissions opt[[]string] `json:"permissions"`
}

// openapi:operation
// summary: Update a role
// tags: [roles]
// requestBody: { schema: UpdateRoleRequest }
// responses:
//   '200': { description: Updated, schema: Role }

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleAction(w, r, func(req updateRoleRequest) (roleDTO, error) {
		name := r.PathValue("name")
		cur, err := s.Store.Q.GetRole(r.Context(), name)
		if err != nil {
			return roleDTO{}, fromStore(err, "role")
		}
		if name == "admin" && req.Permissions.Set {
			return roleDTO{}, conflict("admin always holds every permission")
		}
		if req.Description.Set {
			cur.Description = req.Description.V
		}
		if req.Permissions.Set {
			if cur.Permissions, err = checkPerms(req.Permissions.V); err != nil {
				return roleDTO{}, err
			}
		}
		if err := s.Store.Q.UpdateRole(r.Context(), db.UpdateRoleParams{Name: name, Description: cur.Description, Permissions: cur.Permissions}); err != nil {
			return roleDTO{}, err
		}
		s.record(r, p, "role.update", "role", name, map[string]any{"permissions": strings.Fields(cur.Permissions)})
		return toRole(cur), nil
	})
}

// openapi:operation
// summary: Delete a role
// description: Only roles nobody holds, and never a builtin one.
// tags: [roles]
// responses:
//   '204': { description: Deleted }
//   '409': Error

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request, p principal) error {
	name := r.PathValue("name")
	return handleCommand(w, func() error {
		cur, err := s.Store.Q.GetRole(r.Context(), name)
		if err != nil {
			return fromStore(err, "role")
		}
		if cur.Builtin {
			return conflict("builtin roles cannot be deleted")
		}
		if n, err := s.Store.Q.CountRoleUsers(r.Context(), name); err != nil || n > 0 {
			if err != nil {
				return err
			}
			return conflict("%d user(s) hold this role", n)
		}
		if _, err := s.Store.Q.DeleteRole(r.Context(), name); err != nil {
			return err
		}
		s.record(r, p, "role.delete", "role", name, nil)
		return nil
	})
}

// openapi:schema Grant
// type: object
// required: [id, subject_type, subject_id, object_type, object_id, permission, created_at]
// properties:
//   id: { type: string, format: uuid }
//   subject_type: { type: string, enum: [user, role] }
//   subject_id: { type: string, description: User id or role name. }
//   object_type: { type: string, enum: [project] }
//   object_id: { type: string }
//   permission: { type: string }
//   created_at: { type: string, format: date-time }

type grantDTO struct {
	ID          string    `json:"id"`
	SubjectType string    `json:"subject_type"`
	SubjectID   string    `json:"subject_id"`
	ObjectType  string    `json:"object_type"`
	ObjectID    string    `json:"object_id"`
	Permission  string    `json:"permission"`
	CreatedAt   time.Time `json:"created_at"`
}

func toGrant(g db.Grant) grantDTO {
	return grantDTO{ID: g.ID, SubjectType: g.SubjectType, SubjectID: g.SubjectID, ObjectType: g.ObjectType, ObjectID: g.ObjectID,
		Permission: g.Permission, CreatedAt: g.CreatedAt.UTC()}
}

// objectPerms says which permissions apply to each grantable object type,
// and the permission needed to see one. Add your resources here.
var objectPerms = map[string][]string{
	"project": {auth.PermProjectsRead, auth.PermProjectsWrite},
	// ducktpl:objects
}

// openapi:operation
// summary: List the grants on an object
// description: You see the grants of objects you may write.
// tags: [grants]
// parameters:
//   - { name: object_type, in: query, required: true, schema: { type: string } }
//   - { name: object_id, in: query, required: true, schema: { type: string } }
// responses:
//   '200': { description: Grants, schema: '[]Grant' }

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request, p principal) error {
	ot, oid := r.URL.Query().Get("object_type"), r.URL.Query().Get("object_id")
	perms, known := objectPerms[ot]
	if !known || oid == "" {
		return badRequest("object_type and object_id are required")
	}
	if err := s.allow(r, p, perms[len(perms)-1], ot, oid); err != nil {
		return err
	}
	gs, err := s.Store.Q.ListGrants(r.Context(), db.ListGrantsParams{ObjectType: ot, ObjectID: oid})
	if err != nil {
		return err
	}
	out := make([]grantDTO, 0, len(gs))
	for _, g := range gs {
		out = append(out, toGrant(g))
	}
	return ok(w, out)
}

// openapi:schema CreateGrantRequest
// type: object
// required: [subject_type, subject_id, object_type, object_id, permission]
// additionalProperties: false
// properties:
//   subject_type: { type: string, enum: [user, role] }
//   subject_id: { type: string }
//   object_type: { type: string, enum: [project] }
//   object_id: { type: string }
//   permission: { type: string }

type createGrantRequest struct {
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	ObjectType  string `json:"object_type"`
	ObjectID    string `json:"object_id"`
	Permission  string `json:"permission"`
}

// openapi:operation
// summary: Grant a permission on an object
// description: You can only pass on a permission you hold on that object.
// tags: [grants]
// requestBody: { schema: CreateGrantRequest }
// responses:
//   '201': { description: Created, schema: Grant }
//   '409': Error

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req createGrantRequest) (grantDTO, error) {
		perms, known := objectPerms[req.ObjectType]
		if !known {
			return grantDTO{}, badRequest("objects of type %q cannot be granted", req.ObjectType)
		}
		valid := false
		for _, x := range perms {
			valid = valid || x == req.Permission
		}
		if !valid {
			return grantDTO{}, badRequest("permission %q does not apply to %s", req.Permission, req.ObjectType)
		}
		if err := s.allow(r, p, req.Permission, req.ObjectType, req.ObjectID); err != nil {
			return grantDTO{}, err
		}
		switch req.SubjectType {
		case "user":
			if _, err := s.Store.Q.GetUser(r.Context(), req.SubjectID); err != nil {
				return grantDTO{}, fromStore(err, "user")
			}
		case "role":
			if _, err := s.Store.Q.GetRole(r.Context(), req.SubjectID); err != nil {
				return grantDTO{}, fromStore(err, "role")
			}
		default:
			return grantDTO{}, badRequest("subject_type must be user or role")
		}
		g := db.Grant{ID: store.NewID(), SubjectType: req.SubjectType, SubjectID: req.SubjectID, ObjectType: req.ObjectType,
			ObjectID: req.ObjectID, Permission: req.Permission, CreatedAt: store.Now()}
		err := s.Store.Q.CreateGrant(r.Context(), db.CreateGrantParams{ID: g.ID, SubjectType: g.SubjectType, SubjectID: g.SubjectID,
			ObjectType: g.ObjectType, ObjectID: g.ObjectID, Permission: g.Permission, Now: g.CreatedAt})
		if err != nil {
			return grantDTO{}, fromStore(err, "grant")
		}
		s.record(r, p, "grant.create", g.ObjectType, g.ObjectID, map[string]any{"subject": g.SubjectType + ":" + g.SubjectID, "permission": g.Permission})
		return toGrant(g), nil
	})
}

// openapi:operation
// summary: Revoke a grant
// tags: [grants]
// responses:
//   '204': { description: Revoked }

func (s *Server) deleteGrant(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		g, err := s.Store.Q.GetGrant(r.Context(), r.PathValue("id"))
		if err != nil {
			return fromStore(err, "grant")
		}
		if err := s.allow(r, p, g.Permission, g.ObjectType, g.ObjectID); err != nil {
			return err
		}
		if _, err := s.Store.Q.DeleteGrant(r.Context(), g.ID); err != nil {
			return err
		}
		s.record(r, p, "grant.delete", g.ObjectType, g.ObjectID, map[string]any{"subject": g.SubjectType + ":" + g.SubjectID, "permission": g.Permission})
		return nil
	})
}
