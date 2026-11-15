package auth

import (
	"context"
	"slices"
	"strings"
)

// Permissions are verb-free names, object.action. A role holds a list of
// them; PermAll grants everything.
const (
	PermAll               = "*"
	PermUsersManage       = "users.manage"
	PermAuditRead         = "audit.read"
	PermRolesManage       = "roles.manage"
	PermProjectsRead      = "projects.read"
	PermProjectsWrite     = "projects.write"
	PermEnvironmentsRead  = "environments.read"
	PermEnvironmentsWrite = "environments.write"
	PermSecretsRead       = "secrets.read"
	PermSecretsWrite      = "secrets.write"
	PermSystemManage      = "system.manage"
	// ducktpl:perms
)

// openapi:schema Permission
// type: object
// required: [name, description]
// properties:
//   name: { type: string }
//   description: { type: string }

type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Catalog lists every permission, for role editors.
var Catalog = []Permission{
	{PermUsersManage, "Manage users"},
	{PermAuditRead, "Read and verify the audit log"},
	{PermRolesManage, "Manage roles and their permissions"},
	{PermProjectsRead, "View projects"},
	{PermProjectsWrite, "Create, edit and delete projects"},
	{PermEnvironmentsRead, "View project environments"},
	{PermEnvironmentsWrite, "Create and manage project environments"},
	{PermSecretsRead, "Read and export secrets"},
	{PermSecretsWrite, "Create, update, rollback and delete secrets"},
	{PermSystemManage, "Manage system configuration and database migration"},
	// ducktpl:catalog
}

// BuiltinRoles are the roles a fresh database has. Without the rbac module
// they are the only ones; with it they are rows admins can edit (except
// admin, which always holds everything).
var BuiltinRoles = map[string][]string{
	"admin": {PermAll},
	"user": {
		PermProjectsRead, PermProjectsWrite,
		PermEnvironmentsRead, PermEnvironmentsWrite,
		PermSecretsRead, PermSecretsWrite,
		// ducktpl:user-perms
	},
}

// Has reports whether perms grant p.
func Has(perms []string, p string) bool {
	return slices.Contains(perms, PermAll) || slices.Contains(perms, p)
}

// Known reports whether p is in the catalog.
func Known(p string) bool {
	return p == PermAll || slices.ContainsFunc(Catalog, func(c Permission) bool { return c.Name == p })
}

// Permissions resolves a role's global permissions.
func (s *Service) Permissions(ctx context.Context, role string) ([]string, error) {
	r, err := s.Store.Q.GetRole(ctx, role)
	if err != nil {
		return nil, err
	}
	return strings.Fields(r.Permissions), nil
}
