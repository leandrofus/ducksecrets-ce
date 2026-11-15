// Package server exposes the REST API (/api/v1) and serves the embedded UI.
//
// Every route is registered in Handler with its access rule; cmd/openapi-gen
// reads them from here, so the contract (openapi/openapi.yaml) always says
// who may call what.
package server

import (
	"net/http"
	"net/netip"

	"github.com/leandrofus/ducksecrets/gateway/internal/audit"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/events"
	"github.com/leandrofus/ducksecrets/gateway/internal/license"
	"github.com/leandrofus/ducksecrets/gateway/internal/sites"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/tlsutil"
)

type Server struct {
	Store   *store.Store
	Auth    *auth.Service
	Audit   *audit.Log
	Events  *events.Bus
	Vault   *crypto.Vault
	Sites   *sites.Manager
	License *license.Manager
	TLS     *tlsutil.Manager
	// TrustedProxies are the reverse proxies in front of the gateway. Requests
	// from them are attributed to the address in X-Forwarded-For (the last
	// one not itself a trusted proxy), and their X-Forwarded-Proto counts.
	TrustedProxies []netip.Prefix
	// SecureCookies forces the Secure flag on cookies, for TLS terminated
	// before the gateway by a proxy not listed as trusted.
	SecureCookies bool
	// AllowScripts enables host-side execution for rotation "script" verifiers
	// and PAM "local"/"command" dynamic providers (off by default to prevent RCE).
	AllowScripts bool
	// AllowPrivateProbes permits http_probe and tcp_probe rotation verifiers
	// to connect to loopback, link-local, or RFC1918 private addresses.
	AllowPrivateProbes bool
	// PublicURL overrides Host-header inference in /install.sh when set.
	PublicURL    string
	Version      string
	DefaultAdmin string
	// Self-update overrides (default: leandrofus/ducksecrets-ce on GitHub).
	UpdateRepo       string
	UpdateAPIBase    string
	UpdateTargetPath string

	limiter *auth.Limiter
}

func (s *Server) Handler() http.Handler {
	if s.limiter == nil {
		s.limiter = auth.NewLimiter()
	}
	if s.Sites == nil {
		s.Sites = sites.New()
	}
	if s.License == nil {
		s.License = license.MustManager()
	}
	mux := http.NewServeMux()
	mux.Handle("/", s.static())

	mux.Handle("GET /api/v1/health", s.public(s.health))

	// Client CLI Distribution & Installer
	mux.Handle("GET /download/ducksecrets", s.public(s.downloadCLI))
	mux.Handle("GET /api/v1/download/ducksecrets", s.public(s.downloadCLI))
	mux.Handle("GET /install.sh", s.public(s.installScript))
	mux.Handle("GET /api/v1/install.sh", s.public(s.installScript))

	mux.Handle("GET /api/v1/auth/setup", s.public(s.setupStatus))
	mux.Handle("POST /api/v1/auth/setup", s.public(s.completeSetup))
	mux.Handle("POST /api/v1/auth/login", s.public(s.login))
	mux.Handle("POST /api/v1/auth/logout", s.userSignedIn(s.logout))
	mux.Handle("GET /api/v1/auth/me", s.userSignedIn(s.me))
	mux.Handle("PUT /api/v1/auth/me/password", s.userSignedIn(s.changePassword))

	mux.Handle("GET /api/v1/users", s.userCan(auth.PermUsersManage, s.listUsers))
	mux.Handle("POST /api/v1/users", s.userCan(auth.PermUsersManage, s.createUser))
	mux.Handle("PATCH /api/v1/users/{id}", s.userCan(auth.PermUsersManage, s.updateUser))
	mux.Handle("DELETE /api/v1/users/{id}", s.userCan(auth.PermUsersManage, s.deleteUser))
	mux.Handle("PUT /api/v1/users/{id}/password", s.userCan(auth.PermUsersManage, s.resetPassword))

	mux.Handle("GET /api/v1/permissions", s.userSignedIn(s.listPermissions))
	mux.Handle("GET /api/v1/roles", s.userSignedIn(s.listRoles))
	mux.Handle("POST /api/v1/roles", s.userCan(auth.PermRolesManage, s.createRole))
	mux.Handle("PATCH /api/v1/roles/{name}", s.userCan(auth.PermRolesManage, s.updateRole))
	mux.Handle("DELETE /api/v1/roles/{name}", s.userCan(auth.PermRolesManage, s.deleteRole))
	mux.Handle("GET /api/v1/grants", s.userSignedIn(s.listGrants))
	mux.Handle("POST /api/v1/grants", s.userSignedIn(s.createGrant))
	mux.Handle("DELETE /api/v1/grants/{id}", s.userSignedIn(s.deleteGrant))

	mux.Handle("GET /api/v1/audit", s.userCan(auth.PermAuditRead, s.listAudit))
	mux.Handle("GET /api/v1/audit/verify", s.userCan(auth.PermAuditRead, s.verifyAudit))

	mux.Handle("GET /api/v1/ws", s.userSignedIn(s.websocket))

	mux.Handle("GET /api/v1/projects", s.userSignedIn(s.listProjects))
	mux.Handle("POST /api/v1/projects", s.userCan(auth.PermProjectsWrite, s.createProject))
	mux.Handle("GET /api/v1/projects/{id}", s.signedIn(s.getProject))
	mux.Handle("PATCH /api/v1/projects/{id}", s.signedIn(s.updateProject))
	mux.Handle("DELETE /api/v1/projects/{id}", s.signedIn(s.deleteProject))

	mux.Handle("GET /api/v1/projects/{id}/environments", s.can(auth.PermEnvironmentsRead, s.listEnvironments))
	mux.Handle("POST /api/v1/projects/{id}/environments", s.can(auth.PermEnvironmentsWrite, s.createEnvironment))
	mux.Handle("DELETE /api/v1/projects/{id}/environments/{env_id}", s.can(auth.PermEnvironmentsWrite, s.deleteEnvironment))

	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/secrets", s.can(auth.PermSecretsRead, s.listSecrets))
	mux.Handle("POST /api/v1/projects/{id}/environments/{env_slug}/secrets", s.can(auth.PermSecretsWrite, s.createSecret))
	mux.Handle("POST /api/v1/projects/{id}/environments/{env_slug}/secrets/import", s.can(auth.PermSecretsWrite, s.importSecrets))
	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/secrets/export", s.can(auth.PermSecretsRead, s.exportSecrets))
	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/secrets/{secret_id}", s.can(auth.PermSecretsRead, s.getSecret))
	mux.Handle("PATCH /api/v1/projects/{id}/environments/{env_slug}/secrets/{secret_id}", s.can(auth.PermSecretsWrite, s.updateSecret))
	mux.Handle("DELETE /api/v1/projects/{id}/environments/{env_slug}/secrets/{secret_id}", s.can(auth.PermSecretsWrite, s.deleteSecret))
	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/secrets/{secret_id}/versions", s.can(auth.PermSecretsRead, s.listSecretVersions))
	mux.Handle("POST /api/v1/projects/{id}/environments/{env_slug}/secrets/{secret_id}/rollback", s.can(auth.PermSecretsWrite, s.rollbackSecret))

	mux.Handle("GET /api/v1/system/database", s.userCan(auth.PermSystemManage, s.getDatabaseInfo))
	mux.Handle("POST /api/v1/system/database/test", s.userCan(auth.PermSystemManage, s.testDatabase))
	mux.Handle("POST /api/v1/system/database/migrate", s.userCan(auth.PermSystemManage, s.migrateDatabase))
	mux.Handle("GET /api/v1/system/license", s.userSignedIn(s.getLicenseStatus))
	mux.Handle("PUT /api/v1/system/license", s.userCan(auth.PermSystemManage, s.updateLicense))
	mux.Handle("DELETE /api/v1/system/license", s.userCan(auth.PermSystemManage, s.deleteLicense))
	mux.Handle("GET /api/v1/system/update", s.userCan(auth.PermSystemManage, s.getUpdateStatus))
	mux.Handle("POST /api/v1/system/update", s.userCan(auth.PermSystemManage, s.applySystemUpdate))
	mux.Handle("GET /api/v1/system/tls", s.userCan(auth.PermSystemManage, s.getTLSStatus))
	mux.Handle("PUT /api/v1/system/tls", s.userCan(auth.PermSystemManage, s.uploadCustomTLS))
	mux.Handle("POST /api/v1/system/tls/self-signed", s.userCan(auth.PermSystemManage, s.regenerateSelfSignedTLS))
	mux.Handle("DELETE /api/v1/system/tls", s.userCan(auth.PermSystemManage, s.resetCustomTLS))

	mux.Handle("GET /api/v1/projects/{id}/tokens", s.can(auth.PermProjectsRead, s.listTokens))
	mux.Handle("POST /api/v1/projects/{id}/tokens", s.can(auth.PermProjectsWrite, s.createToken))
	mux.Handle("DELETE /api/v1/projects/{id}/tokens/{token_id}", s.can(auth.PermProjectsWrite, s.deleteToken))

	mux.Handle("GET /api/v1/projects/{id}/policies", s.can(auth.PermProjectsRead, s.listProjectPolicies))
	mux.Handle("POST /api/v1/projects/{id}/policies", s.can(auth.PermProjectsWrite, s.createProjectPolicy))
	mux.Handle("PUT /api/v1/projects/{id}/policies/{policy_id}", s.can(auth.PermProjectsWrite, s.updateProjectPolicy))
	mux.Handle("DELETE /api/v1/projects/{id}/policies/{policy_id}", s.can(auth.PermProjectsWrite, s.deleteProjectPolicy))

	mux.Handle("POST /api/v1/shares", s.public(s.createShare))
	mux.Handle("GET /api/v1/shares", s.userSignedIn(s.listMyShares))
	mux.Handle("GET /api/v1/shares/{id}", s.public(s.getShareMetadata))
	mux.Handle("POST /api/v1/shares/{id}/reveal", s.public(s.revealShare))
	mux.Handle("DELETE /api/v1/shares/{id}", s.userSignedIn(s.deleteShare))

	// Dynamic Secret Providers & Leases
	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/dynamic", s.can(auth.PermSecretsRead, s.listDynamicProviders))
	mux.Handle("POST /api/v1/projects/{id}/environments/{env_slug}/dynamic", s.can(auth.PermSecretsWrite, s.createDynamicProvider))
	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/dynamic/{provider_id}", s.can(auth.PermSecretsRead, s.getDynamicProvider))
	mux.Handle("DELETE /api/v1/projects/{id}/environments/{env_slug}/dynamic/{provider_id}", s.can(auth.PermSecretsWrite, s.deleteDynamicProvider))
	mux.Handle("POST /api/v1/projects/{id}/environments/{env_slug}/dynamic/{provider_id}/test", s.can(auth.PermSecretsWrite, s.testDynamicProvider))
	mux.Handle("POST /api/v1/projects/{id}/environments/{env_slug}/dynamic/{provider_id}/lease", s.can(auth.PermSecretsRead, s.issueDynamicLease))
	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/dynamic/{provider_id}/leases", s.can(auth.PermSecretsRead, s.listDynamicLeases))
	mux.Handle("DELETE /api/v1/projects/{id}/environments/{env_slug}/dynamic/{provider_id}/leases/{lease_id}", s.can(auth.PermSecretsWrite, s.revokeDynamicLease))
	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/dynamic/{provider_id}/tunnel", s.can(auth.PermSecretsRead, s.tunnelDynamicConnection))

	// Network Sites (Reverse Tunnel Gateways)
	mux.Handle("GET /api/v1/projects/{id}/sites", s.can(auth.PermSecretsRead, s.listSites))
	mux.Handle("POST /api/v1/projects/{id}/sites", s.can(auth.PermSecretsWrite, s.createSite))
	mux.Handle("DELETE /api/v1/projects/{id}/sites/{site_id}", s.can(auth.PermSecretsWrite, s.deleteSite))
	mux.Handle("GET /api/v1/sites/{site_id}/connect", s.public(s.connectSite))
	mux.Handle("GET /api/v1/sites/{site_id}/streams/{stream_id}", s.public(s.connectStream))

	// Automated Secret Rotation Policies
	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/rotation", s.can(auth.PermSecretsRead, s.listRotationPolicies))
	mux.Handle("GET /api/v1/projects/{id}/environments/{env_slug}/secrets/{secret_id}/rotation", s.can(auth.PermSecretsRead, s.getRotationPolicy))
	mux.Handle("POST /api/v1/projects/{id}/environments/{env_slug}/secrets/{secret_id}/rotation", s.can(auth.PermSecretsWrite, s.setRotationPolicy))
	mux.Handle("DELETE /api/v1/projects/{id}/environments/{env_slug}/secrets/{secret_id}/rotation", s.can(auth.PermSecretsWrite, s.deleteRotationPolicy))
	mux.Handle("POST /api/v1/projects/{id}/environments/{env_slug}/secrets/{secret_id}/rotation/run", s.can(auth.PermSecretsWrite, s.runRotationNow))

	// ducktpl:routes (npx ducktpl add <resource> inserts above)

	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, notFound("route"))
	}))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
