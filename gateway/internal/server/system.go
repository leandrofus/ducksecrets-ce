package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/license"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// openapi:schema DatabaseInfo
// type: object
// required: [engine, can_migrate, is_postgres]
// properties:
//   engine: { type: string }
//   can_migrate: { type: boolean }
//   is_postgres: { type: boolean }

type databaseInfoDTO struct {
	Engine     string `json:"engine"`
	CanMigrate bool   `json:"can_migrate"`
	IsPostgres bool   `json:"is_postgres"`
}

// openapi:schema TestDatabaseRequest
// type: object
// required: [postgres_url]
// additionalProperties: false
// properties:
//   postgres_url: { type: string, minLength: 10 }

type testDatabaseRequest struct {
	PostgresURL string `json:"postgres_url"`
}

// openapi:schema TestDatabaseResponse
// type: object
// required: [ok, message]
// properties:
//   ok: { type: boolean }
//   message: { type: string }

type testDatabaseResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// openapi:schema MigrateDatabaseRequest
// type: object
// required: [postgres_url]
// additionalProperties: false
// properties:
//   postgres_url: { type: string, minLength: 10 }

type migrateDatabaseRequest struct {
	PostgresURL string `json:"postgres_url"`
}

// openapi:schema MigrateDatabaseResponse
// type: object
// required: [ok, total_rows, message]
// properties:
//   ok: { type: boolean }
//   total_rows: { type: integer }
//   message: { type: string }

type migrateDatabaseResponse struct {
	OK        bool   `json:"ok"`
	TotalRows int64  `json:"total_rows"`
	Message   string `json:"message"`
}

// openapi:operation
// summary: Get database info
// description: Returns the active database engine (SQLite or PostgreSQL) and migration readiness.
// responses:
//   '200': { description: Database engine info, schema: DatabaseInfo }

func (s *Server) getDatabaseInfo(w http.ResponseWriter, r *http.Request, p principal) error {
	isPG := s.Store.IsPostgresDB()
	engine := "sqlite"
	if isPG {
		engine = "postgres"
	}
	return ok(w, databaseInfoDTO{
		Engine:     engine,
		CanMigrate: !isPG,
		IsPostgres: isPG,
	})
}

// openapi:operation
// summary: Test PostgreSQL connection
// description: Tests connectivity to a target PostgreSQL database for migration.
// requestBody: { schema: TestDatabaseRequest }
// responses:
//   '200': { description: Test result, schema: TestDatabaseResponse }

func (s *Server) testDatabase(w http.ResponseWriter, r *http.Request, p principal) error {
	var in testDatabaseRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	url := strings.TrimSpace(in.PostgresURL)
	if url == "" {
		return badRequest("postgres_url cannot be empty")
	}

	if err := store.TestPostgresConnection(r.Context(), url); err != nil {
		return badRequest("connection failed: %v", err)
	}

	return ok(w, testDatabaseResponse{
		OK:      true,
		Message: "Connection successful. Target PostgreSQL is reachable and ready.",
	})
}

// openapi:operation
// summary: Migrate to PostgreSQL
// description: Migrates all application data from SQLite to PostgreSQL and hot-swaps the database connection.
// requestBody: { schema: MigrateDatabaseRequest }
// responses:
//   '200': { description: Migration result, schema: MigrateDatabaseResponse }

func (s *Server) migrateDatabase(w http.ResponseWriter, r *http.Request, p principal) error {
	var in migrateDatabaseRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	url := strings.TrimSpace(in.PostgresURL)
	if url == "" {
		return badRequest("postgres_url cannot be empty")
	}

	report, err := s.Store.MigrateToPostgres(r.Context(), url)
	if err != nil {
		return badRequest("migration failed: %v", err)
	}

	s.record(r, p, "system.database_migrated", "system", "database", map[string]any{
		"engine":     "postgres",
		"total_rows": report.TotalRows,
	})

	return ok(w, migrateDatabaseResponse{
		OK:        true,
		TotalRows: report.TotalRows,
		Message:   fmt.Sprintf("Successfully migrated %d rows across %d tables to PostgreSQL. Connection hot-swapped.", report.TotalRows, len(report.Tables)),
	})
}

const licenseSettingKey = "license_token"

// openapi:schema LicenseFeature
// type: object
// required: [id, name, min_edition, description, enabled]
// properties:
//   id: { type: string }
//   name: { type: string }
//   min_edition: { type: string }
//   description: { type: string }
//   enabled: { type: boolean }

// openapi:schema LicenseStatus
// type: object
// required: [edition, valid, expired, max_sites, used_sites, max_users, features, catalog, source]
// properties:
//   edition: { type: string }
//   licensed_edition: { type: string }
//   valid: { type: boolean }
//   expired: { type: boolean }
//   customer: { type: string }
//   org: { type: string }
//   license_id: { type: string }
//   max_sites: { type: integer }
//   used_sites: { type: integer }
//   max_users: { type: integer }
//   features: { type: array, items: { type: string } }
//   catalog: { type: array, items: { $ref: '#/components/schemas/LicenseFeature' } }
//   source: { type: string }
//   issued_at: { type: string, format: date-time }
//   expires_at: { type: string, format: date-time }
//   error: { type: string }

type licenseStatusDTO struct {
	Edition         string                `json:"edition"`
	LicensedEdition string                `json:"licensed_edition,omitempty"`
	Valid           bool                  `json:"valid"`
	Expired         bool                  `json:"expired"`
	Customer        string                `json:"customer,omitempty"`
	Org             string                `json:"org,omitempty"`
	LicenseID       string                `json:"license_id,omitempty"`
	MaxSites        int                   `json:"max_sites"`
	UsedSites       int64                 `json:"used_sites"`
	MaxUsers        int                   `json:"max_users"`
	Features        []string              `json:"features"`
	Catalog         []license.FeatureInfo `json:"catalog"`
	Source          string                `json:"source"`
	IssuedAt        *time.Time            `json:"issued_at,omitempty"`
	ExpiresAt       *time.Time            `json:"expires_at,omitempty"`
	Error           string                `json:"error,omitempty"`
}

// openapi:schema UpdateLicenseRequest
// type: object
// required: [token]
// additionalProperties: false
// properties:
//   token: { type: string, minLength: 10 }

type updateLicenseRequest struct {
	Token string `json:"token"`
}

func (s *Server) licenseMgr() *license.Manager {
	if s.License == nil {
		s.License = license.MustManager()
	}
	return s.License
}

func (s *Server) buildLicenseDTO(r *http.Request, p principal, st license.Status) (licenseStatusDTO, error) {
	usedSites, err := s.Store.Q.CountAllSites(r.Context())
	if err != nil {
		return licenseStatusDTO{}, fmt.Errorf("counting sites: %w", err)
	}
	dto := licenseStatusDTO{
		Edition:         st.Edition,
		LicensedEdition: st.LicensedEdition,
		Valid:           st.Valid,
		Expired:         st.Expired,
		MaxSites:        st.MaxSites,
		UsedSites:       usedSites,
		MaxUsers:        st.MaxUsers,
		Features:        st.Features,
		Catalog:         st.Catalog,
		Source:          st.Source,
		IssuedAt:        st.IssuedAt,
		ExpiresAt:       st.ExpiresAt,
		Error:           st.Error,
	}
	if p.User.ID != "" && auth.Has(p.Perms, auth.PermSystemManage) {
		dto.Customer = st.Customer
		dto.Org = st.Org
		dto.LicenseID = st.LicenseID
	}
	return dto, nil
}

// openapi:operation
// summary: Get Open-Core license status
// description: Returns the active edition (community, pro, business), site quota, and commercial feature flags.
// responses:
//   '200': { description: Active license status, schema: LicenseStatus }

func (s *Server) getLicenseStatus(w http.ResponseWriter, r *http.Request, p principal) error {
	dto, err := s.buildLicenseDTO(r, p, s.licenseMgr().Status())
	if err != nil {
		return err
	}
	return ok(w, dto)
}

// openapi:operation
// summary: Activate offline license key
// description: Verifies an offline Ed25519 commercial license token (dkl1...) and persists it.
// requestBody: { schema: UpdateLicenseRequest }
// responses:
//   '200': { description: Activated license status, schema: LicenseStatus }

func (s *Server) updateLicense(w http.ResponseWriter, r *http.Request, p principal) error {
	mgr := s.licenseMgr()
	if mgr.Status().Source == "env" {
		return conflict("%v", license.ErrManagedByConfig)
	}
	var in updateLicenseRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	tok := strings.TrimSpace(in.Token)
	if tok == "" {
		return badRequest("license token is required")
	}
	st, err := mgr.Activate(tok, "database")
	if err != nil {
		return badRequest("invalid license: %v", err)
	}
	if err := s.Store.Q.UpsertSystemSetting(r.Context(), db.UpsertSystemSettingParams{
		Key:       licenseSettingKey,
		Value:     tok,
		UpdatedAt: store.Now(),
	}); err != nil {
		return fmt.Errorf("saving license: %w", err)
	}
	s.record(r, p, "system.license_updated", "system", "license", map[string]any{
		"edition":    st.Edition,
		"license_id": st.LicenseID,
		"customer":   st.Customer,
	})
	dto, err := s.buildLicenseDTO(r, p, st)
	if err != nil {
		return err
	}
	return ok(w, dto)
}

// openapi:operation
// summary: Remove commercial license
// description: Clears a database-stored commercial license and reverts the instance to Community Edition.
// responses:
//   '200': { description: Reverted Community license status, schema: LicenseStatus }

func (s *Server) deleteLicense(w http.ResponseWriter, r *http.Request, p principal) error {
	mgr := s.licenseMgr()
	if mgr.Status().Source == "env" {
		return conflict("%v", license.ErrManagedByConfig)
	}
	if err := s.Store.Q.DeleteSystemSetting(r.Context(), licenseSettingKey); err != nil {
		return fmt.Errorf("deleting license: %w", err)
	}
	mgr.Clear()
	s.record(r, p, "system.license_removed", "system", "license", nil)
	dto, err := s.buildLicenseDTO(r, p, mgr.Status())
	if err != nil {
		return err
	}
	return ok(w, dto)
}
