package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/interpolate"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// MaskedSecretValue is returned when a secret is listed without reveal=1.
const MaskedSecretValue = "••••••••"

// openapi:schema Secret
// type: object
// required: [id, project_id, environment_slug, path, key, value, comment, version, created_at, updated_at]
// properties:
//   id: { type: string, format: uuid }
//   project_id: { type: string, format: uuid }
//   environment_slug: { type: string }
//   path: { type: string }
//   key: { type: string }
//   value: { type: string }
//   raw_value: { type: string }
//   comment: { type: string }
//   version: { type: integer }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }

type secretDTO struct {
	ID              string    `json:"id"`
	ProjectID       string    `json:"project_id"`
	EnvironmentSlug string    `json:"environment_slug"`
	Path            string    `json:"path"`
	Key             string    `json:"key"`
	Value           string    `json:"value"`
	RawValue        string    `json:"raw_value,omitempty"`
	Comment         string    `json:"comment"`
	Version         int32     `json:"version"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func toSecret(s db.Secret, val string) secretDTO {
	return secretDTO{
		ID:              s.ID,
		ProjectID:       s.ProjectID,
		EnvironmentSlug: s.EnvironmentSlug,
		Path:            s.Path,
		Key:             s.Key,
		Value:           val,
		Comment:         s.Comment,
		Version:         s.Version,
		CreatedAt:       s.CreatedAt.UTC(),
		UpdatedAt:       s.UpdatedAt.UTC(),
	}
}

// openapi:schema SecretList
// type: object
// required: [items, total]
// properties:
//   items: { type: array, items: { $ref: '#/components/schemas/Secret' } }
//   total: { type: integer }

type secretListDTO struct {
	Items []secretDTO `json:"items"`
	Total int         `json:"total"`
}

// openapi:schema CreateSecretRequest
// type: object
// required: [key, value]
// additionalProperties: false
// properties:
//   key: { type: string, minLength: 1, maxLength: 256 }
//   value: { type: string }
//   comment: { type: string, maxLength: 500 }
//   path: { type: string, maxLength: 256 }

type createSecretRequest struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Comment string `json:"comment"`
	Path    string `json:"path"`
}

// openapi:schema UpdateSecretRequest
// type: object
// additionalProperties: false
// properties:
//   value: { type: string }
//   comment: { type: string, maxLength: 500 }

type updateSecretRequest struct {
	Value   opt[string] `json:"value"`
	Comment opt[string] `json:"comment"`
}

// openapi:schema SecretVersion
// type: object
// required: [id, secret_id, version, value, comment, created_at, created_by]
// properties:
//   id: { type: string, format: uuid }
//   secret_id: { type: string, format: uuid }
//   version: { type: integer }
//   value: { type: string }
//   comment: { type: string }
//   created_at: { type: string, format: date-time }
//   created_by: { type: string }

type secretVersionDTO struct {
	ID        string    `json:"id"`
	SecretID  string    `json:"secret_id"`
	Version   int32     `json:"version"`
	Value     string    `json:"value"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

func toSecretVersion(sv db.SecretVersion, val string) secretVersionDTO {
	return secretVersionDTO{
		ID:        sv.ID,
		SecretID:  sv.SecretID,
		Version:   sv.Version,
		Value:     val,
		Comment:   sv.Comment,
		CreatedAt: sv.CreatedAt.UTC(),
		CreatedBy: sv.CreatedBy,
	}
}

// openapi:schema SecretVersionList
// type: object
// required: [items, total]
// properties:
//   items: { type: array, items: { $ref: '#/components/schemas/SecretVersion' } }
//   total: { type: integer }

type secretVersionListDTO struct {
	Items []secretVersionDTO `json:"items"`
	Total int                `json:"total"`
}

// openapi:schema RollbackSecretRequest
// type: object
// required: [version]
// additionalProperties: false
// properties:
//   version: { type: integer }

type rollbackSecretRequest struct {
	Version int32 `json:"version"`
}

func (s *Server) projectVault(projectID string) (*crypto.Vault, error) {
	if s.Vault == nil {
		return nil, errors.New("crypto vault not initialized")
	}
	return s.Vault.DeriveSubVault("project", projectID)
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func serviceTokenAllowsPath(p principal, secretPath string) bool {
	if p.ServiceToken == nil {
		return true
	}
	scope := strings.TrimSpace(p.ServiceToken.Path)
	if scope == "" || scope == "/" || scope == "*" {
		return true
	}
	scope = normalizePath(scope)
	sec := normalizePath(secretPath)
	return sec == scope || strings.HasPrefix(sec, scope+"/")
}

func filterSecretsByTokenPath(p principal, rows []db.Secret) []db.Secret {
	if p.ServiceToken == nil {
		return rows
	}
	scope := strings.TrimSpace(p.ServiceToken.Path)
	if scope == "" || scope == "/" || scope == "*" {
		return rows
	}
	filtered := make([]db.Secret, 0, len(rows))
	for _, row := range rows {
		if serviceTokenAllowsPath(p, row.Path) {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func (s *Server) consumeSingleUseToken(r *http.Request, p principal) error {
	if p.ServiceToken == nil || !p.ServiceToken.SingleUse {
		return nil
	}
	n, err := s.Store.Q.BurnServiceToken(r.Context(), db.BurnServiceTokenParams{
		ID:  p.ServiceToken.ID,
		Now: store.NullTime(store.Now()),
	})
	if err != nil {
		return fmt.Errorf("consuming single-use token: %w", err)
	}
	if n == 0 {
		return forbidden("single-use service token has already been consumed")
	}
	s.record(r, p, "token.burn", "service_token", p.ServiceToken.ID, map[string]any{
		"name": p.ServiceToken.Name,
	})
	return nil
}

func decryptRowsAndExpand(rows []db.Secret, subVault *crypto.Vault) (rawByID map[string]string, expandedByPath map[string]map[string]string) {
	rawByID = make(map[string]string, len(rows))
	perPath := make(map[string]map[string]string)
	globalFallback := make(map[string]string, len(rows))

	// Sort deterministically by (Path, Key) for global fallback resolution.
	ordered := make([]db.Secret, len(rows))
	copy(ordered, rows)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		return ordered[i].Key < ordered[j].Key
	})

	for _, row := range ordered {
		decrypted, decErr := subVault.Decrypt(row.ValueEncrypted, row.ValueNonce)
		val := "[decryption error]"
		if decErr == nil {
			val = string(decrypted)
		}
		rawByID[row.ID] = val
		if perPath[row.Path] == nil {
			perPath[row.Path] = make(map[string]string)
		}
		perPath[row.Path][row.Key] = val
		if _, exists := globalFallback[row.Key]; !exists || row.Path == "/" {
			globalFallback[row.Key] = val
		}
	}

	expandedByPath = make(map[string]map[string]string, len(perPath))
	for p, own := range perPath {
		merged := make(map[string]string, len(globalFallback)+len(own))
		for k, v := range globalFallback {
			merged[k] = v
		}
		for k, v := range own {
			merged[k] = v
		}
		expandedByPath[p] = interpolate.Expand(merged)
	}
	return rawByID, expandedByPath
}

func escapeExportValue(val string) string {
	escaped := strings.ReplaceAll(val, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, "\r", `\r`)
	escaped = strings.ReplaceAll(escaped, "\n", `\n`)
	return escaped
}

// openapi:operation
// summary: List secrets
// description: Returns all secrets in a project environment. Secrets are masked unless reveal is 1.
// responses:
//   '200': { description: Secrets list, schema: SecretList }

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request, p principal) error {
	projectRef := r.PathValue("id")
	envSlug := r.PathValue("env_slug")

	proj, err := s.resolveProject(r.Context(), projectRef)
	if err != nil {
		return fromStore(err, "project")
	}
	projectID := proj.ID

	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}

	qPath := r.URL.Query().Get("path")
	if qPath != "" && qPath != "*" && !serviceTokenAllowsPath(p, qPath) {
		return forbidden("service token scope does not allow path %q", normalizePath(qPath))
	}
	reveal := r.URL.Query().Get("reveal") == "1" || r.URL.Query().Get("reveal") == "true"

	var subVault *crypto.Vault
	if reveal {
		var err error
		subVault, err = s.projectVault(projectID)
		if err != nil {
			return err
		}
	}

	var rows []db.Secret
	if qPath == "" || qPath == "*" {
		rows, err = s.Store.Q.ListSecretsAllPaths(r.Context(), db.ListSecretsAllPathsParams{
			ProjectID:       projectID,
			EnvironmentSlug: envSlug,
		})
	} else {
		rows, err = s.Store.Q.ListSecrets(r.Context(), db.ListSecretsParams{
			ProjectID:       projectID,
			EnvironmentSlug: envSlug,
			Path:            normalizePath(qPath),
		})
	}
	if err != nil {
		return err
	}
	rows = filterSecretsByTokenPath(p, rows)

	if reveal {
		if err := s.consumeSingleUseToken(r, p); err != nil {
			return err
		}
	}

	items := make([]secretDTO, 0, len(rows))
	if reveal && subVault != nil {
		rawByID, expandedByPath := decryptRowsAndExpand(rows, subVault)
		for _, row := range rows {
			rawVal := rawByID[row.ID]
			expVal := rawVal
			if pathMap := expandedByPath[row.Path]; pathMap != nil {
				if v, ok := pathMap[row.Key]; ok {
					expVal = v
				}
			}
			dto := toSecret(row, expVal)
			if rawVal != expVal {
				dto.RawValue = rawVal
			}
			items = append(items, dto)
		}
		s.record(r, p, "secrets.list_revealed", "environment", envSlug, map[string]any{
			"project_id":  projectID,
			"environment": envSlug,
			"path":        qPath,
			"count":       len(items),
		})
		w.Header().Set("Cache-Control", "no-store")
	} else {
		for _, row := range rows {
			items = append(items, toSecret(row, MaskedSecretValue))
		}
	}
	return ok(w, secretListDTO{Items: items, Total: len(items)})
}

// openapi:operation
// summary: Create secret
// description: Creates a new encrypted secret and records its initial version.
// requestBody: { schema: CreateSecretRequest }
// responses:
//   '201': { description: Created secret, schema: Secret }

func (s *Server) createSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}
	if _, err := s.Store.Q.GetProject(r.Context(), projectID); err != nil {
		return fromStore(err, "project")
	}
	if _, err := s.Store.Q.GetEnvironmentBySlug(r.Context(), db.GetEnvironmentBySlugParams{
		ProjectID: projectID,
		Slug:      envSlug,
	}); err != nil {
		return fromStore(err, "environment")
	}

	var in createSecretRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	key := strings.TrimSpace(in.Key)
	if key == "" || len(key) > 256 {
		return badRequest("secret key must be between 1 and 256 characters")
	}
	path := normalizePath(in.Path)
	if !serviceTokenAllowsPath(p, path) {
		return forbidden("service token scope does not allow path %q", path)
	}
	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}

	v, err := s.projectVault(projectID)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := v.Encrypt([]byte(in.Value))
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	secretID := store.NewID()
	versionID := store.NewID()
	now := store.Now()

	err = s.Store.Tx(r.Context(), func(q *db.Queries) error {
		if err := q.CreateSecret(r.Context(), db.CreateSecretParams{
			ID:              secretID,
			ProjectID:       projectID,
			EnvironmentSlug: envSlug,
			Path:            path,
			Key:             key,
			ValueEncrypted:  ciphertext,
			ValueNonce:      nonce,
			Comment:         in.Comment,
			Version:         1,
			Now:             now,
		}); err != nil {
			return err
		}
		return q.CreateSecretVersion(r.Context(), db.CreateSecretVersionParams{
			ID:             versionID,
			SecretID:       secretID,
			Version:        1,
			ValueEncrypted: ciphertext,
			ValueNonce:     nonce,
			Comment:        in.Comment,
			Now:            now,
			CreatedBy:      p.User.Username,
		})
	})
	if err != nil {
		return fromStore(err, "secret")
	}

	s.record(r, p, "secret.create", "secret", secretID, map[string]any{
		"project_id":  projectID,
		"environment": envSlug,
		"path":        path,
		"key":         key,
	})
	s.changed(r, "secret", secretID)

	sRow, err := s.Store.Q.GetSecret(r.Context(), secretID)
	if err != nil {
		return err
	}
	return created(w, toSecret(sRow, in.Value))
}

// openapi:schema ImportSecretItem
// type: object
// required: [key, value]
// properties:
//   key: { type: string }
//   value: { type: string }
//   comment: { type: string }
//   path: { type: string }

type importSecretItem struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
	Path    string `json:"path,omitempty"`
}

// openapi:schema ImportSecretsRequest
// type: object
// required: [secrets]
// properties:
//   path: { type: string }
//   overwrite: { type: boolean }
//   secrets:
//     type: array
//     items: { $ref: '#/components/schemas/ImportSecretItem' }

type importSecretsRequest struct {
	Path      string             `json:"path,omitempty"`
	Overwrite bool               `json:"overwrite"`
	Secrets   []importSecretItem `json:"secrets"`
}

// openapi:schema ImportSecretsResponse
// type: object
// required: [created, updated, total]
// properties:
//   created: { type: integer }
//   updated: { type: integer }
//   total: { type: integer }

type importSecretsResponse struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Total   int `json:"total"`
}

// openapi:operation
// summary: Bulk import secrets
// description: Imports multiple secrets from key-value pairs (e.g. parsed .env file) in a single atomic transaction.
// requestBody: { schema: ImportSecretsRequest }
// responses:
//   '200': { description: Import result, schema: ImportSecretsResponse }

func (s *Server) importSecrets(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}
	if _, err := s.Store.Q.GetProject(r.Context(), projectID); err != nil {
		return fromStore(err, "project")
	}
	if _, err := s.Store.Q.GetEnvironmentBySlug(r.Context(), db.GetEnvironmentBySlugParams{
		ProjectID: projectID,
		Slug:      envSlug,
	}); err != nil {
		return fromStore(err, "environment")
	}

	var in importSecretsRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	if len(in.Secrets) == 0 {
		return badRequest("no secrets provided in import payload")
	}
	if len(in.Secrets) > 1000 {
		return badRequest("cannot import more than 1000 secrets at once")
	}

	defaultPath := normalizePath(in.Path)
	for _, item := range in.Secrets {
		k := strings.TrimSpace(item.Key)
		if k == "" || len(k) > 256 {
			continue
		}
		itemPath := defaultPath
		if item.Path != "" {
			itemPath = normalizePath(item.Path)
		}
		if !serviceTokenAllowsPath(p, itemPath) {
			return forbidden("service token scope does not allow path %q", itemPath)
		}
	}
	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}
	v, err := s.projectVault(projectID)
	if err != nil {
		return err
	}

	var createdCount, updatedCount int
	now := store.Now()

	err = s.Store.Tx(r.Context(), func(q *db.Queries) error {
		for _, item := range in.Secrets {
			k := strings.TrimSpace(item.Key)
			if k == "" || len(k) > 256 {
				continue
			}
			itemPath := defaultPath
			if item.Path != "" {
				itemPath = normalizePath(item.Path)
			}

			ciphertext, nonce, encErr := v.Encrypt([]byte(item.Value))
			if encErr != nil {
				return fmt.Errorf("encrypting %s: %w", k, encErr)
			}

			existing, getErr := q.GetSecretByKey(r.Context(), db.GetSecretByKeyParams{
				ProjectID:       projectID,
				EnvironmentSlug: envSlug,
				Path:            itemPath,
				Key:             k,
			})

			if getErr != nil {
				// Does not exist -> Create
				newSecID := store.NewID()
				newVerID := store.NewID()

				if err := q.CreateSecret(r.Context(), db.CreateSecretParams{
					ID:              newSecID,
					ProjectID:       projectID,
					EnvironmentSlug: envSlug,
					Path:            itemPath,
					Key:             k,
					ValueEncrypted:  ciphertext,
					ValueNonce:      nonce,
					Comment:         item.Comment,
					Version:         1,
					Now:             now,
				}); err != nil {
					return err
				}

				if err := q.CreateSecretVersion(r.Context(), db.CreateSecretVersionParams{
					ID:             newVerID,
					SecretID:       newSecID,
					Version:        1,
					ValueEncrypted: ciphertext,
					ValueNonce:     nonce,
					Comment:        item.Comment,
					Now:            now,
					CreatedBy:      p.User.Username,
				}); err != nil {
					return err
				}
				createdCount++
			} else {
				// Already exists
				if !in.Overwrite {
					continue
				}
				newVerID := store.NewID()
				newVersion := existing.Version + 1

				comment := item.Comment
				if comment == "" {
					comment = existing.Comment
				}

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
					ID:             newVerID,
					SecretID:       existing.ID,
					Version:        newVersion,
					ValueEncrypted: ciphertext,
					ValueNonce:     nonce,
					Comment:        comment,
					Now:            now,
					CreatedBy:      p.User.Username,
				}); err != nil {
					return err
				}
				updatedCount++
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("bulk import failed: %w", err)
	}

	s.record(r, p, "secret.import", "environment", envSlug, map[string]any{
		"project_id":  projectID,
		"environment": envSlug,
		"created":     createdCount,
		"updated":     updatedCount,
		"total":       createdCount + updatedCount,
	})
	s.changed(r, "secret", "")

	return ok(w, importSecretsResponse{
		Created: createdCount,
		Updated: updatedCount,
		Total:   createdCount + updatedCount,
	})
}

// openapi:operation
// summary: Export secrets
// description: Exports all decrypted secrets for an environment as dotenv, json, or yaml.
// responses:
//   '200': { description: Decrypted secrets export, schema: { type: object, additionalProperties: { type: string } } }

func (s *Server) exportSecrets(w http.ResponseWriter, r *http.Request, p principal) error {
	projectRef := r.PathValue("id")
	envSlug := r.PathValue("env_slug")

	proj, err := s.resolveProject(r.Context(), projectRef)
	if err != nil {
		return fromStore(err, "project")
	}
	projectID := proj.ID

	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}

	v, err := s.projectVault(projectID)
	if err != nil {
		return err
	}

	qPath := r.URL.Query().Get("path")
	if qPath != "" && qPath != "*" && !serviceTokenAllowsPath(p, qPath) {
		return forbidden("service token scope does not allow path %q", normalizePath(qPath))
	}
	var rows []db.Secret
	if qPath == "" || qPath == "*" {
		rows, err = s.Store.Q.ListSecretsAllPaths(r.Context(), db.ListSecretsAllPathsParams{
			ProjectID:       projectID,
			EnvironmentSlug: envSlug,
		})
	} else {
		rows, err = s.Store.Q.ListSecrets(r.Context(), db.ListSecretsParams{
			ProjectID:       projectID,
			EnvironmentSlug: envSlug,
			Path:            normalizePath(qPath),
		})
	}
	if err != nil {
		return err
	}
	rows = filterSecretsByTokenPath(p, rows)

	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}

	ordered := make([]db.Secret, len(rows))
	copy(ordered, rows)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		return ordered[i].Key < ordered[j].Key
	})

	_, expandedByPath := decryptRowsAndExpand(ordered, v)
	decrypted := make(map[string]string, len(ordered))
	keys := make([]string, 0, len(ordered))
	seenKeys := make(map[string]bool, len(ordered))
	for _, row := range ordered {
		val := ""
		if pathMap := expandedByPath[row.Path]; pathMap != nil {
			val = pathMap[row.Key]
		}
		decrypted[row.Key] = val
		if !seenKeys[row.Key] {
			seenKeys[row.Key] = true
			keys = append(keys, row.Key)
		}
	}
	sort.Strings(keys)

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	s.record(r, p, "secret.export", "environment", envSlug, map[string]any{
		"project_id":  projectID,
		"environment": envSlug,
		"path":        qPath,
		"format":      format,
		"count":       len(keys),
	})
	w.Header().Set("Cache-Control", "no-store")
	switch format {
	case "json":
		return ok(w, decrypted)
	case "yaml", "yml":
		var b strings.Builder
		for _, k := range keys {
			escaped := escapeExportValue(decrypted[k])
			b.WriteString(fmt.Sprintf("%s: \"%s\"\n", k, escaped))
		}
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b.String()))
		return nil
	default: // dotenv
		var b strings.Builder
		for _, k := range keys {
			escaped := escapeExportValue(decrypted[k])
			b.WriteString(fmt.Sprintf("%s=\"%s\"\n", k, escaped))
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b.String()))
		return nil
	}
}

// openapi:operation
// summary: Get secret
// description: Retrieves and decrypts a specific secret.
// responses:
//   '200': { description: Secret, schema: Secret }

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	secretID := r.PathValue("secret_id")

	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}
	sRow, err := s.Store.Q.GetSecret(r.Context(), secretID)
	if err != nil {
		return fromStore(err, "secret")
	}
	if sRow.ProjectID != projectID || sRow.EnvironmentSlug != envSlug {
		return notFound("secret")
	}
	if !serviceTokenAllowsPath(p, sRow.Path) {
		return forbidden("service token scope does not allow path %q", sRow.Path)
	}

	v, err := s.projectVault(projectID)
	if err != nil {
		return err
	}
	decrypted, err := v.Decrypt(sRow.ValueEncrypted, sRow.ValueNonce)
	if err != nil {
		return fmt.Errorf("decrypting secret: %w", err)
	}

	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}

	rawVal := string(decrypted)
	dto := toSecret(sRow, rawVal)
	if interpolate.HasReference(rawVal) {
		allRows, _ := s.Store.Q.ListSecretsAllPaths(r.Context(), db.ListSecretsAllPathsParams{
			ProjectID:       projectID,
			EnvironmentSlug: envSlug,
		})
		allRows = filterSecretsByTokenPath(p, allRows)
		if len(allRows) > 0 {
			rawMap := make(map[string]string, len(allRows))
			for _, row := range allRows {
				if row.Path == sRow.Path {
					continue
				}
				if valBytes, decErr := v.Decrypt(row.ValueEncrypted, row.ValueNonce); decErr == nil {
					if _, exists := rawMap[row.Key]; !exists || row.Path == "/" {
						rawMap[row.Key] = string(valBytes)
					}
				}
			}
			for _, row := range allRows {
				if row.Path != sRow.Path || row.ID == sRow.ID {
					continue
				}
				if valBytes, decErr := v.Decrypt(row.ValueEncrypted, row.ValueNonce); decErr == nil {
					rawMap[row.Key] = string(valBytes)
				}
			}
			rawMap[sRow.Key] = rawVal
			expanded := interpolate.Expand(rawMap)
			if expVal, ok := expanded[sRow.Key]; ok && expVal != rawVal {
				dto.Value = expVal
				dto.RawValue = rawVal
			}
		}
	}

	s.record(r, p, "secret.read", "secret", sRow.ID, map[string]any{
		"project_id":  projectID,
		"environment": envSlug,
		"path":        sRow.Path,
		"key":         sRow.Key,
	})
	w.Header().Set("Cache-Control", "no-store")
	return ok(w, dto)
}

// openapi:operation
// summary: Update secret
// description: Updates a secret value or comment, incrementing its version.
// requestBody: { schema: UpdateSecretRequest }
// responses:
//   '200': { description: Updated secret, schema: Secret }

func (s *Server) updateSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	secretID := r.PathValue("secret_id")

	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}
	sRow, err := s.Store.Q.GetSecret(r.Context(), secretID)
	if err != nil {
		return fromStore(err, "secret")
	}
	if sRow.ProjectID != projectID || sRow.EnvironmentSlug != envSlug {
		return notFound("secret")
	}
	if !serviceTokenAllowsPath(p, sRow.Path) {
		return forbidden("service token scope does not allow path %q", sRow.Path)
	}

	var in updateSecretRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}

	v, err := s.projectVault(projectID)
	if err != nil {
		return err
	}

	ciphertext := sRow.ValueEncrypted
	nonce := sRow.ValueNonce
	comment := sRow.Comment
	newVersion := sRow.Version + 1
	now := store.Now()
	newValStr := ""

	if in.Comment.Set {
		comment = in.Comment.V
	}

	if in.Value.Set {
		newValStr = in.Value.V
		enc, n, err := v.Encrypt([]byte(newValStr))
		if err != nil {
			return fmt.Errorf("encrypting updated secret: %w", err)
		}
		ciphertext = enc
		nonce = n
	} else {
		// Decrypt current value for response
		dec, err := v.Decrypt(sRow.ValueEncrypted, sRow.ValueNonce)
		if err == nil {
			newValStr = string(dec)
		}
	}

	versionID := store.NewID()
	err = s.Store.Tx(r.Context(), func(q *db.Queries) error {
		if err := q.UpdateSecret(r.Context(), db.UpdateSecretParams{
			ID:             secretID,
			ValueEncrypted: ciphertext,
			ValueNonce:     nonce,
			Comment:        comment,
			Now:            now,
		}); err != nil {
			return err
		}
		return q.CreateSecretVersion(r.Context(), db.CreateSecretVersionParams{
			ID:             versionID,
			SecretID:       secretID,
			Version:        newVersion,
			ValueEncrypted: ciphertext,
			ValueNonce:     nonce,
			Comment:        comment,
			Now:            now,
			CreatedBy:      p.User.Username,
		})
	})
	if err != nil {
		return fromStore(err, "secret")
	}

	s.record(r, p, "secret.update", "secret", secretID, map[string]any{
		"project_id":  projectID,
		"environment": envSlug,
		"key":         sRow.Key,
		"version":     newVersion,
	})
	s.changed(r, "secret", secretID)

	updatedRow, err := s.Store.Q.GetSecret(r.Context(), secretID)
	if err != nil {
		return err
	}
	return ok(w, toSecret(updatedRow, newValStr))
}

// openapi:operation
// summary: Delete secret
// description: Permanently deletes a secret and all its version history.
// responses:
//   '204': { description: Secret deleted }

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	secretID := r.PathValue("secret_id")

	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}
	sRow, err := s.Store.Q.GetSecret(r.Context(), secretID)
	if err != nil {
		return fromStore(err, "secret")
	}
	if sRow.ProjectID != projectID || sRow.EnvironmentSlug != envSlug {
		return notFound("secret")
	}
	if !serviceTokenAllowsPath(p, sRow.Path) {
		return forbidden("service token scope does not allow path %q", sRow.Path)
	}
	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}

	return handleCommand(w, func() error {
		n, err := s.Store.Q.DeleteSecret(r.Context(), secretID)
		if err != nil {
			return err
		}
		if n == 0 {
			return notFound("secret")
		}
		s.record(r, p, "secret.delete", "secret", secretID, map[string]any{
			"project_id":  projectID,
			"environment": envSlug,
			"key":         sRow.Key,
		})
		s.changed(r, "secret", secretID)
		return nil
	})
}

// openapi:operation
// summary: List secret versions
// description: Returns version history for a secret.
// responses:
//   '200': { description: Version history, schema: SecretVersionList }

func (s *Server) listSecretVersions(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	secretID := r.PathValue("secret_id")

	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}
	sRow, err := s.Store.Q.GetSecret(r.Context(), secretID)
	if err != nil {
		return fromStore(err, "secret")
	}
	if sRow.ProjectID != projectID || sRow.EnvironmentSlug != envSlug {
		return notFound("secret")
	}
	if !serviceTokenAllowsPath(p, sRow.Path) {
		return forbidden("service token scope does not allow path %q", sRow.Path)
	}

	reveal := r.URL.Query().Get("reveal") == "1" || r.URL.Query().Get("reveal") == "true"
	var subVault *crypto.Vault
	if reveal {
		var err error
		subVault, err = s.projectVault(projectID)
		if err != nil {
			return err
		}
		if err := s.consumeSingleUseToken(r, p); err != nil {
			return err
		}
	}

	versions, err := s.Store.Q.ListSecretVersions(r.Context(), secretID)
	if err != nil {
		return err
	}

	items := make([]secretVersionDTO, 0, len(versions))
	for _, v := range versions {
		val := MaskedSecretValue
		if reveal && subVault != nil {
			decrypted, decErr := subVault.Decrypt(v.ValueEncrypted, v.ValueNonce)
			if decErr != nil {
				val = "[decryption error]"
			} else {
				val = string(decrypted)
			}
		}
		items = append(items, toSecretVersion(v, val))
	}
	if reveal {
		s.record(r, p, "secret.versions_read", "secret", sRow.ID, map[string]any{
			"project_id":  projectID,
			"environment": envSlug,
			"path":        sRow.Path,
			"key":         sRow.Key,
			"count":       len(items),
		})
	}
	return ok(w, secretVersionListDTO{Items: items, Total: len(items)})
}

// openapi:operation
// summary: Rollback secret
// description: Rolls back a secret to a previous version by creating a new version with the historic value.
// requestBody: { schema: RollbackSecretRequest }
// responses:
//   '200': { description: Restored secret, schema: Secret }

func (s *Server) rollbackSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	secretID := r.PathValue("secret_id")

	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}
	sRow, err := s.Store.Q.GetSecret(r.Context(), secretID)
	if err != nil {
		return fromStore(err, "secret")
	}
	if sRow.ProjectID != projectID || sRow.EnvironmentSlug != envSlug {
		return notFound("secret")
	}
	if !serviceTokenAllowsPath(p, sRow.Path) {
		return forbidden("service token scope does not allow path %q", sRow.Path)
	}

	var in rollbackSecretRequest
	if err := decode(r, &in); err != nil {
		return err
	}

	targetVer, err := s.Store.Q.GetSecretVersion(r.Context(), db.GetSecretVersionParams{
		SecretID: secretID,
		Version:  in.Version,
	})
	if err != nil {
		return badRequest("target version does not exist")
	}
	if err := s.consumeSingleUseToken(r, p); err != nil {
		return err
	}

	v, err := s.projectVault(projectID)
	if err != nil {
		return err
	}

	newVersion := sRow.Version + 1
	now := store.Now()
	comment := fmt.Sprintf("Rollback to version %d", in.Version)
	versionID := store.NewID()

	err = s.Store.Tx(r.Context(), func(q *db.Queries) error {
		if err := q.RollbackSecret(r.Context(), db.RollbackSecretParams{
			ID:             secretID,
			ValueEncrypted: targetVer.ValueEncrypted,
			ValueNonce:     targetVer.ValueNonce,
			Comment:        comment,
			Version:        newVersion,
			Now:            now,
		}); err != nil {
			return err
		}
		return q.CreateSecretVersion(r.Context(), db.CreateSecretVersionParams{
			ID:             versionID,
			SecretID:       secretID,
			Version:        newVersion,
			ValueEncrypted: targetVer.ValueEncrypted,
			ValueNonce:     targetVer.ValueNonce,
			Comment:        comment,
			Now:            now,
			CreatedBy:      p.User.Username,
		})
	})
	if err != nil {
		return fromStore(err, "secret")
	}

	s.record(r, p, "secret.rollback", "secret", secretID, map[string]any{
		"project_id":     projectID,
		"environment":    envSlug,
		"key":            sRow.Key,
		"from_version":   sRow.Version,
		"target_version": in.Version,
		"new_version":    newVersion,
	})
	s.changed(r, "secret", secretID)

	decrypted, decErr := v.Decrypt(targetVer.ValueEncrypted, targetVer.ValueNonce)
	valStr := MaskedSecretValue
	if decErr == nil {
		valStr = string(decrypted)
	}

	updatedRow, err := s.Store.Q.GetSecret(r.Context(), secretID)
	if err != nil {
		return err
	}
	return ok(w, toSecret(updatedRow, valStr))
}
