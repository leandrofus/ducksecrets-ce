package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/rotation"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// openapi:schema RotationPolicy
// type: object
// required: [id, secret_id, interval_seconds, generator_type, verifier_type, next_rotation_at, status, created_at, updated_at]
// properties:
//   id: { type: string, format: uuid }
//   secret_id: { type: string, format: uuid }
//   secret_key: { type: string }
//   secret_path: { type: string }
//   interval_seconds: { type: integer }
//   generator_type: { type: string }
//   generator_config: { type: string }
//   verifier_type: { type: string }
//   verifier_config: { type: string }
//   last_rotated_at: { type: string, format: date-time, nullable: true }
//   next_rotation_at: { type: string, format: date-time }
//   status: { type: string }
//   last_error: { type: string }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }

type rotationPolicyDTO struct {
	ID              string     `json:"id"`
	SecretID        string     `json:"secret_id"`
	SecretKey       string     `json:"secret_key,omitempty"`
	SecretPath      string     `json:"secret_path,omitempty"`
	IntervalSeconds int32      `json:"interval_seconds"`
	GeneratorType   string     `json:"generator_type"`
	GeneratorConfig string     `json:"generator_config"`
	VerifierType    string     `json:"verifier_type"`
	VerifierConfig  string     `json:"verifier_config"`
	LastRotatedAt   *time.Time `json:"last_rotated_at,omitempty"`
	NextRotationAt  time.Time  `json:"next_rotation_at"`
	Status          string     `json:"status"`
	LastError       string     `json:"last_error"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// openapi:schema SetRotationPolicyRequest
// type: object
// required: [interval_seconds, generator_type]
// additionalProperties: false
// properties:
//   interval_seconds: { type: integer }
//   generator_type: { type: string }
//   generator_config: { type: string }
//   verifier_type: { type: string }
//   verifier_config: { type: string }

type setRotationPolicyRequest struct {
	IntervalSeconds int    `json:"interval_seconds"`
	GeneratorType   string `json:"generator_type"`
	GeneratorConfig string `json:"generator_config"`
	VerifierType    string `json:"verifier_type"`
	VerifierConfig  string `json:"verifier_config"`
}

// openapi:schema RotationRunResponse
// type: object
// required: [success, rolled_back, message]
// properties:
//   success: { type: boolean }
//   rolled_back: { type: boolean }
//   message: { type: string }
//   new_version: { type: integer }

type rotationRunResponse struct {
	Success    bool   `json:"success"`
	RolledBack bool   `json:"rolled_back"`
	Message    string `json:"message"`
	NewVersion int32  `json:"new_version,omitempty"`
}

func toRotationDTO(r db.RotationPolicy, secretKey, secretPath string) rotationPolicyDTO {
	dto := rotationPolicyDTO{
		ID:              r.ID,
		SecretID:        r.SecretID,
		SecretKey:       secretKey,
		SecretPath:      secretPath,
		IntervalSeconds: r.IntervalSeconds,
		GeneratorType:   r.GeneratorType,
		GeneratorConfig: r.GeneratorConfig,
		VerifierType:    r.VerifierType,
		VerifierConfig:  r.VerifierConfig,
		NextRotationAt:  r.NextRotationAt.UTC(),
		Status:          r.Status,
		LastError:       r.LastError,
		CreatedAt:       r.CreatedAt.UTC(),
		UpdatedAt:       r.UpdatedAt.UTC(),
	}
	if r.LastRotatedAt.Valid {
		t := r.LastRotatedAt.Time.UTC()
		dto.LastRotatedAt = &t
	}
	return dto
}

// openapi:operation
// summary: List project rotation policies
// description: Returns all automated secret rotation policies in an environment.
// responses:
//   '200': { description: Policies list, schema: { type: array, items: { $ref: '#/components/schemas/RotationPolicy' } } }

func (s *Server) listRotationPolicies(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}

	rows, err := s.Store.Q.ListRotationPoliciesByProject(r.Context(), db.ListRotationPoliciesByProjectParams{
		ProjectID:       projectID,
		EnvironmentSlug: envSlug,
	})
	if err != nil {
		return fmt.Errorf("listing rotation policies: %w", err)
	}

	res := make([]rotationPolicyDTO, len(rows))
	for i, row := range rows {
		policy := db.RotationPolicy{
			ID:              row.ID,
			SecretID:        row.SecretID,
			IntervalSeconds: row.IntervalSeconds,
			GeneratorType:   row.GeneratorType,
			GeneratorConfig: row.GeneratorConfig,
			VerifierType:    row.VerifierType,
			VerifierConfig:  row.VerifierConfig,
			LastRotatedAt:   row.LastRotatedAt,
			NextRotationAt:  row.NextRotationAt,
			Status:          row.Status,
			LastError:       row.LastError,
			CreatedAt:       row.CreatedAt,
			UpdatedAt:       row.UpdatedAt,
		}
		res[i] = toRotationDTO(policy, row.SecretKey, row.SecretPath)
	}
	return ok(w, res)
}

func (s *Server) getScopedSecret(ctx context.Context, projectID, envSlug, secretID string) (db.Secret, error) {
	sec, err := s.Store.Q.GetSecret(ctx, secretID)
	if err != nil {
		return db.Secret{}, fromStore(err, "secret")
	}
	if sec.ProjectID != projectID || sec.EnvironmentSlug != envSlug {
		return db.Secret{}, notFound("secret")
	}
	return sec, nil
}

// openapi:operation
// summary: Get secret rotation policy
// description: Retrieves rotation policy attached to a secret.
// responses:
//   '200': { description: Rotation policy, schema: { $ref: '#/components/schemas/RotationPolicy' } }

func (s *Server) getRotationPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	secretID := r.PathValue("secret_id")
	if err := s.allowEnv(r, p, auth.PermSecretsRead, projectID, envSlug); err != nil {
		return err
	}

	if _, err := s.getScopedSecret(r.Context(), projectID, envSlug, secretID); err != nil {
		return err
	}

	pol, err := s.Store.Q.GetRotationPolicyBySecret(r.Context(), secretID)
	if err != nil {
		return fromStore(err, "rotation policy")
	}
	return ok(w, toRotationDTO(pol, "", ""))
}

// openapi:operation
// summary: Set or update secret rotation policy
// description: Configures automated rotation interval, generator type, and health verification probe.
// requestBody:
//   schema: { $ref: '#/components/schemas/SetRotationPolicyRequest' }
// responses:
//   '200': { description: Policy updated, schema: { $ref: '#/components/schemas/RotationPolicy' } }

func (s *Server) setRotationPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	secretID := r.PathValue("secret_id")
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}

	secret, err := s.getScopedSecret(r.Context(), projectID, envSlug, secretID)
	if err != nil {
		return err
	}

	var req setRotationPolicyRequest
	if err := decode(r, &req); err != nil {
		return err
	}

	interval := req.IntervalSeconds
	if interval <= 0 {
		interval = 2592000 // default 30 days
	}
	genType := req.GeneratorType
	if genType == "" {
		genType = "password"
	}
	verType := req.VerifierType
	if verType == "" {
		verType = "none"
	}
	switch verType {
	case "none", "http_probe", "tcp_probe":
	case "script":
		if !s.AllowScripts {
			return forbidden("script rotation verifiers are disabled on this server")
		}
		if !auth.Has(p.Perms, auth.PermSystemManage) {
			return forbidden("configuring script verifier requires %s", auth.PermSystemManage)
		}
	default:
		return badRequest("unsupported verifier_type %q", verType)
	}

	now := store.Now()
	nextRotation := now.Add(time.Duration(interval) * time.Second)

	existing, err := s.Store.Q.GetRotationPolicyBySecret(r.Context(), secretID)
	if err == nil {
		// Update existing
		err = s.Store.Q.UpdateRotationPolicy(r.Context(), db.UpdateRotationPolicyParams{
			IntervalSeconds: int32(interval),
			GeneratorType:   genType,
			GeneratorConfig: req.GeneratorConfig,
			VerifierType:    verType,
			VerifierConfig:  req.VerifierConfig,
			Status:          "active",
			Now:             now,
			ID:              existing.ID,
		})
		if err != nil {
			return fmt.Errorf("updating rotation policy: %w", err)
		}
		existing.IntervalSeconds = int32(interval)
		existing.GeneratorType = genType
		existing.GeneratorConfig = req.GeneratorConfig
		existing.VerifierType = verType
		existing.VerifierConfig = req.VerifierConfig
		existing.Status = "active"
		existing.UpdatedAt = now

		s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "rotation.policy_update", "rotation_policy", existing.ID, map[string]any{"secret": secret.Key, "interval": interval})
		return ok(w, toRotationDTO(existing, secret.Key, secret.Path))
	}

	// Create new policy
	policyID := uuid.NewString()
	err = s.Store.Q.CreateRotationPolicy(r.Context(), db.CreateRotationPolicyParams{
		ID:              policyID,
		SecretID:        secretID,
		IntervalSeconds: int32(interval),
		GeneratorType:   genType,
		GeneratorConfig: req.GeneratorConfig,
		VerifierType:    verType,
		VerifierConfig:  req.VerifierConfig,
		NextRotationAt:  nextRotation,
		Status:          "active",
		Now:             now,
	})
	if err != nil {
		return fromStore(err, "rotation policy")
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "rotation.policy_create", "rotation_policy", policyID, map[string]any{"secret": secret.Key, "interval": interval})

	createdPolicy := db.RotationPolicy{
		ID:              policyID,
		SecretID:        secretID,
		IntervalSeconds: int32(interval),
		GeneratorType:   genType,
		GeneratorConfig: req.GeneratorConfig,
		VerifierType:    verType,
		VerifierConfig:  req.VerifierConfig,
		NextRotationAt:  nextRotation,
		Status:          "active",
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	return ok(w, toRotationDTO(createdPolicy, secret.Key, secret.Path))
}

// openapi:operation
// summary: Delete secret rotation policy
// description: Removes rotation policy from secret.
// responses:
//   '204': { description: Policy removed }

func (s *Server) deleteRotationPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	secretID := r.PathValue("secret_id")
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}

	if _, err := s.getScopedSecret(r.Context(), projectID, envSlug, secretID); err != nil {
		return err
	}

	existing, err := s.Store.Q.GetRotationPolicyBySecret(r.Context(), secretID)
	if err != nil {
		return fromStore(err, "rotation policy")
	}

	n, err := s.Store.Q.DeleteRotationPolicy(r.Context(), existing.ID)
	if err != nil {
		return fromStore(err, "rotation policy")
	}
	if n == 0 {
		return notFound("rotation policy")
	}
	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "rotation.policy_delete", "rotation_policy", existing.ID, nil)
	return noContent(w)
}

// openapi:operation
// summary: Trigger immediate rotation
// description: Generates new credential, runs verification probe, and triggers automatic rollback if health check fails.
// responses:
//   '200': { description: Rotation result, schema: { $ref: '#/components/schemas/RotationRunResponse' } }

func (s *Server) runRotationNow(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	envSlug := r.PathValue("env_slug")
	secretID := r.PathValue("secret_id")
	if err := s.allowEnv(r, p, auth.PermSecretsWrite, projectID, envSlug); err != nil {
		return err
	}

	res, err := s.executeSecretRotation(r.Context(), projectID, envSlug, secretID, p)
	if err != nil {
		return err
	}
	return ok(w, res)
}

// executeSecretRotation executes the full rotation + probe + auto-rollback lifecycle.
func (s *Server) executeSecretRotation(ctx context.Context, projectID, envSlug, secretID string, p principal) (*rotationRunResponse, error) {
	secret, err := s.getScopedSecret(ctx, projectID, envSlug, secretID)
	if err != nil {
		return nil, err
	}

	policy, err := s.Store.Q.GetRotationPolicyBySecret(ctx, secretID)
	if err != nil {
		return nil, fromStore(err, "rotation policy")
	}

	// 1. Generate candidate secret value
	candidateValue, err := rotation.GenerateNewSecret(policy.GeneratorType, policy.GeneratorConfig)
	if err != nil {
		return nil, fmt.Errorf("generating secret: %w", err)
	}

	pv, err := s.projectVault(projectID)
	if err != nil {
		return nil, fmt.Errorf("deriving vault: %w", err)
	}

	// 2. Encrypt candidate value
	encVal, nonceVal, err := pv.Encrypt([]byte(candidateValue))
	if err != nil {
		return nil, fmt.Errorf("encrypting candidate secret: %w", err)
	}

	// Preserve old values for rollback
	oldEnc := secret.ValueEncrypted
	oldNonce := secret.ValueNonce
	oldVersion := secret.Version
	newVersion := oldVersion + 1
	now := store.Now()

	// 3. Stage candidate version in vault atomically with its version record
	if err := s.Store.Tx(ctx, func(q *db.Queries) error {
		if err := q.UpdateSecret(ctx, db.UpdateSecretParams{
			ValueEncrypted: encVal,
			ValueNonce:     nonceVal,
			Comment:        fmt.Sprintf("Automated rotation via %s", policy.GeneratorType),
			Now:            now,
			ID:             secret.ID,
		}); err != nil {
			return fmt.Errorf("updating secret with candidate version: %w", err)
		}
		if err := q.CreateSecretVersion(ctx, db.CreateSecretVersionParams{
			ID:             uuid.NewString(),
			SecretID:       secret.ID,
			Version:        newVersion,
			ValueEncrypted: encVal,
			ValueNonce:     nonceVal,
			Comment:        fmt.Sprintf("Rotated candidate v%d", newVersion),
			Now:            now,
			CreatedBy:      p.User.Username,
		}); err != nil {
			return fmt.Errorf("creating candidate secret version: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// 4. Run verification probe
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var probeErr error
	if policy.VerifierType == "script" && !s.AllowScripts {
		probeErr = fmt.Errorf("script rotation verifiers are disabled on this server")
	} else {
		probeErr = rotation.VerifySecretHealthWithOptions(probeCtx, policy.VerifierType, policy.VerifierConfig, candidateValue, rotation.VerifyOptions{
			AllowPrivate: s.AllowPrivateProbes,
		})
	}

	if probeErr != nil {
		// PROBE FAILED -> AUTOMATIC ROLLBACK TRIGGERED!
		rollbackVersion := newVersion + 1
		rollbackNow := store.Now()

		if err := s.Store.Tx(ctx, func(q *db.Queries) error {
			if err := q.RollbackSecret(ctx, db.RollbackSecretParams{
				ValueEncrypted: oldEnc,
				ValueNonce:     oldNonce,
				Comment:        fmt.Sprintf("AUTOMATIC ROLLBACK: verifier probe failed (%v)", probeErr),
				Version:        rollbackVersion,
				Now:            rollbackNow,
				ID:             secret.ID,
			}); err != nil {
				return fmt.Errorf("rolling back secret: %w", err)
			}
			if err := q.CreateSecretVersion(ctx, db.CreateSecretVersionParams{
				ID:             uuid.NewString(),
				SecretID:       secret.ID,
				Version:        rollbackVersion,
				ValueEncrypted: oldEnc,
				ValueNonce:     oldNonce,
				Comment:        fmt.Sprintf("Rolled back to v%d due to probe failure", oldVersion),
				Now:            rollbackNow,
				CreatedBy:      "system:auto_rollback",
			}); err != nil {
				return fmt.Errorf("recording rollback secret version: %w", err)
			}
			if err := q.RecordRotationFailure(ctx, db.RecordRotationFailureParams{
				LastError: probeErr.Error(),
				Now:       rollbackNow,
				ID:        policy.ID,
			}); err != nil {
				return fmt.Errorf("recording rotation failure: %w", err)
			}
			return nil
		}); err != nil {
			return nil, err
		}

		s.recordAudit(nil, p.IP, p.User.ID, p.User.Username, "rotation.rollback", "secret", secret.ID, map[string]any{
			"error":        probeErr.Error(),
			"restored_ver": oldVersion,
		})

		return &rotationRunResponse{
			Success:    false,
			RolledBack: true,
			Message:    fmt.Sprintf("Health verification probe failed: %v. Previous secret version restored automatically.", probeErr),
			NewVersion: rollbackVersion,
		}, nil
	}

	// 5. PROBE SUCCEEDED -> COMMIT ROTATION!
	nextRotation := now.Add(time.Duration(policy.IntervalSeconds) * time.Second)
	if err := s.Store.Q.RecordRotationSuccess(ctx, db.RecordRotationSuccessParams{
		LastRotatedAt:  sql.NullTime{Time: now, Valid: true},
		NextRotationAt: nextRotation,
		Now:            now,
		ID:             policy.ID,
	}); err != nil {
		return nil, fmt.Errorf("recording rotation success: %w", err)
	}

	s.recordAudit(nil, p.IP, p.User.ID, p.User.Username, "rotation.success", "secret", secret.ID, map[string]any{
		"version": newVersion,
		"type":    policy.GeneratorType,
	})

	return &rotationRunResponse{
		Success:    true,
		RolledBack: false,
		Message:    fmt.Sprintf("Secret successfully rotated to v%d and verified healthy.", newVersion),
		NewVersion: newVersion,
	}, nil
}

// ProcessPendingRotations executes due automated secret rotations. Called by the background ticker.
func (s *Server) ProcessPendingRotations(ctx context.Context) {
	now := store.Now()
	pending, err := s.Store.Q.ListPendingRotations(ctx, now)
	if err != nil {
		return
	}
	for _, p := range pending {
		systemPrincipal := principal{
			IP: "127.0.0.1",
			User: db.User{
				ID:       "system:scheduler",
				Username: "system:scheduler",
			},
		}
		_, _ = s.executeSecretRotation(ctx, p.ProjectID, p.EnvironmentSlug, p.SecretID, systemPrincipal)
	}
}
