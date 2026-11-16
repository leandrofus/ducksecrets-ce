package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/selfupdate"
)

// openapi:schema UpdateStatus
// type: object
// required: [repo, current_version, latest_version, update_available]
// properties:
//   repo: { type: string }
//   current_version: { type: string }
//   latest_version: { type: string }
//   update_available: { type: boolean }
//   release_url: { type: string }
//   published_at: { type: string }
//   asset_name: { type: string }
//   expected_sha256: { type: string }
//   error: { type: string }

type updateStatusDTO struct {
	Repo            string `json:"repo"`
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      string `json:"release_url,omitempty"`
	PublishedAt     string `json:"published_at,omitempty"`
	AssetName       string `json:"asset_name,omitempty"`
	ExpectedSHA256  string `json:"expected_sha256,omitempty"`
	Error           string `json:"error,omitempty"`
}

// openapi:schema ApplyUpdateRequest
// type: object
// additionalProperties: false
// properties:
//   version: { type: string }
//   force: { type: boolean }

type applyUpdateRequest struct {
	Version string `json:"version"`
	Force   bool   `json:"force"`
}

// openapi:schema ApplyUpdateResponse
// type: object
// required: [ok, updated, previous_version, new_version, restart_required, message]
// properties:
//   ok: { type: boolean }
//   updated: { type: boolean }
//   previous_version: { type: string }
//   new_version: { type: string }
//   target_path: { type: string }
//   expected_sha256: { type: string }
//   actual_sha256: { type: string }
//   restart_required: { type: boolean }
//   message: { type: string }

type applyUpdateResponse struct {
	OK              bool   `json:"ok"`
	Updated         bool   `json:"updated"`
	PreviousVersion string `json:"previous_version"`
	NewVersion      string `json:"new_version"`
	TargetPath      string `json:"target_path,omitempty"`
	ExpectedSHA256  string `json:"expected_sha256,omitempty"`
	ActualSHA256    string `json:"actual_sha256,omitempty"`
	RestartRequired bool   `json:"restart_required"`
	Message         string `json:"message"`
}

func (s *Server) updateOptions(targetTag string, force bool) selfupdate.Options {
	ver := s.Version
	if ver == "" {
		ver = "dev"
	}
	return selfupdate.Options{
		BinaryName:     "ducksecretsd",
		CurrentVersion: ver,
		TargetTag:      targetTag,
		Repo:           s.UpdateRepo,
		APIBase:        s.UpdateAPIBase,
		TargetPath:     s.UpdateTargetPath,
		Force:          force,
	}
}

// openapi:operation
// summary: Check for public release updates
// description: Checks the latest release tag in the public repository (leandrofus/ducksecrets-ce) against the running server version.
// responses:
//   '200': { description: Update status check result, schema: UpdateStatus }

func (s *Server) getUpdateStatus(w http.ResponseWriter, r *http.Request, _ principal) error {
	opts := s.updateOptions("", false)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	info, err := selfupdate.Check(ctx, opts)
	if err != nil {
		// Return 200 with Error populated so air-gapped dashboards render cleanly.
		repo := opts.Repo
		if repo == "" {
			repo = selfupdate.DefaultRepo
		}
		return ok(w, updateStatusDTO{
			Repo:           repo,
			CurrentVersion: opts.CurrentVersion,
			LatestVersion:  opts.CurrentVersion,
			Error:          err.Error(),
		})
	}
	return ok(w, updateStatusDTO{
		Repo:            info.Repo,
		CurrentVersion:  info.CurrentVersion,
		LatestVersion:   info.LatestVersion,
		UpdateAvailable: info.UpdateAvailable,
		ReleaseURL:      info.ReleaseURL,
		PublishedAt:     info.PublishedAt,
		AssetName:       info.AssetName,
		ExpectedSHA256:  info.ExpectedSHA256,
	})
}

// openapi:operation
// summary: Apply verified self-update from public release
// description: Downloads the matching ducksecretsd release binary from leandrofus/ducksecrets-ce, verifies its SHA256SUMS digest, and atomically replaces the executable on disk.
// requestBody: { schema: ApplyUpdateRequest }
// responses:
//   '200': { description: Self-update result, schema: ApplyUpdateResponse }

func (s *Server) applySystemUpdate(w http.ResponseWriter, r *http.Request, p principal) error {
	var in applyUpdateRequest
	if r.ContentLength > 0 {
		if err := decode(r, &in); err != nil {
			return err
		}
	}

	opts := s.updateOptions(in.Version, in.Force)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	res, err := selfupdate.Apply(ctx, opts)
	if err != nil {
		return badRequest("self-update failed: %v", err)
	}
	if !res.Updated {
		return ok(w, applyUpdateResponse{
			OK:              true,
			Updated:         false,
			PreviousVersion: res.CurrentVersion,
			NewVersion:      res.LatestVersion,
			TargetPath:      res.TargetPath,
			ExpectedSHA256:  res.ExpectedSHA256,
			RestartRequired: false,
			Message:         fmt.Sprintf("Already running the latest version (%s).", res.CurrentVersion),
		})
	}

	s.record(r, p, "system.updated", "system", "binary", map[string]any{
		"previous_version": res.CurrentVersion,
		"new_version":      res.LatestVersion,
		"sha256":           res.ActualSHA,
		"repo":             res.Repo,
	})

	return ok(w, applyUpdateResponse{
		OK:              true,
		Updated:         true,
		PreviousVersion: res.CurrentVersion,
		NewVersion:      res.LatestVersion,
		TargetPath:      res.TargetPath,
		ExpectedSHA256:  res.ExpectedSHA256,
		ActualSHA256:    res.ActualSHA,
		RestartRequired: true,
		Message:         fmt.Sprintf("Updated binary to %s (SHA-256 verified). Restart the daemon service to activate the new version.", res.LatestVersion),
	})
}
