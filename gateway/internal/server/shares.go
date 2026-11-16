package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// openapi:schema ShareCreated
// type: object
// required: [id, expires_at, max_views, has_passphrase, created_at]
// properties:
//   id: { type: string }
//   expires_at: { type: string, format: date-time }
//   max_views: { type: integer }
//   has_passphrase: { type: boolean }
//   created_at: { type: string, format: date-time }

type shareCreatedDTO struct {
	ID            string    `json:"id"`
	ExpiresAt     time.Time `json:"expires_at"`
	MaxViews      int32     `json:"max_views"`
	HasPassphrase bool      `json:"has_passphrase"`
	CreatedAt     time.Time `json:"created_at"`
}

// openapi:schema ShareMetadata
// type: object
// required: [id, expires_at, max_views, view_count, has_passphrase, created_at]
// properties:
//   id: { type: string }
//   expires_at: { type: string, format: date-time }
//   max_views: { type: integer }
//   view_count: { type: integer }
//   has_passphrase: { type: boolean }
//   passphrase_salt: { type: string }
//   created_at: { type: string, format: date-time }

type shareMetadataDTO struct {
	ID             string    `json:"id"`
	ExpiresAt      time.Time `json:"expires_at"`
	MaxViews       int32     `json:"max_views"`
	ViewCount      int32     `json:"view_count"`
	HasPassphrase  bool      `json:"has_passphrase"`
	PassphraseSalt string    `json:"passphrase_salt,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// openapi:schema ShareReveal
// type: object
// required: [id, ciphertext, nonce, has_passphrase, view_count, max_views, burned]
// properties:
//   id: { type: string }
//   ciphertext: { type: string }
//   nonce: { type: string }
//   has_passphrase: { type: boolean }
//   passphrase_salt: { type: string }
//   view_count: { type: integer }
//   max_views: { type: integer }
//   burned: { type: boolean }

type shareRevealDTO struct {
	ID             string `json:"id"`
	Ciphertext     string `json:"ciphertext"`
	Nonce          string `json:"nonce"`
	HasPassphrase  bool   `json:"has_passphrase"`
	PassphraseSalt string `json:"passphrase_salt,omitempty"`
	ViewCount      int32  `json:"view_count"`
	MaxViews       int32  `json:"max_views"`
	Burned         bool   `json:"burned"`
}

// openapi:schema CreateShareRequest
// type: object
// required: [ciphertext, nonce]
// additionalProperties: false
// properties:
//   ciphertext: { type: string }
//   nonce: { type: string }
//   ttl_seconds: { type: integer }
//   max_views: { type: integer }
//   has_passphrase: { type: boolean }
//   passphrase_salt: { type: string }

type createShareRequest struct {
	Ciphertext     string `json:"ciphertext"`
	Nonce          string `json:"nonce"`
	TTLSeconds     int    `json:"ttl_seconds"`
	MaxViews       int    `json:"max_views"`
	HasPassphrase  bool   `json:"has_passphrase"`
	PassphraseSalt string `json:"passphrase_salt"`
}

// openapi:operation
// summary: Create ephemeral secret share
// description: Stores a client-encrypted payload for zero-knowledge one-time or time-limited sharing.
// requestBody:
//   schema: { $ref: '#/components/schemas/CreateShareRequest' }
// responses:
//   '201': { description: Share created, schema: { $ref: '#/components/schemas/ShareCreated' } }

func (s *Server) createShare(w http.ResponseWriter, r *http.Request, p principal) error {
	var req createShareRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Ciphertext == "" {
		return badRequest("ciphertext is required")
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return badRequest("invalid base64 ciphertext: %v", err)
	}
	if len(cipherBytes) > 131072 { // 128KB max
		return badRequest("ciphertext exceeds maximum allowed size of 128KB")
	}

	if req.Nonce == "" {
		return badRequest("nonce is required")
	}
	nonceBytes, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonceBytes) != 12 {
		return badRequest("nonce must be base64-encoded 12 bytes")
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 86400 // 24 hours default
	} else if ttl > 2592000 { // 30 days max
		ttl = 2592000
	}

	maxViews := int32(req.MaxViews)
	if maxViews <= 0 {
		maxViews = 1
	} else if maxViews > 100 {
		maxViews = 100
	}

	var saltBytes []byte
	if req.HasPassphrase && req.PassphraseSalt != "" {
		saltBytes, err = base64.StdEncoding.DecodeString(req.PassphraseSalt)
		if err != nil {
			return badRequest("invalid passphrase salt: %v", err)
		}
	}

	// Generate random 16-hex ID
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return fmt.Errorf("generating share ID: %w", err)
	}
	shareID := "sh_" + hex.EncodeToString(idBytes)

	now := store.Now()
	expiresAt := now.Add(time.Duration(ttl) * time.Second)

	createdBy := ""
	if res, err := s.resolve(r); err == nil && res.User.Username != "" {
		p = res
		createdBy = res.User.Username
	}

	err = s.Store.Q.CreateShare(r.Context(), db.CreateShareParams{
		ID:             shareID,
		Ciphertext:     cipherBytes,
		Nonce:          nonceBytes,
		ExpiresAt:      expiresAt,
		MaxViews:       maxViews,
		HasPassphrase:  req.HasPassphrase,
		PassphraseSalt: saltBytes,
		CreatedBy:      createdBy,
		Now:            now,
	})
	if err != nil {
		return fmt.Errorf("creating share: %w", err)
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "share.create", "share", shareID, map[string]any{"ttl_seconds": ttl, "max_views": maxViews})

	return created(w, shareCreatedDTO{
		ID:            shareID,
		ExpiresAt:     expiresAt.UTC(),
		MaxViews:      maxViews,
		HasPassphrase: req.HasPassphrase,
		CreatedAt:     now.UTC(),
	})
}

// openapi:operation
// summary: List user active shares
// description: Returns the list of unexpired shares created by the authenticated user.
// responses:
//   '200': { description: User active shares, schema: { type: array, items: { $ref: '#/components/schemas/ShareMetadata' } } }

func (s *Server) listMyShares(w http.ResponseWriter, r *http.Request, p principal) error {
	shares, err := s.Store.Q.ListSharesByCreator(r.Context(), p.User.Username)
	if err != nil {
		return fmt.Errorf("listing shares: %w", err)
	}
	now := store.Now()
	res := make([]shareMetadataDTO, 0, len(shares))
	for _, sh := range shares {
		if now.After(sh.ExpiresAt) || sh.BurnedAt.Valid || sh.ViewCount >= sh.MaxViews {
			continue
		}
		dto := shareMetadataDTO{
			ID:            sh.ID,
			ExpiresAt:     sh.ExpiresAt.UTC(),
			MaxViews:      sh.MaxViews,
			ViewCount:     sh.ViewCount,
			HasPassphrase: sh.HasPassphrase,
			CreatedAt:     sh.CreatedAt.UTC(),
		}
		if len(sh.PassphraseSalt) > 0 {
			dto.PassphraseSalt = base64.StdEncoding.EncodeToString(sh.PassphraseSalt)
		}
		res = append(res, dto)
	}
	return ok(w, res)
}

// openapi:operation
// summary: Get ephemeral share metadata
// description: Returns public metadata of a share without revealing or consuming it.
// responses:
//   '200': { description: Share metadata, schema: { $ref: '#/components/schemas/ShareMetadata' } }

func (s *Server) getShareMetadata(w http.ResponseWriter, r *http.Request, p principal) error {
	id := r.PathValue("id")
	share, err := s.Store.Q.GetShareMetadata(r.Context(), id)
	if err != nil {
		if errors.Is(store.Classify(err), store.ErrNotFound) {
			return notFound("share")
		}
		return fmt.Errorf("reading share metadata: %w", err)
	}

	now := store.Now()
	if now.After(share.ExpiresAt) || share.BurnedAt.Valid || share.ViewCount >= share.MaxViews {
		return notFound("share")
	}

	dto := shareMetadataDTO{
		ID:            share.ID,
		ExpiresAt:     share.ExpiresAt.UTC(),
		MaxViews:      share.MaxViews,
		ViewCount:     share.ViewCount,
		HasPassphrase: share.HasPassphrase,
		CreatedAt:     share.CreatedAt.UTC(),
	}
	if len(share.PassphraseSalt) > 0 {
		dto.PassphraseSalt = base64.StdEncoding.EncodeToString(share.PassphraseSalt)
	}

	return ok(w, dto)
}

// openapi:operation
// summary: Reveal ephemeral share
// description: Consumes one view of the ephemeral share and returns the encrypted ciphertext and nonce. If max views is reached, it is permanently burned.
// responses:
//   '200': { description: Share ciphertext payload, schema: { $ref: '#/components/schemas/ShareReveal' } }

func (s *Server) revealShare(w http.ResponseWriter, r *http.Request, p principal) error {
	id := r.PathValue("id")
	now := store.Now()

	var share db.Share
	var burned bool
	err := s.Store.Tx(r.Context(), func(q *db.Queries) error {
		n, err := q.ConsumeShareView(r.Context(), db.ConsumeShareViewParams{
			ID:  id,
			Now: now,
		})
		if err != nil {
			return fmt.Errorf("consuming share view: %w", err)
		}
		if n == 0 {
			return notFound("share")
		}

		row, err := q.GetShareForReveal(r.Context(), id)
		if err != nil {
			if errors.Is(store.Classify(err), store.ErrNotFound) {
				return notFound("share")
			}
			return fmt.Errorf("reading share: %w", err)
		}
		share = row
		burned = share.ViewCount >= share.MaxViews
		if burned {
			if err := q.BurnShare(r.Context(), db.BurnShareParams{
				BurnedAt:        sql.NullTime{Time: now, Valid: true},
				EmptyCiphertext: []byte{},
				EmptyNonce:      []byte{},
				ID:              id,
			}); err != nil {
				return fmt.Errorf("burning share: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "share.reveal", "share", id, map[string]any{"views": share.ViewCount, "burned": burned})

	dto := shareRevealDTO{
		ID:            share.ID,
		Ciphertext:    base64.StdEncoding.EncodeToString(share.Ciphertext),
		Nonce:         base64.StdEncoding.EncodeToString(share.Nonce),
		HasPassphrase: share.HasPassphrase,
		ViewCount:     share.ViewCount,
		MaxViews:      share.MaxViews,
		Burned:        burned,
	}
	if len(share.PassphraseSalt) > 0 {
		dto.PassphraseSalt = base64.StdEncoding.EncodeToString(share.PassphraseSalt)
	}

	w.Header().Set("Cache-Control", "no-store")
	return ok(w, dto)
}

// openapi:operation
// summary: Revoke ephemeral share
// description: Immediately deletes and destroys an ephemeral share link.
// responses:
//   '204': { description: Share revoked }

func (s *Server) deleteShare(w http.ResponseWriter, r *http.Request, p principal) error {
	id := r.PathValue("id")
	share, err := s.Store.Q.GetShareMetadata(r.Context(), id)
	if err != nil {
		if errors.Is(store.Classify(err), store.ErrNotFound) {
			return notFound("share")
		}
		return fmt.Errorf("reading share: %w", err)
	}

	if (share.CreatedBy == "" || share.CreatedBy != p.User.Username) && !auth.Has(p.Perms, auth.PermSystemManage) {
		return forbidden("only creator or admin can delete this share")
	}

	rows, err := s.Store.Q.DeleteShare(r.Context(), id)
	if err != nil {
		return fmt.Errorf("deleting share: %w", err)
	}
	if rows == 0 {
		return notFound("share")
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "share.delete", "share", id, nil)
	return noContent(w)
}
