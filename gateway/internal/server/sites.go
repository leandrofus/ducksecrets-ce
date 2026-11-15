package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

// openapi:schema Site
// type: object
// required: [id, project_id, name, token_prefix, description, online, created_at, updated_at]
// properties:
//   id: { type: string, format: uuid }
//   project_id: { type: string, format: uuid }
//   name: { type: string }
//   token_prefix: { type: string }
//   description: { type: string }
//   online: { type: boolean }
//   last_seen_at: { type: string, format: date-time, nullable: true }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }

type siteDTO struct {
	ID          string     `json:"id"`
	ProjectID   string     `json:"project_id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	Description string     `json:"description"`
	Online      bool       `json:"online"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// openapi:schema CreatedSite
// type: object
// required: [id, project_id, name, token, token_prefix, description, online, created_at, updated_at]
// properties:
//   id: { type: string, format: uuid }
//   project_id: { type: string, format: uuid }
//   name: { type: string }
//   token: { type: string }
//   token_prefix: { type: string }
//   description: { type: string }
//   online: { type: boolean }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }

type createdSiteDTO struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id"`
	Name        string    `json:"name"`
	Token       string    `json:"token"`
	TokenPrefix string    `json:"token_prefix"`
	Description string    `json:"description"`
	Online      bool      `json:"online"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// openapi:schema CreateSiteRequest
// type: object
// required: [name]
// additionalProperties: false
// properties:
//   name: { type: string }
//   description: { type: string }

type createSiteRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) toSiteDTO(st db.Site) siteDTO {
	var lastSeen *time.Time
	if st.LastSeenAt.Valid {
		t := st.LastSeenAt.Time.UTC()
		lastSeen = &t
	}
	online := false
	if s.Sites != nil {
		online = s.Sites.IsOnline(st.ID)
	}

	return siteDTO{
		ID:          st.ID,
		ProjectID:   st.ProjectID,
		Name:        st.Name,
		TokenPrefix: st.TokenPrefix,
		Description: st.Description,
		Online:      online,
		LastSeenAt:  lastSeen,
		CreatedAt:   st.CreatedAt.UTC(),
		UpdatedAt:   st.UpdatedAt.UTC(),
	}
}

// openapi:operation
// summary: List project network sites
// description: Returns all remote network sites configured for this project.
// responses:
//   '200': { description: Sites list, schema: { type: array, items: { $ref: '#/components/schemas/Site' } } }

func (s *Server) listSites(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	if err := s.allow(r, p, auth.PermSecretsRead, "project", projectID); err != nil {
		return err
	}

	rows, err := s.Store.Q.ListSites(r.Context(), projectID)
	if err != nil {
		return fromStore(err, "sites")
	}

	res := make([]siteDTO, len(rows))
	for i, row := range rows {
		res[i] = s.toSiteDTO(row)
	}
	return ok(w, res)
}

// openapi:operation
// summary: Register new network site
// description: Generates a new Site identity with reverse tunnel token (duck_site_*).
// requestBody: { schema: CreateSiteRequest }
// responses:
//   '201': { description: Created site, schema: { $ref: '#/components/schemas/CreatedSite' } }

func (s *Server) createSite(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	if err := s.allow(r, p, auth.PermSecretsWrite, "project", projectID); err != nil {
		return err
	}

	var req createSiteRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return badRequest("site name is required")
	}

	totalSites, err := s.Store.Q.CountAllSites(r.Context())
	if err != nil {
		return fmt.Errorf("counting sites: %w", err)
	}
	if err := s.licenseMgr().CanCreateSite(totalSites); err != nil {
		return paymentRequired("%v", err)
	}

	// Generate high-entropy token: duck_site_<prefix>_<secret>
	prefixBytes := make([]byte, 4)
	_, _ = rand.Read(prefixBytes)
	prefix := "duck_site_" + hex.EncodeToString(prefixBytes)

	secretBytes := make([]byte, 24)
	_, _ = rand.Read(secretBytes)
	rawToken := prefix + "_" + hex.EncodeToString(secretBytes)

	tokenHashBytes := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	siteID := uuid.NewString()
	now := store.Now()

	err = s.Store.Q.CreateSite(r.Context(), db.CreateSiteParams{
		ID:          siteID,
		ProjectID:   projectID,
		Name:        name,
		TokenHash:   tokenHash,
		TokenPrefix: prefix,
		Description: strings.TrimSpace(req.Description),
		Now:         now,
	})
	if err != nil {
		return fromStore(err, "site")
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "site.create", "site", siteID, map[string]any{"name": name})

	return created(w, createdSiteDTO{
		ID:          siteID,
		ProjectID:   projectID,
		Name:        name,
		Token:       rawToken,
		TokenPrefix: prefix,
		Description: strings.TrimSpace(req.Description),
		Online:      false,
		CreatedAt:   now.UTC(),
		UpdatedAt:   now.UTC(),
	})
}

// openapi:operation
// summary: Delete network site
// description: Removes a network site and disconnects its active reverse tunnels.
// responses:
//   '204': { description: Site deleted }

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request, p principal) error {
	projectID := r.PathValue("id")
	siteID := r.PathValue("site_id")
	if err := s.allow(r, p, auth.PermSecretsWrite, "project", projectID); err != nil {
		return err
	}

	site, err := s.Store.Q.GetSite(r.Context(), siteID)
	if err != nil {
		return fromStore(err, "site")
	}
	if site.ProjectID != projectID {
		return notFound("site")
	}

	if s.Sites != nil {
		s.Sites.Unregister(siteID, nil)
	}

	n, err := s.Store.Q.DeleteSite(r.Context(), siteID)
	if err != nil {
		return fromStore(err, "site")
	}
	if n == 0 {
		return notFound("site")
	}

	s.recordAudit(r, p.IP, p.User.ID, p.User.Username, "site.delete", "site", siteID, nil)
	return noContent(w)
}

func (s *Server) authenticateSite(r *http.Request, siteID string) (*db.Site, error) {
	token := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		return nil, &apiError{http.StatusUnauthorized, "unauthorized", "site token required"}
	}

	tokenHashBytes := sha256.Sum256([]byte(strings.TrimSpace(token)))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	site, err := s.Store.Q.GetSiteByTokenHash(r.Context(), tokenHash)
	if err != nil {
		return nil, &apiError{http.StatusUnauthorized, "unauthorized", "invalid site token"}
	}
	if site.ID != siteID {
		return nil, &apiError{http.StatusUnauthorized, "unauthorized", "token does not match site"}
	}

	return &site, nil
}

// openapi:operation
// summary: Connect remote site connector agent (Reverse Tunnel Control)
// description: Upgrades to a persistent WebSocket reverse tunnel control channel from a remote private network.
// responses:
//   '101': { description: Switching to WebSocket control channel }

func (s *Server) connectSite(w http.ResponseWriter, r *http.Request, p principal) error {
	siteID := r.PathValue("site_id")
	site, err := s.authenticateSite(r, siteID)
	if err != nil {
		return err
	}

	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil // Accept answered
	}
	defer ws.Close(websocket.StatusNormalClosure, "site connector disconnected")

	if s.Sites != nil {
		s.Sites.Register(site.ID, ws)
		defer s.Sites.Unregister(site.ID, ws)
	}

	// Update last_seen_at
	_ = s.Store.Q.UpdateSiteLastSeen(r.Context(), db.UpdateSiteLastSeenParams{
		Now: sql.NullTime{Time: store.Now(), Valid: true},
		ID:  site.ID,
	})

	// Keep alive ticker
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	// Wait for disconnection
	readCtx := ws.CloseRead(r.Context())
	for {
		select {
		case <-readCtx.Done():
			return nil
		case <-ticker.C:
			pingCtx, pingCancel := context.WithTimeout(r.Context(), 5*time.Second)
			err := ws.Ping(pingCtx)
			pingCancel()
			if err != nil {
				return nil
			}
		}
	}
}

// openapi:operation
// summary: Connect remote site data stream
// description: Connects a multiplexed reverse TCP data stream to a target service via WebSocket.
// responses:
//   '101': { description: Switching to WebSocket data stream }

func (s *Server) connectStream(w http.ResponseWriter, r *http.Request, p principal) error {
	siteID := r.PathValue("site_id")
	streamID := r.PathValue("stream_id")
	if _, err := s.authenticateSite(r, siteID); err != nil {
		return err
	}

	if s.Sites == nil {
		return fmt.Errorf("sites manager unavailable")
	}
	if !s.Sites.HasPendingStream(streamID) {
		return badRequest("no pending stream request with ID %q", streamID)
	}

	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil
	}
	defer ws.Close(websocket.StatusNormalClosure, "stream closed")

	netConn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
	defer netConn.Close()

	if err := s.Sites.AttachStream(streamID, netConn); err != nil {
		return nil
	}

	// Wait for stream to finish
	<-r.Context().Done()
	return nil
}
