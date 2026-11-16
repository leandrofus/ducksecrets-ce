package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

const (
	sessionCookie = "ducksecrets_session"
	// Mutating requests must carry this header. Browsers cannot add custom
	// headers to cross-site requests without a CORS preflight we never
	// answer, so together with SameSite=Strict cookies it stops CSRF.
	csrfHeader = "X-Ducksecrets-Request"
)

// principal is who is calling.
type principal struct {
	IP          string
	User        db.User
	SessionHash string
	// Perms: the user's global permissions (auth.PermAll for everything).
	Perms        []string
	ServiceToken *db.ServiceToken
}

// who names the caller for audit records and logs.
func (p principal) who() (id, username string) {
	return p.User.ID, p.User.Username
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, p principal) error

func checkCSRF(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, "LIST":
		return nil
	}
	// Machine identities with Bearer tokens or X-Vault-Token are exempt from cookie CSRF protection
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || strings.TrimSpace(r.Header.Get("X-Vault-Token")) != "" {
		return nil
	}
	if r.Header.Get(csrfHeader) == "" {
		return &apiError{http.StatusForbidden, "csrf", "missing " + csrfHeader + " header"}
	}
	return nil
}

// public needs no session (still the CSRF header on writes).
func (s *Server) public(h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := checkCSRF(r); err != nil {
			writeErr(w, err)
			return
		}
		p := principal{IP: s.clientIP(r)}
		if err := h(w, r, p); err != nil {
			writeErr(w, err)
		}
	})
}

func (s *Server) resolveTokenString(r *http.Request, token string) (principal, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return principal{}, errUnauthorized
	}
	if strings.HasPrefix(token, "duck_st_") {
		return s.resolveServiceToken(r, token)
	}
	sess, err := s.Auth.Session(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrNoSession) {
			return principal{}, errUnauthorized
		}
		return principal{}, err
	}
	perms, err := s.Auth.Permissions(r.Context(), sess.User.Role)
	if err != nil {
		return principal{}, err
	}
	return principal{IP: s.clientIP(r), User: sess.User, SessionHash: sess.IDHash, Perms: perms}, nil
}

func (s *Server) resolve(r *http.Request) (principal, error) {
	// 1. Check for X-Vault-Token (HashiCorp Vault compatibility)
	if vaultTok := strings.TrimSpace(r.Header.Get("X-Vault-Token")); vaultTok != "" {
		return s.resolveTokenString(r, vaultTok)
	}

	// 2. Check for Bearer token in Authorization header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		return s.resolveTokenString(r, token)
	}

	// 3. Fallback to standard web session cookie
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return principal{}, errUnauthorized
	}
	return s.resolveTokenString(r, c.Value)
}

func (s *Server) resolveServiceToken(r *http.Request, token string) (principal, error) {
	h := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(h[:])

	st, err := s.Store.Q.GetServiceTokenByHash(r.Context(), tokenHash)
	if err != nil {
		return principal{}, errUnauthorized
	}
	if st.ExpiresAt.Valid && st.ExpiresAt.Time.Before(time.Now()) {
		return principal{}, forbidden("service token has expired")
	}
	if st.BurnedAt.Valid {
		return principal{}, forbidden("single-use service token has already been consumed")
	}

	clientIP := s.clientIP(r)
	if strings.TrimSpace(st.AllowedCidrs) != "" {
		if !isIPAllowed(clientIP, st.AllowedCidrs) {
			return principal{}, forbidden("client IP %s is not authorized for this service token", clientIP)
		}
	}

	// Touch last used in background
	go func() {
		_ = s.Store.Q.TouchServiceToken(context.Background(), db.TouchServiceTokenParams{
			ID:  st.ID,
			Now: store.NullTime(store.Now()),
		})
	}()

	perms := strings.Fields(st.Permissions)
	user := db.User{
		ID:          st.ID,
		Username:    "token:" + st.Name,
		DisplayName: st.Name,
		Role:        "service_token",
	}

	return principal{
		IP:           clientIP,
		User:         user,
		SessionHash:  st.TokenPrefix,
		Perms:        perms,
		ServiceToken: &st,
	}, nil
}

func isIPAllowed(clientIPStr string, rawAllowed string) bool {
	rawAllowed = strings.TrimSpace(rawAllowed)
	if rawAllowed == "" {
		return true // No restriction
	}
	clientAddr, err := netip.ParseAddr(clientIPStr)
	if err != nil {
		return false
	}
	clientAddr = clientAddr.Unmap()

	parts := strings.FieldsFunc(rawAllowed, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			if prefix, err := netip.ParsePrefix(part); err == nil {
				if prefix.Contains(clientAddr) {
					return true
				}
			}
		} else {
			if addr, err := netip.ParseAddr(part); err == nil {
				if addr.Unmap() == clientAddr {
					return true
				}
			}
		}
	}
	return false
}

// signedIn requires a session; what the caller may do is checked inside.
func (s *Server) signedIn(h handlerFunc) http.Handler {
	return s.can("", h)
}

// userSignedIn requires a human web session (rejects project service tokens).
func (s *Server) userSignedIn(h handlerFunc) http.Handler {
	return s.userCan("", h)
}

// userCan requires a human web session whose role grants perm (rejects service tokens).
func (s *Server) userCan(perm string, h handlerFunc) http.Handler {
	return s.can(perm, func(w http.ResponseWriter, r *http.Request, p principal) error {
		if p.ServiceToken != nil {
			return forbidden("service tokens cannot access this endpoint")
		}
		return h(w, r, p)
	})
}

// can requires a session whose role grants perm ("" for any session).
func (s *Server) can(perm string, h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := checkCSRF(r); err != nil {
			writeErr(w, err)
			return
		}
		p, err := s.resolve(r)
		switch {
		case err != nil:
			writeErr(w, err)
		case perm != "" && !auth.Has(p.Perms, perm):
			writeErr(w, forbidden("missing permission %s", perm))
		default:
			if err := h(w, r, p); err != nil {
				writeErr(w, err)
			}
		}
	})
}

// record writes an audit event. A failure is logged, never shown to the
// client: the change it describes already happened.
func (s *Server) record(r *http.Request, p principal, action, targetType, targetID string, details any) {
	id, username := p.who()
	s.recordAudit(r, p.IP, id, username, action, targetType, targetID, details)
}

// changed tells live clients (ws, sse) that an object changed, and drops
// cached reads of its type. Events carry ids only: clients refetch through
// the API, which applies permissions.
func (s *Server) changed(r *http.Request, objType, id string) {
	s.Events.Publish(r.Context(), objType+".changed", id)
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func remoteAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// clientIP is the address the request came from. Behind trusted proxies it
// is the right-most X-Forwarded-For entry that is not one of them: entries
// further left were written by the client and prove nothing.
func (s *Server) clientIP(r *http.Request) string {
	addr := remoteAddr(r)
	if !addr.IsValid() {
		return r.RemoteAddr
	}
	if !s.trusted(addr) {
		return addr.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // garbage: stop at the last address we could trust
		}
		addr = a.Unmap()
		if !s.trusted(addr) {
			break
		}
	}
	return addr.String()
}

// secureRequest reports whether the browser reached us over HTTPS.
func (s *Server) secureRequest(r *http.Request) bool {
	if r.TLS != nil || s.SecureCookies {
		return true
	}
	return s.trusted(remoteAddr(r)) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// ParseProxies parses a comma-separated list of addresses and CIDRs.
func ParseProxies(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(list, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", f, err)
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", f, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
