// Package auth authenticates users: local passwords (bcrypt) and web
// sessions stored in the database (only the hash of the cookie value).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

var (
	ErrInvalid   = errors.New("invalid credentials")
	ErrDisabled  = errors.New("user disabled")
	ErrNoSession = errors.New("no valid session")
)

const (
	SessionAbsolute = 12 * time.Hour
	SessionIdle     = 30 * time.Minute
	MinPassword     = 10
)

type Service struct {
	Store *store.Store
}

func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func CheckPasswordPolicy(pw string) error {
	if len([]rune(pw)) < MinPassword {
		return errors.New("password must have at least 10 characters")
	}
	if len([]byte(pw)) > 72 {
		return errors.New("password must not exceed 72 bytes")
	}
	return nil
}

// RandomPassword is for bootstrap accounts: 24 hex characters.
func RandomPassword() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// dummyHash keeps unknown-user logins as slow as real ones.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("ducksecrets-dummy"), bcrypt.DefaultCost)

// Authenticate checks a username/password.
func (s *Service) Authenticate(ctx context.Context, username, password string) (db.User, error) {
	u, err := s.Store.Q.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(store.Classify(err), store.ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
			return db.User{}, ErrInvalid
		}
		return db.User{}, err
	}
	// Non-local / uninitialized hashes (e.g. external PAM users with empty hash)
	// still run a constant-time dummy comparison to avoid username enumeration.
	if u.PasswordHash == "" || !strings.HasPrefix(u.PasswordHash, "$2") {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return db.User{}, ErrInvalid
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return db.User{}, ErrInvalid
	}
	if u.Disabled {
		return db.User{}, ErrDisabled
	}
	return u, nil
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// NewSession creates a web session and returns the cookie value.
func (s *Service) NewSession(ctx context.Context, userID, ip, ua string) (string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	now := store.Now()
	err := s.Store.Q.CreateWebSession(ctx, db.CreateWebSessionParams{
		IDHash: hashToken(tok), UserID: userID, IP: ip, UserAgent: ua, Now: now, ExpiresAt: now.Add(SessionAbsolute),
	})
	return tok, err
}

type Session struct {
	IDHash string
	User   db.User
}

// Session resolves a cookie value, enforcing absolute and idle expiry and
// sliding the idle window.
func (s *Service) Session(ctx context.Context, tok string) (Session, error) {
	if tok == "" {
		return Session{}, ErrNoSession
	}
	h := hashToken(tok)
	ws, err := s.Store.Q.GetWebSession(ctx, h)
	if err != nil {
		if errors.Is(store.Classify(err), store.ErrNotFound) {
			return Session{}, ErrNoSession
		}
		return Session{}, err
	}
	now := store.Now()
	if now.After(ws.ExpiresAt) || now.Sub(ws.LastSeenAt) > SessionIdle {
		if err := s.Store.Q.DeleteWebSession(ctx, h); err != nil {
			return Session{}, err
		}
		return Session{}, ErrNoSession
	}
	u, err := s.Store.Q.GetUser(ctx, ws.UserID)
	if err != nil {
		if errors.Is(store.Classify(err), store.ErrNotFound) {
			if delErr := s.Store.Q.DeleteWebSession(ctx, h); delErr != nil {
				return Session{}, delErr
			}
			return Session{}, ErrNoSession
		}
		return Session{}, err
	}
	if u.Disabled {
		if delErr := s.Store.Q.DeleteWebSession(ctx, h); delErr != nil {
			return Session{}, delErr
		}
		return Session{}, ErrNoSession
	}
	// Write at most once a minute.
	if now.Sub(ws.LastSeenAt) > time.Minute {
		if err := s.Store.Q.TouchWebSession(ctx, db.TouchWebSessionParams{IDHash: h, Now: now}); err != nil {
			return Session{}, err
		}
	}
	return Session{IDHash: h, User: u}, nil
}

func (s *Service) EndSession(ctx context.Context, idHash string) error {
	return s.Store.Q.DeleteWebSession(ctx, idHash)
}

// PurgeExpired deletes dead sessions; run it periodically.
func (s *Service) PurgeExpired(ctx context.Context) (int64, error) {
	now := store.Now()
	return s.Store.Q.DeleteExpiredWebSessions(ctx, db.DeleteExpiredWebSessionsParams{Now: now, IdleBefore: now.Add(-SessionIdle)})
}

// ResetPassword sets an existing user's password and revokes active web sessions.
func (s *Service) ResetPassword(ctx context.Context, username, password string) error {
	if err := CheckPasswordPolicy(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.Store.Tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUserByUsername(ctx, username)
		if err != nil {
			return err
		}
		if err := q.SetUserPassword(ctx, db.SetUserPasswordParams{
			ID: u.ID, PasswordHash: hash, Now: store.Now(),
		}); err != nil {
			return err
		}
		return q.DeleteUserWebSessions(ctx, u.ID)
	})
}

// Bootstrap creates the first admin when there are no users. It returns the
// generated password ("" when password was given or users already exist).
func (s *Service) Bootstrap(ctx context.Context, username, password string) (string, error) {
	if password != "" {
		if err := CheckPasswordPolicy(password); err != nil {
			return "", err
		}
	}
	var generated string
	err := s.Store.Tx(ctx, func(q *db.Queries) error {
		n, err := q.CountUsers(ctx)
		if err != nil || n > 0 {
			return err
		}
		pw := password
		if pw == "" {
			pw = RandomPassword()
			generated = pw
		}
		hash, err := HashPassword(pw)
		if err != nil {
			return err
		}
		return q.CreateUser(ctx, db.CreateUserParams{
			ID: store.NewID(), Username: username, DisplayName: username, PasswordHash: hash, Role: "admin", Now: store.Now(),
		})
	})
	if err != nil {
		return "", err
	}
	return generated, nil
}
