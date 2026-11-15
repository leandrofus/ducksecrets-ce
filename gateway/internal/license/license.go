// Package license implements offline Ed25519-signed Open-Core licensing
// and feature/quota entitlement checks without any external phone-home calls.
package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// TokenPrefix versions signed offline DuckSecrets license tokens.
	TokenPrefix = "dkl1."

	EditionCommunity = "community"
	EditionPro       = "pro"
	EditionBusiness  = "business"

	CommunityMaxSites  = 2
	ProDefaultMaxSites = 25
	Unlimited          = -1
)

// Feature identifiers gated behind commercial licenses.
const (
	FeatureSitesPro        = "sites.pro"
	FeatureSitesUnlimited  = "sites.unlimited"
	FeatureSSOOIDC         = "sso.oidc"
	FeatureSSOSAML         = "sso.saml"
	FeatureKubernetesSync  = "sync.kubernetes"
	FeatureApprovals       = "governance.approvals"
	FeatureMasterKeyRotate = "vault.master_key_rotation"
	FeatureExternalKMS     = "vault.external_kms"
	FeatureAuditExport     = "audit.export"
)

// FeatureInfo describes an Open-Core commercial entitlement in API/UI responses.
type FeatureInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	MinEdition  string `json:"min_edition"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

var catalogDefs = []FeatureInfo{
	{
		ID:          FeatureSitesPro,
		Name:        "Multi-Site Tunnels (25 Sites)",
		MinEdition:  EditionPro,
		Description: "Scale reverse tunnel network sites beyond the 2-site Community quota.",
	},
	{
		ID:          FeatureSSOOIDC,
		Name:        "OIDC / OAuth2 Single Sign-On",
		MinEdition:  EditionPro,
		Description: "Authenticate users via corporate OIDC identity providers.",
	},
	{
		ID:          FeatureKubernetesSync,
		Name:        "Kubernetes & Sync Automations",
		MinEdition:  EditionPro,
		Description: "Automated secret delivery and Kubernetes operator synchronization.",
	},
	{
		ID:          FeatureMasterKeyRotate,
		Name:        "Master Key Rotation",
		MinEdition:  EditionPro,
		Description: "Re-wrap vault sub-keys under a rotated master encryption key.",
	},
	{
		ID:          FeatureSitesUnlimited,
		Name:        "Unlimited Network Sites",
		MinEdition:  EditionBusiness,
		Description: "Unlimited private network tunnel connectors.",
	},
	{
		ID:          FeatureApprovals,
		Name:        "Approval Workflows (Two-Person Rule)",
		MinEdition:  EditionBusiness,
		Description: "Require approval before sensitive secret changes take effect.",
	},
	{
		ID:          FeatureSSOSAML,
		Name:        "SAML 2.0 / SCIM / LDAP",
		MinEdition:  EditionBusiness,
		Description: "Enterprise SAML identity federation and automated directory provisioning.",
	},
	{
		ID:          FeatureExternalKMS,
		Name:        "External KMS Auto-Unseal",
		MinEdition:  EditionBusiness,
		Description: "Wrap the vault root key using an external KMS or HSM.",
	},
	{
		ID:          FeatureAuditExport,
		Name:        "Compliance Audit Streaming",
		MinEdition:  EditionBusiness,
		Description: "Continuous SIEM forwarding and signed compliance audit bundles.",
	},
}

// DefaultPublicKeyHex is the compiled Ed25519 public key used to verify offline
// commercial license tokens. Official release builds override this at link time:
//
//	-ldflags "-X github.com/leandrofus/ducksecrets/gateway/internal/license.DefaultPublicKeyHex=<hex>"
var DefaultPublicKeyHex = "6fe6aa9212b16f7f444d8db9482798ca5a60077752207d5f669c189f9fe1d6e9"

var (
	ErrInvalidToken    = errors.New("license: invalid token format or signature")
	ErrExpiredToken    = errors.New("license: license token has expired")
	ErrInvalidEdition  = errors.New("license: unsupported edition")
	ErrFeatureLocked   = errors.New("license: commercial license required for feature")
	ErrQuotaExceeded   = errors.New("license: edition quota exceeded")
	ErrManagedByConfig = errors.New("license: managed by -license-key / DUCKSECRETS_LICENSE_KEY")
)

// Claims is the signed JSON payload carried inside an offline license token.
type Claims struct {
	ID        string     `json:"id"`
	Edition   string     `json:"edition"`
	Customer  string     `json:"customer"`
	Org       string     `json:"org,omitempty"`
	MaxSites  int        `json:"max_sites,omitempty"`
	MaxUsers  int        `json:"max_users,omitempty"`
	Features  []string   `json:"features,omitempty"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Status summarizes the effective Open-Core state for API and UI consumers.
type Status struct {
	Edition         string        `json:"edition"`
	LicensedEdition string        `json:"licensed_edition,omitempty"`
	Valid           bool          `json:"valid"`
	Expired         bool          `json:"expired"`
	Customer        string        `json:"customer,omitempty"`
	Org             string        `json:"org,omitempty"`
	LicenseID       string        `json:"license_id,omitempty"`
	MaxSites        int           `json:"max_sites"`
	MaxUsers        int           `json:"max_users"`
	Features        []string      `json:"features"`
	Catalog         []FeatureInfo `json:"catalog"`
	Source          string        `json:"source"`
	IssuedAt        *time.Time    `json:"issued_at,omitempty"`
	ExpiresAt       *time.Time    `json:"expires_at,omitempty"`
	Error           string        `json:"error,omitempty"`
}

// GenerateKeypair creates a fresh Ed25519 keypair for signing offline licenses.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("license: generate keypair: %w", err)
	}
	return pub, priv, nil
}

// Sign encodes and signs Claims using priv, returning a dkl1.<payload>.<sig> token.
func Sign(priv ed25519.PrivateKey, claims Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("license: invalid Ed25519 private key size")
	}
	claims.Edition = strings.ToLower(strings.TrimSpace(claims.Edition))
	if !isPaidEdition(claims.Edition) {
		return "", ErrInvalidEdition
	}
	claims.Customer = strings.TrimSpace(claims.Customer)
	if claims.Customer == "" {
		return "", errors.New("license: customer is required")
	}
	if claims.ID == "" {
		return "", errors.New("license: id is required")
	}
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now().UTC().Truncate(time.Second)
	} else {
		claims.IssuedAt = claims.IssuedAt.UTC()
	}
	if claims.ExpiresAt != nil {
		exp := claims.ExpiresAt.UTC()
		claims.ExpiresAt = &exp
	}

	raw, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("license: marshal claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(raw)
	sig := ed25519.Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return TokenPrefix + payloadB64 + "." + sigB64, nil
}

// ParseAndVerify verifies the Ed25519 signature and expiration of token against pub.
// When expired, the decoded Claims are still returned alongside ErrExpiredToken so callers
// can surface expiration metadata while enforcing Community fallback limits.
func ParseAndVerify(token string, pub ed25519.PublicKey, now time.Time) (*Claims, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("license: invalid Ed25519 public key size")
	}
	tok := strings.TrimSpace(token)
	if !strings.HasPrefix(tok, TokenPrefix) {
		return nil, ErrInvalidToken
	}
	rest := strings.TrimPrefix(tok, TokenPrefix)
	payloadB64, sigB64, ok := strings.Cut(rest, ".")
	if !ok || payloadB64 == "" || sigB64 == "" || strings.Contains(sigB64, ".") {
		return nil, ErrInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrInvalidToken
	}
	if !ed25519.Verify(pub, []byte(payloadB64), sig) {
		return nil, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	claims.Edition = strings.ToLower(strings.TrimSpace(claims.Edition))
	if !isPaidEdition(claims.Edition) || strings.TrimSpace(claims.Customer) == "" {
		return nil, ErrInvalidToken
	}
	if claims.ExpiresAt != nil && now.UTC().After(claims.ExpiresAt.UTC()) {
		return &claims, ErrExpiredToken
	}
	return &claims, nil
}

// Manager holds the verified runtime edition and commercial entitlements.
type Manager struct {
	mu      sync.RWMutex
	pubKey  ed25519.PublicKey
	claims  *Claims
	source  string
	expired bool
	lastErr string
	nowFn   func() time.Time
}

// NewManager creates a Community-edition license manager using pubKeyHex
// (or DefaultPublicKeyHex when pubKeyHex is empty).
func NewManager(pubKeyHex string) (*Manager, error) {
	if strings.TrimSpace(pubKeyHex) == "" {
		pubKeyHex = DefaultPublicKeyHex
	}
	raw, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("license: invalid Ed25519 public key hex")
	}
	return &Manager{
		pubKey: ed25519.PublicKey(raw),
		source: "none",
		nowFn:  func() time.Time { return time.Now().UTC() },
	}, nil
}

// MustManager constructs a Manager with the compiled public key, panicking only
// if DefaultPublicKeyHex itself was misconfigured at build time.
func MustManager() *Manager {
	m, err := NewManager("")
	if err != nil {
		panic(err)
	}
	return m
}

// Activate validates and activates token. If verification fails or the token is
// expired, the previous active state is preserved and an error is returned.
func (m *Manager) Activate(token, source string) (Status, error) {
	claims, err := ParseAndVerify(token, m.pubKey, m.nowFn())
	if err != nil {
		return m.Status(), err
	}
	m.mu.Lock()
	m.claims = claims
	m.source = normalizeSource(source)
	m.expired = false
	m.lastErr = ""
	m.mu.Unlock()
	return m.Status(), nil
}

// LoadStartup loads a persisted or env-configured token at daemon boot.
// Expired or invalid tokens safely fall back to Community limits without
// preventing the server from starting.
func (m *Manager) LoadStartup(token, source string) error {
	tok := strings.TrimSpace(token)
	if tok == "" {
		m.Clear()
		return nil
	}
	claims, err := ParseAndVerify(tok, m.pubKey, m.nowFn())
	m.mu.Lock()
	defer m.mu.Unlock()
	m.source = normalizeSource(source)
	if err == nil {
		m.claims = claims
		m.expired = false
		m.lastErr = ""
		return nil
	}
	if errors.Is(err, ErrExpiredToken) && claims != nil {
		m.claims = claims
		m.expired = true
		m.lastErr = err.Error()
		return err
	}
	m.claims = nil
	m.expired = false
	m.lastErr = err.Error()
	return err
}

// Clear removes any active commercial license and reverts to Community Edition.
func (m *Manager) Clear() {
	m.mu.Lock()
	m.claims = nil
	m.source = "none"
	m.expired = false
	m.lastErr = ""
	m.mu.Unlock()
}

// Status returns a snapshot of the effective edition, quotas, and features.
func (m *Manager) Status() Status {
	m.mu.RLock()
	claims := m.claims
	source := m.source
	expired := m.expired
	lastErr := m.lastErr
	now := m.nowFn()
	m.mu.RUnlock()

	if claims != nil && claims.ExpiresAt != nil && now.After(claims.ExpiresAt.UTC()) {
		expired = true
		if lastErr == "" {
			lastErr = ErrExpiredToken.Error()
		}
	}

	activeClaims := claims
	if expired {
		activeClaims = nil
	}

	granted := effectiveFeatures(activeClaims)
	catalog := make([]FeatureInfo, len(catalogDefs))
	for i, def := range catalogDefs {
		def.Enabled = slices.Contains(granted, def.ID)
		catalog[i] = def
	}

	st := Status{
		Edition:  EditionCommunity,
		Valid:    activeClaims != nil,
		Expired:  expired,
		MaxSites: CommunityMaxSites,
		MaxUsers: Unlimited,
		Features: granted,
		Catalog:  catalog,
		Source:   source,
		Error:    lastErr,
	}

	if claims != nil {
		st.LicensedEdition = claims.Edition
		st.Customer = claims.Customer
		st.Org = claims.Org
		st.LicenseID = claims.ID
		iat := claims.IssuedAt.UTC()
		st.IssuedAt = &iat
		if claims.ExpiresAt != nil {
			exp := claims.ExpiresAt.UTC()
			st.ExpiresAt = &exp
		}
	}

	if activeClaims != nil {
		st.Edition = activeClaims.Edition
		st.MaxSites = effectiveSitesLimit(activeClaims, granted)
		if activeClaims.MaxUsers > 0 {
			st.MaxUsers = activeClaims.MaxUsers
		}
	}

	return st
}

// HasFeature reports whether feature is active under the current license.
func (m *Manager) HasFeature(feature string) bool {
	return slices.Contains(m.Status().Features, feature)
}

// RequireFeature returns ErrFeatureLocked when feature is not licensed.
func (m *Manager) RequireFeature(feature string) error {
	if m.HasFeature(feature) {
		return nil
	}
	return fmt.Errorf("%w: %q requires a DuckSecrets Pro or Business license", ErrFeatureLocked, feature)
}

// SitesLimit returns the active Network Sites limit (-1 means unlimited).
func (m *Manager) SitesLimit() int {
	return m.Status().MaxSites
}

// CanCreateSite enforces the active edition's global Network Sites quota.
func (m *Manager) CanCreateSite(currentCount int64) error {
	st := m.Status()
	if st.MaxSites < 0 || currentCount < int64(st.MaxSites) {
		return nil
	}
	return fmt.Errorf(
		"%w: %s edition allows up to %d network sites (currently %d); upgrade to Pro or Business for additional sites",
		ErrQuotaExceeded, st.Edition, st.MaxSites, currentCount,
	)
}

func isPaidEdition(ed string) bool {
	return ed == EditionPro || ed == EditionBusiness
}

func normalizeSource(s string) string {
	switch s {
	case "env", "database":
		return s
	default:
		return "none"
	}
}

func effectiveFeatures(c *Claims) []string {
	if c == nil {
		return []string{}
	}
	set := make(map[string]struct{}, len(catalogDefs))
	for _, f := range catalogDefs {
		switch c.Edition {
		case EditionBusiness:
			set[f.ID] = struct{}{}
		case EditionPro:
			if f.MinEdition == EditionPro {
				set[f.ID] = struct{}{}
			}
		}
	}
	for _, extra := range c.Features {
		trimmed := strings.TrimSpace(extra)
		if trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func effectiveSitesLimit(c *Claims, granted []string) int {
	if c.MaxSites < 0 || slices.Contains(granted, FeatureSitesUnlimited) {
		return Unlimited
	}
	if c.MaxSites > 0 {
		return c.MaxSites
	}
	if c.Edition == EditionBusiness {
		return Unlimited
	}
	return ProDefaultMaxSites
}
