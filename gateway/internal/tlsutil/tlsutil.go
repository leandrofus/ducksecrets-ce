// Package tlsutil manages TLS certificates for ducksecretsd: automatic install-time
// self-signed ECDSA P-256 certificates, custom PEM certificate loading, and
// lock-free hot-swapping via tls.Config.GetCertificate.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	ModeOff        = "off"
	ModeAuto       = "auto"
	ModeSelfSigned = "self-signed"
	ModeCustom     = "custom"

	defaultValidDays = 365
)

// CertInfo describes an active X.509 server certificate.
type CertInfo struct {
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	SelfSigned        bool      `json:"self_signed"`
	SANDNS            []string  `json:"san_dns"`
	SANIPs            []string  `json:"san_ips"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
}

// Status reports the daemon's runtime TLS configuration and active certificate.
type Status struct {
	TLSActive bool     `json:"tls_active"`
	Mode      string   `json:"mode"`
	CertPath  string   `json:"cert_path,omitempty"`
	KeyPath   string   `json:"key_path,omitempty"`
	HasCert   bool     `json:"has_cert"`
	Cert      CertInfo `json:"cert"`
}

// GenerateSelfSigned creates a self-signed ECDSA P-256 certificate and PKCS#8
// private key covering localhost, loopback IPs, the local hostname, and any extra hosts.
func GenerateSelfSigned(extraHosts []string, validDays int) (certPEM, keyPEM []byte, info CertInfo, err error) {
	if validDays <= 0 {
		validDays = defaultValidDays
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, CertInfo{}, fmt.Errorf("generating ECDSA key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, CertInfo{}, fmt.Errorf("generating certificate serial: %w", err)
	}

	now := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := now.Add(time.Duration(validDays) * 24 * time.Hour)

	dnsSet := map[string]struct{}{"localhost": {}}
	ipSet := map[string]net.IP{
		"127.0.0.1": net.ParseIP("127.0.0.1"),
		"::1":       net.ParseIP("::1"),
	}
	if hn, err := os.Hostname(); err == nil && hn != "" {
		dnsSet[hn] = struct{}{}
	}
	for _, h := range extraHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ipSet[ip.String()] = ip
		} else {
			dnsSet[h] = struct{}{}
		}
	}

	var dnsNames []string
	for d := range dnsSet {
		dnsNames = append(dnsNames, d)
	}
	var ips []net.IP
	for _, ip := range ipSet {
		ips = append(ips, ip)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"DuckSecrets Self-Signed"},
			CommonName:   "ducksecrets",
		},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, CertInfo{}, fmt.Errorf("signing certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, CertInfo{}, fmt.Errorf("encoding private key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	_, info, err = InspectPair(certPEM, keyPEM)
	return certPEM, keyPEM, info, err
}

// InspectPair parses and validates a PEM certificate chain and matching private key.
func InspectPair(certPEM, keyPEM []byte) (tls.Certificate, CertInfo, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return tls.Certificate{}, CertInfo{}, errors.New("both cert_pem and key_pem are required")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return tls.Certificate{}, CertInfo{}, errors.New("certificate PEM contains no certificates")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("parsing X.509 leaf certificate: %w", err)
	}
	pair.Leaf = leaf

	now := time.Now()
	if now.After(leaf.NotAfter) {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	sum := sha256.Sum256(leaf.Raw)
	var sanIPs []string
	for _, ip := range leaf.IPAddresses {
		sanIPs = append(sanIPs, ip.String())
	}
	sanDNS := append([]string{}, leaf.DNSNames...)
	if sanDNS == nil {
		sanDNS = []string{}
	}
	if sanIPs == nil {
		sanIPs = []string{}
	}

	info := CertInfo{
		Subject:           leaf.Subject.String(),
		Issuer:            leaf.Issuer.String(),
		SelfSigned:        leaf.Subject.String() == leaf.Issuer.String(),
		SANDNS:            sanDNS,
		SANIPs:            sanIPs,
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
		FingerprintSHA256: hex.EncodeToString(sum[:]),
	}
	return pair, info, nil
}

// WritePair atomically writes certPEM (0644) and keyPEM (0600) to disk.
func WritePair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return writeAtomic(keyPath, keyPEM, 0o600)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// Manager holds the active TLS certificate and supports live rotation/replacement.
type Manager struct {
	mu        sync.RWMutex
	tlsActive bool
	mode      string
	certPath  string
	keyPath   string
	hosts     []string
	cert      *tls.Certificate
	info      CertInfo
}

// NewManager creates a TLS manager. Pass tlsActive=false when running HTTP (e.g. reverse proxy mode).
func NewManager(tlsActive bool, mode, certPath, keyPath string, hosts []string) *Manager {
	if mode == "" {
		mode = ModeOff
	}
	return &Manager{
		tlsActive: tlsActive,
		mode:      mode,
		certPath:  certPath,
		keyPath:   keyPath,
		hosts:     append([]string{}, hosts...),
	}
}

// LoadPEM validates and installs a PEM pair as the active certificate in memory.
func (m *Manager) LoadPEM(mode string, certPEM, keyPEM []byte) (CertInfo, error) {
	pair, info, err := InspectPair(certPEM, keyPEM)
	if err != nil {
		return CertInfo{}, err
	}
	m.mu.Lock()
	m.cert = &pair
	m.info = info
	if mode != "" {
		m.mode = mode
	}
	m.mu.Unlock()
	return info, nil
}

// LoadOrInitFiles loads certPath/keyPath if both exist, or generates a self-signed
// pair at those paths when missing.
func (m *Manager) LoadOrInitFiles(certPath, keyPath string) (created bool, err error) {
	certBytes, errC := os.ReadFile(certPath)
	keyBytes, errK := os.ReadFile(keyPath)
	if errC == nil && errK == nil {
		_, info, err := InspectPair(certBytes, keyBytes)
		if err != nil {
			return false, err
		}
		mode := ModeCustom
		if info.SelfSigned {
			mode = ModeSelfSigned
		}
		if _, err := m.LoadPEM(mode, certBytes, keyBytes); err != nil {
			return false, err
		}
		m.mu.Lock()
		m.certPath = certPath
		m.keyPath = keyPath
		m.mu.Unlock()
		return false, nil
	}

	certPEM, keyPEM, _, err := GenerateSelfSigned(m.hosts, defaultValidDays)
	if err != nil {
		return false, err
	}
	if err := WritePair(certPath, keyPath, certPEM, keyPEM); err != nil {
		return false, err
	}
	if _, err := m.LoadPEM(ModeSelfSigned, certPEM, keyPEM); err != nil {
		return false, err
	}
	m.mu.Lock()
	m.certPath = certPath
	m.keyPath = keyPath
	m.mu.Unlock()
	return true, nil
}

// SetCustom validates a custom PEM cert+key pair, updates disk files if configured,
// and hot-swaps the active certificate in memory.
func (m *Manager) SetCustom(certPEM, keyPEM []byte) (CertInfo, error) {
	pair, info, err := InspectPair(certPEM, keyPEM)
	if err != nil {
		return CertInfo{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.certPath != "" && m.keyPath != "" {
		if err := WritePair(m.certPath, m.keyPath, certPEM, keyPEM); err != nil {
			return CertInfo{}, err
		}
	}
	m.cert = &pair
	m.info = info
	m.mode = ModeCustom
	return info, nil
}

// RegenerateSelfSigned mints a fresh self-signed certificate and activates it.
func (m *Manager) RegenerateSelfSigned(extraHosts []string) (certPEM, keyPEM []byte, info CertInfo, err error) {
	m.mu.RLock()
	baseHosts := append([]string{}, m.hosts...)
	certPath, keyPath := m.certPath, m.keyPath
	m.mu.RUnlock()

	merged := append(baseHosts, extraHosts...)
	certPEM, keyPEM, info, err = GenerateSelfSigned(merged, defaultValidDays)
	if err != nil {
		return nil, nil, CertInfo{}, err
	}
	pair, _, err := InspectPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, CertInfo{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if certPath != "" && keyPath != "" {
		if err := WritePair(certPath, keyPath, certPEM, keyPEM); err != nil {
			return nil, nil, CertInfo{}, err
		}
	}
	m.cert = &pair
	m.info = info
	m.mode = ModeSelfSigned
	return certPEM, keyPEM, info, nil
}

// TLSConfig builds a TLS configuration whose GetCertificate callback returns
// the currently active certificate, enabling zero-downtime cert hot-reloads.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.cert == nil {
				return nil, errors.New("no TLS certificate loaded")
			}
			return m.cert, nil
		},
	}
}

// Status returns a snapshot of the TLS manager state.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info := m.info
	if info.SANDNS == nil {
		info.SANDNS = []string{}
	}
	if info.SANIPs == nil {
		info.SANIPs = []string{}
	}
	return Status{
		TLSActive: m.tlsActive,
		Mode:      m.mode,
		CertPath:  m.certPath,
		KeyPath:   m.keyPath,
		HasCert:   m.cert != nil,
		Cert:      info,
	}
}
