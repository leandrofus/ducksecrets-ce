package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
	"github.com/leandrofus/ducksecrets/gateway/internal/tlsutil"
)

const (
	tlsModeSettingKey = "tls_mode"
	tlsCertSettingKey = "tls_cert_pem"
	tlsKeySettingKey  = "tls_key_pem"
)

// openapi:schema TLSStatus
// type: object
// required: [tls_active, mode, has_cert, self_signed, san_dns, san_ips, trusted_proxies_count, reverse_proxy_ready, restart_required]
// properties:
//   tls_active: { type: boolean }
//   mode: { type: string }
//   cert_path: { type: string }
//   key_path: { type: string }
//   has_cert: { type: boolean }
//   subject: { type: string }
//   issuer: { type: string }
//   self_signed: { type: boolean }
//   san_dns: { type: array, items: { type: string } }
//   san_ips: { type: array, items: { type: string } }
//   not_before: { type: string, format: date-time }
//   not_after: { type: string, format: date-time }
//   fingerprint_sha256: { type: string }
//   trusted_proxies_count: { type: integer }
//   reverse_proxy_ready: { type: boolean }
//   restart_required: { type: boolean }

type tlsStatusDTO struct {
	TLSActive           bool       `json:"tls_active"`
	Mode                string     `json:"mode"`
	CertPath            string     `json:"cert_path,omitempty"`
	KeyPath             string     `json:"key_path,omitempty"`
	HasCert             bool       `json:"has_cert"`
	Subject             string     `json:"subject,omitempty"`
	Issuer              string     `json:"issuer,omitempty"`
	SelfSigned          bool       `json:"self_signed"`
	SANDNS              []string   `json:"san_dns"`
	SANIPs              []string   `json:"san_ips"`
	NotBefore           *time.Time `json:"not_before,omitempty"`
	NotAfter            *time.Time `json:"not_after,omitempty"`
	FingerprintSHA256   string     `json:"fingerprint_sha256,omitempty"`
	TrustedProxiesCount int        `json:"trusted_proxies_count"`
	ReverseProxyReady   bool       `json:"reverse_proxy_ready"`
	RestartRequired     bool       `json:"restart_required"`
}

// openapi:schema UploadTLSRequest
// type: object
// required: [cert_pem, key_pem]
// additionalProperties: false
// properties:
//   cert_pem: { type: string, minLength: 32 }
//   key_pem: { type: string, minLength: 32 }

type uploadTLSRequest struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// openapi:schema GenerateSelfSignedTLSRequest
// type: object
// additionalProperties: false
// properties:
//   hosts: { type: array, items: { type: string } }

type generateSelfSignedTLSRequest struct {
	Hosts []string `json:"hosts"`
}

func (s *Server) tlsMgr() *tlsutil.Manager {
	if s.TLS == nil {
		s.TLS = tlsutil.NewManager(false, tlsutil.ModeOff, "", "", nil)
	}
	return s.TLS
}

func (s *Server) buildTLSDTO(st tlsutil.Status, restartRequired bool) tlsStatusDTO {
	dto := tlsStatusDTO{
		TLSActive:           st.TLSActive,
		Mode:                st.Mode,
		CertPath:            st.CertPath,
		KeyPath:             st.KeyPath,
		HasCert:             st.HasCert,
		Subject:             st.Cert.Subject,
		Issuer:              st.Cert.Issuer,
		SelfSigned:          st.Cert.SelfSigned,
		SANDNS:              st.Cert.SANDNS,
		SANIPs:              st.Cert.SANIPs,
		FingerprintSHA256:   st.Cert.FingerprintSHA256,
		TrustedProxiesCount: len(s.TrustedProxies),
		ReverseProxyReady:   true,
		RestartRequired:     restartRequired,
	}
	if dto.SANDNS == nil {
		dto.SANDNS = []string{}
	}
	if dto.SANIPs == nil {
		dto.SANIPs = []string{}
	}
	if st.HasCert {
		nb := st.Cert.NotBefore
		na := st.Cert.NotAfter
		dto.NotBefore = &nb
		dto.NotAfter = &na
	}
	return dto
}

func (s *Server) persistTLSPair(ctx context.Context, mode, certPEM, keyPEM string) error {
	now := store.Now()
	for _, kv := range []struct{ k, v string }{
		{tlsModeSettingKey, mode},
		{tlsCertSettingKey, certPEM},
		{tlsKeySettingKey, keyPEM},
	} {
		if err := s.Store.Q.UpsertSystemSetting(ctx, db.UpsertSystemSettingParams{
			Key:       kv.k,
			Value:     kv.v,
			UpdatedAt: now,
		}); err != nil {
			return fmt.Errorf("saving TLS setting %s: %w", kv.k, err)
		}
	}
	return nil
}

// openapi:operation
// summary: Get TLS and reverse proxy status
// description: Returns active TLS certificate metadata, mode (off, self-signed, custom), and reverse proxy readiness.
// responses:
//   '200': { description: TLS configuration status, schema: TLSStatus }

func (s *Server) getTLSStatus(w http.ResponseWriter, r *http.Request, _ principal) error {
	st := s.tlsMgr().Status()
	return ok(w, s.buildTLSDTO(st, false))
}

// openapi:operation
// summary: Upload custom TLS certificate and private key
// description: Validates a PEM X.509 certificate and matching private key, persists it, and hot-swaps the active TLS listener certificate when HTTPS is active.
// requestBody: { schema: UploadTLSRequest }
// responses:
//   '200': { description: Updated TLS status, schema: TLSStatus }

func (s *Server) uploadCustomTLS(w http.ResponseWriter, r *http.Request, p principal) error {
	var in uploadTLSRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	certPEM := strings.TrimSpace(in.CertPEM) + "\n"
	keyPEM := strings.TrimSpace(in.KeyPEM) + "\n"

	mgr := s.tlsMgr()
	info, err := mgr.SetCustom([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return badRequest("%v", err)
	}
	if err := s.persistTLSPair(r.Context(), tlsutil.ModeCustom, certPEM, keyPEM); err != nil {
		return err
	}
	s.record(r, p, "system.tls_updated", "system", "tls", map[string]any{
		"mode":        tlsutil.ModeCustom,
		"fingerprint": info.FingerprintSHA256,
		"subject":     info.Subject,
	})
	st := mgr.Status()
	return ok(w, s.buildTLSDTO(st, !st.TLSActive))
}

// openapi:operation
// summary: Generate or regenerate self-signed TLS certificate
// description: Generates a fresh self-signed ECDSA P-256 certificate (optionally with extra DNS/IP SANs) and hot-swaps it live.
// requestBody: { schema: GenerateSelfSignedTLSRequest }
// responses:
//   '200': { description: Updated TLS status, schema: TLSStatus }

func (s *Server) regenerateSelfSignedTLS(w http.ResponseWriter, r *http.Request, p principal) error {
	var in generateSelfSignedTLSRequest
	if r.ContentLength > 0 {
		if err := decode(r, &in); err != nil {
			return err
		}
	}
	mgr := s.tlsMgr()
	certPEM, keyPEM, info, err := mgr.RegenerateSelfSigned(in.Hosts)
	if err != nil {
		return fmt.Errorf("generating self-signed TLS certificate: %w", err)
	}
	if err := s.persistTLSPair(r.Context(), tlsutil.ModeSelfSigned, string(certPEM), string(keyPEM)); err != nil {
		return err
	}
	s.record(r, p, "system.tls_self_signed", "system", "tls", map[string]any{
		"fingerprint": info.FingerprintSHA256,
		"san_dns":     info.SANDNS,
	})
	st := mgr.Status()
	return ok(w, s.buildTLSDTO(st, !st.TLSActive))
}

// openapi:operation
// summary: Reset custom TLS certificate back to self-signed
// description: Clears a custom uploaded certificate and generates a fresh self-signed certificate.
// responses:
//   '200': { description: Reverted TLS status, schema: TLSStatus }

func (s *Server) resetCustomTLS(w http.ResponseWriter, r *http.Request, p principal) error {
	return s.regenerateSelfSignedTLS(w, r, p)
}
