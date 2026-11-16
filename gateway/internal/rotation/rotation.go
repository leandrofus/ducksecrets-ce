package rotation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
)

// GenerateNewSecret generates a new secret value based on generatorType and generatorConfig.
// If generatorConfig specifies a "template" field (e.g. "postgres://user:{{secret}}@host:port/db"),
// the generated secret will be interpolated into {{secret}} in the template.
func GenerateNewSecret(generatorType, configJSON string) (string, error) {
	var rawSecret string
	switch generatorType {
	case "password":
		length := 32
		if configJSON != "" {
			var cfg struct {
				Length int `json:"length"`
			}
			_ = json.Unmarshal([]byte(configJSON), &cfg)
			if cfg.Length >= 8 && cfg.Length <= 256 {
				length = cfg.Length
			}
		}
		const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>"
		bytes := make([]byte, length)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		for i := 0; i < length; i++ {
			bytes[i] = chars[int(bytes[i])%len(chars)]
		}
		rawSecret = string(bytes)

	case "hex":
		bytes := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
			return "", err
		}
		rawSecret = hex.EncodeToString(bytes)

	case "base64":
		bytes := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
			return "", err
		}
		rawSecret = base64.StdEncoding.EncodeToString(bytes)

	case "uuid":
		rawSecret = uuid.NewString()

	case "jwt_secret":
		bytes := make([]byte, 64)
		if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
			return "", err
		}
		rawSecret = hex.EncodeToString(bytes)

	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", fmt.Errorf("generating RSA key: %w", err)
		}
		der := x509.MarshalPKCS1PrivateKey(key)
		b := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		}
		rawSecret = string(pem.EncodeToMemory(&b))

	default:
		return "", fmt.Errorf("unknown generator type %q", generatorType)
	}

	if configJSON != "" {
		var cfg struct {
			Template string `json:"template"`
		}
		_ = json.Unmarshal([]byte(configJSON), &cfg)
		if cfg.Template != "" {
			return strings.ReplaceAll(cfg.Template, "{{secret}}", rawSecret), nil
		}
	}

	return rawSecret, nil
}

// VerifyOptions controls optional safety overrides for health probes.
type VerifyOptions struct {
	AllowPrivate bool
}

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	// Block CGNAT (100.64.0.0/10) as well when disallowing private networks.
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return true
		}
	}
	return false
}

func safeProbeDialContext(timeout time.Duration, allowPrivate bool) func(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid probe target %q: %w", address, err)
		}
		if host == "" {
			return nil, fmt.Errorf("probe target host is empty")
		}
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			if !allowPrivate && isBlockedIP(ip) {
				return nil, fmt.Errorf("probe target IP %s is blocked (loopback/private/link-local)", ip.String())
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolving probe host %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses resolved for %q", host)
		}
		for _, ipAddr := range ips {
			if !allowPrivate && isBlockedIP(ipAddr.IP) {
				return nil, fmt.Errorf("probe target %q resolved to blocked IP %s", host, ipAddr.IP.String())
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

// VerifySecretHealth tests whether the rotated secret passes the configured health probe
// using strict default anti-SSRF rules (blocking loopback, private, and link-local addresses).
func VerifySecretHealth(ctx context.Context, verifierType, configJSON, secretValue string) error {
	return VerifySecretHealthWithOptions(ctx, verifierType, configJSON, secretValue, VerifyOptions{})
}

// VerifySecretHealthWithOptions tests whether the rotated secret passes the configured health probe.
func VerifySecretHealthWithOptions(ctx context.Context, verifierType, configJSON, secretValue string, opts VerifyOptions) error {
	switch verifierType {
	case "", "none":
		return nil

	case "http_probe":
		var cfg struct {
			URL     string            `json:"url"`
			Method  string            `json:"method"`
			Headers map[string]string `json:"headers"`
			Timeout int               `json:"timeout_seconds"`
		}
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return fmt.Errorf("parsing http_probe config: %w", err)
		}
		if cfg.URL == "" {
			return fmt.Errorf("http_probe requires url")
		}
		parsedURL, err := url.Parse(cfg.URL)
		if err != nil {
			return fmt.Errorf("invalid http_probe url: %w", err)
		}
		scheme := strings.ToLower(parsedURL.Scheme)
		if (scheme != "http" && scheme != "https") || parsedURL.Hostname() == "" {
			return fmt.Errorf("http_probe requires http or https url with valid host")
		}
		method := strings.ToUpper(strings.TrimSpace(cfg.Method))
		if method == "" {
			method = "GET"
		}
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		default:
			return fmt.Errorf("unsupported http_probe method %q", method)
		}
		timeout := 5 * time.Second
		if cfg.Timeout > 0 {
			timeout = time.Duration(cfg.Timeout) * time.Second
		}

		transport := &http.Transport{
			DialContext: safeProbeDialContext(timeout, opts.AllowPrivate),
		}
		defer transport.CloseIdleConnections()

		client := &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("http_probe redirects are not allowed")
			},
		}
		req, err := http.NewRequestWithContext(ctx, method, cfg.URL, nil)
		if err != nil {
			return fmt.Errorf("creating http probe request: %w", err)
		}

		// Apply headers with {{secret}} substitution
		for k, v := range cfg.Headers {
			headerVal := strings.ReplaceAll(v, "{{secret}}", secretValue)
			req.Header.Set(k, headerVal)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("http probe connection failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("http probe returned unexpected status %d", resp.StatusCode)
		}
		return nil

	case "tcp_probe":
		var cfg struct {
			Address string `json:"address"`
			Timeout int    `json:"timeout_seconds"`
		}
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return fmt.Errorf("parsing tcp_probe config: %w", err)
		}
		if cfg.Address == "" {
			return fmt.Errorf("tcp_probe requires address")
		}
		timeout := 3 * time.Second
		if cfg.Timeout > 0 {
			timeout = time.Duration(cfg.Timeout) * time.Second
		}
		conn, err := safeProbeDialContext(timeout, opts.AllowPrivate)(ctx, "tcp", cfg.Address)
		if err != nil {
			return fmt.Errorf("tcp probe dial failed: %w", err)
		}
		conn.Close()
		return nil

	case "script":
		var cfg struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return fmt.Errorf("parsing script config: %w", err)
		}
		if cfg.Command == "" {
			return fmt.Errorf("script probe requires command")
		}
		cmd := exec.CommandContext(ctx, "sh", "-c", cfg.Command)
		cmd.Env = append(cmd.Environ(), "DUCKSECRETS_NEW_VALUE="+secretValue)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("verification script failed: %s (%w)", string(out), err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported verifier type %q", verifierType)
	}
}
