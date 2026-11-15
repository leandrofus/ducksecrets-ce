package rotation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGenerators(t *testing.T) {
	t.Run("password generator default", func(t *testing.T) {
		val, err := GenerateNewSecret("password", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(val) < 24 {
			t.Fatalf("expected password length >= 24, got %d", len(val))
		}
	})

	t.Run("password generator custom length", func(t *testing.T) {
		val, err := GenerateNewSecret("password", `{"length": 36, "symbols": true}`)
		if err != nil {
			t.Fatal(err)
		}
		if len(val) != 36 {
			t.Fatalf("expected length 36, got %d", len(val))
		}
	})

	t.Run("template interpolation", func(t *testing.T) {
		val, err := GenerateNewSecret("password", `{"length": 16, "template": "postgres://app_dev:{{secret}}@10.0.1.5:5432/ecommerce_dev"}`)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(val, "postgres://app_dev:") || !strings.HasSuffix(val, "@10.0.1.5:5432/ecommerce_dev") {
			t.Fatalf("unexpected template interpolated secret: %s", val)
		}
		parts := strings.Split(val, ":")
		if len(parts) < 3 {
			t.Fatalf("malformed connection string: %s", val)
		}
	})

	t.Run("hex generator", func(t *testing.T) {
		val, err := GenerateNewSecret("hex", `{"length": 64}`)
		if err != nil {
			t.Fatal(err)
		}
		if len(val) != 64 {
			t.Fatalf("expected length 64, got %d", len(val))
		}
	})

	t.Run("base64 generator", func(t *testing.T) {
		val, err := GenerateNewSecret("base64", `{"length": 32}`)
		if err != nil {
			t.Fatal(err)
		}
		if val == "" {
			t.Fatal("empty base64 string")
		}
	})

	t.Run("uuid generator", func(t *testing.T) {
		val, err := GenerateNewSecret("uuid", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(val) != 36 || strings.Count(val, "-") != 4 {
			t.Fatalf("invalid uuid format: %s", val)
		}
	})

	t.Run("jwt_secret generator", func(t *testing.T) {
		val, err := GenerateNewSecret("jwt_secret", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(val) != 128 {
			t.Fatalf("expected 128-char hex jwt secret, got %d", len(val))
		}
	})

	t.Run("rsa generator", func(t *testing.T) {
		val, err := GenerateNewSecret("rsa", `{"bits": 2048}`)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(val))
		if block == nil {
			t.Fatal("failed to decode PEM block")
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse RSA private key: %v", err)
		}
		if key.N.BitLen() != 2048 {
			t.Fatalf("expected 2048 bits RSA key, got %d", key.N.BitLen())
		}
	})

	t.Run("unknown generator", func(t *testing.T) {
		_, err := GenerateNewSecret("quantum_flux", "")
		if err == nil {
			t.Fatal("expected error for unknown generator")
		}
	})
}

func TestHTTPProbeVerifier(t *testing.T) {
	receivedSecret := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Probe-Auth") == "bad-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		receivedSecret = r.Header.Get("X-Probe-Auth")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Success case with secret interpolation
	cfg := `{
		"url": "` + ts.URL + `",
		"method": "GET",
		"headers": {"X-Probe-Auth": "{{secret}}"},
		"expected_status": 200
	}`
	err := VerifySecretHealthWithOptions(ctx, "http_probe", cfg, "super-candidate-token-123", VerifyOptions{AllowPrivate: true})
	if err != nil {
		t.Fatalf("expected http probe to succeed, got: %v", err)
	}
	if receivedSecret != "super-candidate-token-123" {
		t.Fatalf("header was not interpolated: got %q", receivedSecret)
	}

	// 2. Failure case (status code mismatch)
	failCfg := `{
		"url": "` + ts.URL + `",
		"method": "GET",
		"headers": {"X-Probe-Auth": "bad-token"},
		"expected_status": 200
	}`
	err = VerifySecretHealthWithOptions(ctx, "http_probe", failCfg, "bad-token", VerifyOptions{AllowPrivate: true})
	if err == nil {
		t.Fatal("expected http probe to fail with 401 status, got nil")
	}
}

func TestTCPProbeVerifier(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ctx := context.Background()
	cfg := `{"address": "` + l.Addr().String() + `"}`

	// Success
	if err := VerifySecretHealthWithOptions(ctx, "tcp_probe", cfg, "unused", VerifyOptions{AllowPrivate: true}); err != nil {
		t.Fatalf("expected tcp probe success, got: %v", err)
	}

	// Failure (closed port)
	badCfg := `{"address": "127.0.0.1:54329"}`
	if err := VerifySecretHealthWithOptions(ctx, "tcp_probe", badCfg, "unused", VerifyOptions{AllowPrivate: true}); err == nil {
		t.Fatal("expected tcp probe failure on unreachable port")
	}
}

func TestProbeSSRFBlockedByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Default VerifySecretHealth must block loopback, link-local, RFC1918, and non-http schemes
	for _, u := range []string{
		ts.URL,
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/",
		"file:///etc/passwd",
	} {
		if err := VerifySecretHealth(ctx, "http_probe", `{"url":"`+u+`"}`, "sec"); err == nil {
			t.Fatalf("expected http_probe SSRF error for %s, got nil", u)
		}
	}
	if err := VerifySecretHealth(ctx, "tcp_probe", `{"address":"127.0.0.1:80"}`, "sec"); err == nil {
		t.Fatal("expected tcp_probe SSRF error for 127.0.0.1:80")
	}
	if err := VerifySecretHealth(ctx, "tcp_probe", `{"address":"169.254.169.254:80"}`, "sec"); err == nil {
		t.Fatal("expected tcp_probe SSRF error for link-local address")
	}

	// Redirects must remain blocked even when AllowPrivate is true
	if err := VerifySecretHealthWithOptions(ctx, "http_probe", `{"url":"`+ts.URL+`/redirect"}`, "sec", VerifyOptions{AllowPrivate: true}); err == nil {
		t.Fatal("expected redirect to be rejected by http_probe")
	}
}

func TestScriptVerifier(t *testing.T) {
	ctx := context.Background()

	// Success script
	successCfg := `{"command": "test \"$DUCKSECRETS_NEW_VALUE\" = \"hello_secret\""}`
	if err := VerifySecretHealth(ctx, "script", successCfg, "hello_secret"); err != nil {
		t.Fatalf("expected script probe success, got: %v", err)
	}

	// Failing script
	failCfg := `{"command": "exit 1"}`
	if err := VerifySecretHealth(ctx, "script", failCfg, "hello_secret"); err == nil {
		t.Fatal("expected script probe failure")
	}
}
