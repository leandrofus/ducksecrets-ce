package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var safeHostnameRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)

func validRequestHost(host string) bool {
	if host == "" || len(host) > 255 {
		return false
	}
	h := host
	if strings.HasPrefix(host, "[") {
		if strings.Contains(host, "]:") {
			parsedHost, portStr, err := net.SplitHostPort(host)
			if err != nil {
				return false
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				return false
			}
			h = parsedHost
		} else if strings.HasSuffix(host, "]") {
			h = host[1 : len(host)-1]
		} else {
			return false
		}
		return net.ParseIP(h) != nil
	}
	if strings.Contains(host, ":") {
		parsedHost, portStr, err := net.SplitHostPort(host)
		if err != nil {
			return false
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
		h = parsedHost
	}
	return safeHostnameRe.MatchString(h) || net.ParseIP(h) != nil
}

func shellQuotePOSIX(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func findCLIBinary() string {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "ducksecrets")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	candidates := []string{
		"./dist/bin/ducksecrets",
		"./gateway/bin/ducksecrets",
		"./bin/ducksecrets",
		"./ducksecrets",
		"/usr/local/bin/ducksecrets",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// openapi:operation
// summary: Download ducksecrets CLI binary
// description: Serves the compiled ducksecrets CLI executable for the server's platform.
// responses:
//   '200':
//     description: Binary stream
//     content:
//       application/octet-stream:
//         schema: { type: string, format: binary }

func (s *Server) downloadCLI(w http.ResponseWriter, r *http.Request, _ principal) error {
	binPath := findCLIBinary()
	if binPath == "" {
		return notFound("ducksecrets CLI binary not found on server")
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ducksecrets\"")
	http.ServeFile(w, r, binPath)
	return nil
}

// openapi:operation
// summary: Automated shell installer
// description: Serves a POSIX-compliant shell script to install the ducksecrets CLI and run a Site Connector.
// responses:
//   '200':
//     description: Shell script
//     content:
//       text/plain:
//         schema: { type: string }

func (s *Server) installScript(w http.ResponseWriter, r *http.Request, _ principal) error {
	var serverURL string
	if s.PublicURL != "" {
		serverURL = strings.TrimRight(s.PublicURL, "/")
	} else {
		host := r.Host
		if xfHost := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); xfHost != "" && s.trusted(remoteAddr(r)) {
			host = xfHost
		}
		if !validRequestHost(host) {
			return badRequest("invalid Host header")
		}
		scheme := "http"
		if s.secureRequest(r) {
			scheme = "https"
		}
		serverURL = fmt.Sprintf("%s://%s", scheme, host)
	}

	script := fmt.Sprintf(`#!/bin/sh
# DuckSecrets CLI Automated Installer & Site Runner
set -e

SERVER=%s
TARGET_DIR="/usr/local/bin"

if [ "$(id -u)" != "0" ]; then
  TARGET_DIR="$HOME/.local/bin"
  mkdir -p "$TARGET_DIR"
fi

echo "==> Downloading ducksecrets CLI from ${SERVER}..."
curl -fsSL "${SERVER}/download/ducksecrets" -o "${TARGET_DIR}/ducksecrets"
chmod +x "${TARGET_DIR}/ducksecrets"

case ":$PATH:" in
  *":${TARGET_DIR}:"*) ;;
  *) export PATH="${TARGET_DIR}:$PATH" ;;
esac

echo "==> ducksecrets CLI installed successfully to ${TARGET_DIR}/ducksecrets"

if [ -n "$DUCKSECRETS_SITE_ID" ] && [ -n "$DUCKSECRETS_SITE_TOKEN" ]; then
  echo "==> Starting DuckSecrets Site Connector..."
  exec "${TARGET_DIR}/ducksecrets" site run --server "${SERVER}" --site-id "$DUCKSECRETS_SITE_ID" --token "$DUCKSECRETS_SITE_TOKEN"
fi
`, shellQuotePOSIX(serverURL))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
	return nil
}
