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

	var selfSignedPEM, tlsFingerprint string
	if s.TLS != nil {
		st := s.TLS.Status()
		if st.TLSActive && st.HasCert && (st.Cert.SelfSigned || st.Mode == "self-signed") {
			selfSignedPEM = strings.TrimSpace(string(s.TLS.CertPEM()))
			tlsFingerprint = strings.TrimSpace(st.Cert.FingerprintSHA256)
		}
	}

	certBlock := `TMP_CERT=""`
	if selfSignedPEM != "" {
		certBlock = fmt.Sprintf(`TMP_CERT="$(mktemp)"
trap 'rm -f "$TMP_CERT"' EXIT
cat <<'__DUCKSECRETS_CERT__' > "$TMP_CERT"
%s
__DUCKSECRETS_CERT__`, selfSignedPEM)
	}

	script := fmt.Sprintf(`#!/bin/sh
# DuckSecrets CLI Automated Installer & Site Runner
set -e

SERVER=%s
TLS_FINGERPRINT=%s
TARGET_DIR="/usr/local/bin"

if [ "$(id -u)" != "0" ]; then
  TARGET_DIR="$HOME/.local/bin"
  mkdir -p "$TARGET_DIR"
fi

%s

fetch_url() {
  if [ "${DUCKSECRETS_INSECURE:-}" = "1" ] || [ "${DUCKSECRETS_INSECURE:-}" = "true" ]; then
    curl -fksSL "$1" -o "$2"
  elif [ -n "${DUCKSECRETS_CA_CERT:-}" ]; then
    curl -fsSL --cacert "$DUCKSECRETS_CA_CERT" "$1" -o "$2"
  elif [ -n "$TMP_CERT" ]; then
    curl -fsSL --cacert "$TMP_CERT" "$1" -o "$2"
  else
    curl -fsSL "$1" -o "$2"
  fi
}

echo "==> Downloading ducksecrets CLI from ${SERVER}..."
TMP_BIN="${TARGET_DIR}/ducksecrets.tmp.$$"
fetch_url "${SERVER}/download/ducksecrets" "$TMP_BIN"
chmod 0755 "$TMP_BIN"
mv -f "$TMP_BIN" "${TARGET_DIR}/ducksecrets"

case ":$PATH:" in
  *":${TARGET_DIR}:"*) ;;
  *) export PATH="${TARGET_DIR}:$PATH" ;;
esac

echo "==> ducksecrets CLI installed successfully to ${TARGET_DIR}/ducksecrets"

# Persist CLI server & TLS trust so subsequent commands (login, site list, ssh, etc.)
# trust this server out-of-the-box without requiring --ca-cert or --insecure.
if [ "$(id -u)" = "0" ]; then
  CLI_CONF_DIR="/etc/ducksecrets"
  CLI_MODE=0644
else
  CLI_CONF_DIR="${HOME}/.ducksecrets"
  CLI_MODE=0600
fi
mkdir -p "$CLI_CONF_DIR"
CLI_CERT_PATH=""
if [ -n "$TMP_CERT" ]; then
  CLI_CERT_PATH="${CLI_CONF_DIR}/server.crt"
  cp "$TMP_CERT" "$CLI_CERT_PATH"
  chmod "$CLI_MODE" "$CLI_CERT_PATH"
fi
CLI_CONF_FILE="${CLI_CONF_DIR}/cli.json"
{
  printf '{\n'
  printf '  "server_url": "%%s"' "$SERVER"
  if [ -n "$CLI_CERT_PATH" ]; then
    printf ',\n  "ca_cert": "%%s"' "$CLI_CERT_PATH"
  fi
  if [ -n "$TLS_FINGERPRINT" ]; then
    printf ',\n  "tls_fingerprint": "%%s"' "$TLS_FINGERPRINT"
  fi
  printf '\n}\n'
} > "$CLI_CONF_FILE"
chmod "$CLI_MODE" "$CLI_CONF_FILE"
echo "==> Saved CLI server config to ${CLI_CONF_FILE}"
if [ -n "$CLI_CERT_PATH" ]; then
  echo "    Pinned TLS CA certificate: ${CLI_CERT_PATH}"
fi

RESOLVED_BIN="$(command -v ducksecrets 2>/dev/null || true)"
if [ -n "$RESOLVED_BIN" ] && [ "$RESOLVED_BIN" != "${TARGET_DIR}/ducksecrets" ]; then
  echo "! Warning: your shell resolves 'ducksecrets' to ${RESOLVED_BIN} instead of ${TARGET_DIR}/ducksecrets."
  echo "  Run 'hash -r' (bash) or 'rehash' (zsh), or remove ${RESOLVED_BIN} to avoid invoking an older binary."
fi

if [ -n "${DUCKSECRETS_SITE_ID:-}" ] && [ -n "${DUCKSECRETS_SITE_TOKEN:-}" ]; then
  SITE_SHORT="$(printf '%%s' "$DUCKSECRETS_SITE_ID" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-' | cut -c1-12)"
  if [ -z "$SITE_SHORT" ]; then
    SITE_SHORT="default"
  fi
  SERVICE_NAME="ducksecrets-site-${SITE_SHORT}.service"

  SCOPE=""
  if [ "${DUCKSECRETS_FOREGROUND:-}" != "1" ] && command -v systemctl >/dev/null 2>&1; then
    if [ "$(id -u)" = "0" ] && [ -d /run/systemd/system ]; then
      SCOPE="system"
      CONF_DIR="/etc/ducksecrets"
      UNIT_DIR="/etc/systemd/system"
      WANTED_BY="multi-user.target"
    elif systemctl --user list-units >/dev/null 2>&1; then
      SCOPE="user"
      CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/ducksecrets"
      UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
      WANTED_BY="default.target"
    fi
  fi

  if [ -n "$SCOPE" ]; then
    echo "==> Configuring systemd service (${SERVICE_NAME}, scope=${SCOPE})..."
    mkdir -p "$CONF_DIR" "$UNIT_DIR"

    SITE_CERT=""
    if [ -n "${DUCKSECRETS_CA_CERT:-}" ]; then
      SITE_CERT="$DUCKSECRETS_CA_CERT"
    elif [ -n "$TMP_CERT" ]; then
      SITE_CERT="${CONF_DIR}/site-${SITE_SHORT}.crt"
      cp "$TMP_CERT" "$SITE_CERT"
      chmod 0644 "$SITE_CERT"
    fi

    ENV_FILE="${CONF_DIR}/site-${SITE_SHORT}.env"
    (
      umask 077
      {
        printf 'DUCKSECRETS_SERVER=%%s\n' "$SERVER"
        printf 'DUCKSECRETS_SITE_ID=%%s\n' "$DUCKSECRETS_SITE_ID"
        printf 'DUCKSECRETS_SITE_TOKEN=%%s\n' "$DUCKSECRETS_SITE_TOKEN"
        if [ -n "$SITE_CERT" ]; then
          printf 'DUCKSECRETS_CA_CERT=%%s\n' "$SITE_CERT"
        fi
        if [ -n "$TLS_FINGERPRINT" ]; then
          printf 'DUCKSECRETS_TLS_FINGERPRINT=%%s\n' "$TLS_FINGERPRINT"
        fi
        if [ -n "${DUCKSECRETS_INSECURE:-}" ]; then
          printf 'DUCKSECRETS_INSECURE=%%s\n' "$DUCKSECRETS_INSECURE"
        fi
      } > "$ENV_FILE"
    )

    UNIT_FILE="${UNIT_DIR}/${SERVICE_NAME}"
    cat <<EOF > "$UNIT_FILE"
[Unit]
Description=DuckSecrets Site Connector (${SITE_SHORT})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${TARGET_DIR}/ducksecrets site run --server "\${DUCKSECRETS_SERVER}" --site-id "\${DUCKSECRETS_SITE_ID}"
Restart=always
RestartSec=5

[Install]
WantedBy=${WANTED_BY}
EOF

    if [ "$SCOPE" = "system" ]; then
      systemctl daemon-reload
      systemctl enable "$SERVICE_NAME"
      systemctl restart "$SERVICE_NAME"
      echo "==> DuckSecrets Site Connector running via systemd (${SERVICE_NAME})"
      echo "    Status: systemctl status ${SERVICE_NAME} --no-pager"
      echo "    Logs:   journalctl -u ${SERVICE_NAME} -f"
    else
      systemctl --user daemon-reload
      systemctl --user enable "$SERVICE_NAME"
      systemctl --user restart "$SERVICE_NAME"
      echo "==> DuckSecrets Site Connector running via user systemd (${SERVICE_NAME})"
      echo "    Status: systemctl --user status ${SERVICE_NAME} --no-pager"
      echo "    Logs:   journalctl --user -u ${SERVICE_NAME} -f"
      echo "    Tip:    For boot persistence without active login, run with sudo or: loginctl enable-linger $USER"
    fi
    exit 0
  fi

  if [ -n "$TLS_FINGERPRINT" ] && [ -z "${DUCKSECRETS_TLS_FINGERPRINT:-}" ]; then
    export DUCKSECRETS_TLS_FINGERPRINT="$TLS_FINGERPRINT"
  fi
  if [ -z "${DUCKSECRETS_CA_CERT:-}" ] && [ -n "$TMP_CERT" ]; then
    FALLBACK_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/ducksecrets"
    mkdir -p "$FALLBACK_DIR"
    cp "$TMP_CERT" "${FALLBACK_DIR}/site-${SITE_SHORT}.crt"
    chmod 0644 "${FALLBACK_DIR}/site-${SITE_SHORT}.crt"
    export DUCKSECRETS_CA_CERT="${FALLBACK_DIR}/site-${SITE_SHORT}.crt"
  fi

  echo "==> Starting DuckSecrets Site Connector in foreground..."
  exec "${TARGET_DIR}/ducksecrets" site run --server "${SERVER}" --site-id "$DUCKSECRETS_SITE_ID"
fi
`, shellQuotePOSIX(serverURL), shellQuotePOSIX(tlsFingerprint), certBlock)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
	return nil
}
