#!/usr/bin/env bash
# make dev: the gateway (go run, data in .dev/) and Vite with hot reload,
# side by side. Open http://localhost:5173. Ctrl-C stops both.
# HOST=0.0.0.0 make dev serves the UI to the network too (the gateway stays
# on 127.0.0.1: Vite proxies /api to it).
# The gateway takes the first free port from 8080; DUCKSECRETS_PORT=8085 picks one
# (and fails if it is taken) so a service already on :8080 is never mistaken for it.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .dev
[ -d web/node_modules ] || (cd web && bun install)
busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
port=${DUCKSECRETS_PORT:-}
if [ -z "$port" ]; then
  port=8080
  while busy "$port"; do port=$((port + 1)); done
elif busy "$port"; then
  echo "dev: port $port is in use (DUCKSECRETS_PORT)" >&2
  exit 1
fi
export DUCKSECRETS_PORT=$port DUCKSECRETS_LISTEN=127.0.0.1:$port # web/vite.config.ts proxies /api to DUCKSECRETS_PORT
export DUCKSECRETS_DB=${DUCKSECRETS_DB:-$PWD/.dev/ducksecrets.db}
# A fixed dev password instead of the one-time random one.
export DUCKSECRETS_ADMIN_PASSWORD=${DUCKSECRETS_ADMIN_PASSWORD:-admin-password}
# .dev/ keeps its database: without this an admin made by an earlier run keeps its old password.
# Skip automatic password resets when HOST exposes Vite beyond loopback.
default_reset=1
if [ -n "${HOST:-}" ] && [ "$HOST" != "127.0.0.1" ] && [ "$HOST" != "localhost" ] && [ "$HOST" != "::1" ]; then
  echo "dev: HOST=$HOST is non-loopback; skipping automatic admin password reset" >&2
  default_reset=0
fi
export DUCKSECRETS_ADMIN_PASSWORD_RESET=${DUCKSECRETS_ADMIN_PASSWORD_RESET:-$default_reset}

trap 'kill 0' EXIT
(cd gateway && go run ./cmd/ducksecretsd) &
(cd web && bun run dev --clearScreen false ${HOST:+--host "$HOST"}) &
echo "dev: http://${HOST:-localhost}:5173  gateway :$port  (admin / $DUCKSECRETS_ADMIN_PASSWORD)"
wait
