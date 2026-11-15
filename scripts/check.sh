#!/usr/bin/env sh
# One check for laptops and CI: run before every commit and push.
#   scripts/check.sh          format, vet, tests, drift, repo guards
#   CI=1 scripts/check.sh     strict mode: missing tools fail instead of skipping
set -eu
cd "$(dirname "$0")/.."
fail=0
step() { printf '\n== %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1"; fail=1; }
skip_or_fail() {
  if [ "${CI:-0}" = "1" ]; then
    bad "$1"
  else
    echo "skipped: $1"
  fi
}

step "gofmt"
out=$(gofmt -l gateway/cmd gateway/internal 2>/dev/null || true)
[ -z "$out" ] || bad "not formatted: $out (run 'gofmt -w gateway/')"

step "Makefile parses"
if command -v make >/dev/null 2>&1; then
  make -s -n help >/dev/null || bad "Makefile does not parse (make -n help)"
else
  skip_or_fail "make not installed"
fi

step "go vet"
(cd gateway && go vet ./...) || bad "go vet"

step "go test"
(cd gateway && go test -count=1 ./...) || bad "go test"

step "CLI builds static for linux and imports no server/database packages"
for arch in amd64 arm64; do
  (cd gateway && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o /dev/null ./cmd/ducksecrets) || bad "ducksecrets CLI does not build for linux/$arch with CGO off"
done
if (cd gateway && CGO_ENABLED=0 GOOS=linux go list -deps ./cmd/ducksecrets | grep -E 'ducksecrets/gateway/internal/(server|store)|sqlite'); then
  bad "cmd/ducksecrets CLI must not import gateway server packages or SQLite"
fi

step "daemon builds static for linux"
for arch in amd64 arm64; do
  (cd gateway && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o /dev/null ./cmd/ducksecretsd) || bad "ducksecretsd daemon does not build for linux/$arch with CGO off"
done

step "OpenAPI contract consistency"
(cd gateway && go run ./cmd/openapi-gen -check) || bad "gateway/openapi/openapi.yaml is out of date (run 'make -C gateway openapi')"

step "sqlc drift"
if [ -f gateway/bin/sqlc ]; then
  tmp=$(mktemp -d)
  cp -R gateway/internal/store/db "$tmp/db"
  (cd gateway && bin/sqlc generate) || bad "sqlc generate failed"
  diff -r "$tmp/db" gateway/internal/store/db >/dev/null 2>&1 || bad "gateway/internal/store/db is stale: run 'make -C gateway generate' and commit"
  rm -rf "$tmp"
else
  skip_or_fail "gateway/bin/sqlc not downloaded yet (run 'make -C gateway generate' once)"
fi

step "web air-gapped guard"
if grep -rnE '(src|href)=["'"'"']?(https?:)?//|url\(["'"'"']?(https?:)?//|@import +["'"'"']https?:|from +["'"'"']https?:' web/src web/index.html --exclude='*.d.ts' 2>/dev/null; then
  bad "external asset URL in web/ (the UI must work air-gapped without CDNs)"
fi

step "web typecheck & API drift"
if command -v bun >/dev/null 2>&1; then
  (
    cd web
    [ -d node_modules ] || bun install --frozen-lockfile >/dev/null
    before=$(mktemp)
    cp src/lib/api-types.ts "$before"
    bun run gen-api >/dev/null 2>&1 || exit 1
    if ! cmp -s "$before" src/lib/api-types.ts; then
      rm -f "$before"
      echo "src/lib/api-types.ts was out of date with openapi.yaml: run 'bun run gen-api' in web/ and commit"
      exit 1
    fi
    rm -f "$before"
    bun run typecheck || exit 1
  ) || bad "web typecheck or API types drift"
else
  skip_or_fail "bun not installed"
fi

if [ -n "${DUCKSECRETS_TEST_POSTGRES:-}" ]; then
  step "go test (postgres)"
  (cd gateway && go test -count=1 ./internal/...) || bad "go test postgres"
fi

[ "$fail" -eq 0 ] && printf '\nall checks passed\n' || { printf '\nchecks failed\n'; exit 1; }
