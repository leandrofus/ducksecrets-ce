# Ducksecrets — top-level build.
#
#   make dev       gateway + UI with hot reload
#   make build     one binary with the UI inside, into dist/bin
#   make generate  after changing SQL or an API comment
#   make help      everything

VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo 0.1.0)
DIST    := dist
BIN     := $(DIST)/bin

.DEFAULT_GOAL := help
.PHONY: help dev dev-gateway dev-web build web gateway generate test test-go test-web test-postgres dist packages clean \
        postgres postgres-stop

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- develop ----

dev: ## Gateway (first free port from :5179, or DUCKSECRETS_PORT) and Vite on :5173 (proxying /api); HOST=0.0.0.0 to reach it from the network
	dev/run.sh

dev-gateway: ## Only the server gateway (go run), with the data in .dev/
	mkdir -p .dev && cd gateway && DUCKSECRETS_DB=../.dev/ducksecrets.db go run ./cmd/ducksecretsd

dev-web: ## Only the UI dev server (needs a gateway on :5179)
	cd web && bun run dev

# ---- build ----

build: web gateway ## Compile the UI and the binaries into dist/bin
	@mkdir -p $(BIN)
	cp gateway/bin/ducksecretsd $(BIN)/
	cp gateway/bin/ducksecrets $(BIN)/
	@ls -lh $(BIN)

web: ## UI into gateway/internal/server/ui/dist (embedded)
	$(MAKE) -C gateway web

gateway: ## The gateway binary (static, CGO off)
	$(MAKE) -C gateway build VERSION=$(VERSION)

generate: ## Regenerate sqlc code, the OpenAPI spec and the UI's API types
	$(MAKE) -C gateway generate openapi
	cd web && bun run gen-api

# ---- check ----

test: test-go test-web ## Vet, test, check generated code is current, typecheck the UI

test-go:
	cd gateway && go vet ./... && go test ./... && go run ./cmd/openapi-gen -check

test-web:
	cd web && bun install --frozen-lockfile
	@# regenerated types must equal the file on disk (not the git index: uncommitted work is fine)
	cd web && cp src/lib/api-types.ts .api-types.prev && bun run gen-api && diff -u .api-types.prev src/lib/api-types.ts; rc=$$?; rm -f .api-types.prev; exit $$rc
	cd web && bun run typecheck

# Runs a throwaway container (docker or podman) unless one is already up.
CONTAINER := $(shell command -v docker || command -v podman)

POSTGRES_URL := postgres://ducksecrets:ducksecrets@127.0.0.1:25432/ducksecrets?sslmode=disable
test-postgres: ## The gateway suites again on PostgreSQL (each test in its own schema)
	@started=; if ! $(CONTAINER) exec ducksecrets-postgres pg_isready -q -h 127.0.0.1 2>/dev/null; then $(MAKE) -s postgres && started=1; fi; \
	cd gateway && DUCKSECRETS_TEST_POSTGRES='$(POSTGRES_URL)' go test -count=1 ./internal/...; rc=$$?; \
	cd .. && if [ -n "$$started" ]; then $(MAKE) -s postgres-stop; fi; exit $$rc

postgres: ## Start PostgreSQL for development (DUCKSECRETS_DB=$(POSTGRES_URL))
	$(CONTAINER) run -d --rm --name ducksecrets-postgres -p 25432:5432 -e POSTGRES_USER=ducksecrets -e POSTGRES_PASSWORD=ducksecrets -e POSTGRES_DB=ducksecrets postgres:17-alpine >/dev/null
	@# over TCP: during initdb the image runs a socket-only server that pg_isready would accept
	@until $(CONTAINER) exec ducksecrets-postgres pg_isready -q -h 127.0.0.1 2>/dev/null; do sleep 0.5; done; echo "postgres: $(POSTGRES_URL)"

postgres-stop: ## Stop PostgreSQL
	-$(CONTAINER) stop ducksecrets-postgres >/dev/null

# ---- release ----

PLATFORMS := linux/amd64 linux/arm64 darwin/arm64 windows/amd64
LICENSE_PUBLIC_KEY ?=
DIST_LDFLAGS := -s -w -X main.version=$(VERSION)
ifneq ($(strip $(LICENSE_PUBLIC_KEY)),)
DIST_LDFLAGS += -X github.com/leandrofus/ducksecrets/gateway/internal/license.DefaultPublicKeyHex=$(LICENSE_PUBLIC_KEY)
endif

dist: web ## Static binaries (CLI + daemon) for every platform, with checksums, in dist/
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "→ $$os/$$arch (ducksecrets + ducksecretsd)"; \
		(cd gateway && CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(DIST_LDFLAGS)' -o "../$(DIST)/ducksecrets-$$os-$$arch$$ext" ./cmd/ducksecrets) || exit 1; \
		(cd gateway && CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(DIST_LDFLAGS)' -o "../$(DIST)/ducksecretsd-$$os-$$arch$$ext" ./cmd/ducksecretsd) || exit 1; \
	done
	cd $(DIST) && sha256sum ducksecrets-* ducksecretsd-* > SHA256SUMS

packages: dist ## Native packages (.deb, .rpm, .pkg.tar.zst, .msi) + checksums in dist/
	./scripts/package.sh --version "$(VERSION)" --dist "$(DIST)"

clean: ## Remove build outputs (keeps .dev data)
	rm -rf $(DIST) gateway/bin/ducksecrets gateway/bin/ducksecretsd
	find gateway/internal/server/ui/dist -mindepth 1 ! -name .gitkeep -delete
