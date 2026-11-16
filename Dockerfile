# syntax=docker/dockerfile:1

FROM oven/bun:1-alpine AS web
WORKDIR /src
COPY gateway/openapi ./gateway/openapi
COPY web/package.json web/bun.lock ./web/
RUN cd web && bun install --frozen-lockfile
COPY web ./web
RUN mkdir -p gateway/internal/server/ui/dist && cd web && bun run build

FROM golang:1.26-alpine AS builder
WORKDIR /src/gateway
ARG VERSION=dev
ARG LICENSE_PUBLIC_KEY=
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download
COPY gateway ./
COPY --from=web /src/gateway/internal/server/ui/dist ./internal/server/ui/dist
RUN set -eux; \
    LDFLAGS="-s -w -X main.version=${VERSION}"; \
    if [ -n "${LICENSE_PUBLIC_KEY}" ]; then \
      LDFLAGS="${LDFLAGS} -X github.com/leandrofus/ducksecrets/gateway/internal/license.DefaultPublicKeyHex=${LICENSE_PUBLIC_KEY}"; \
    fi; \
    CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o /out/ducksecretsd ./cmd/ducksecretsd; \
    CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o /out/ducksecrets ./cmd/ducksecrets

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S ducksecrets && \
    adduser -S -G ducksecrets -h /data ducksecrets && \
    mkdir -p /data && \
    chown -R ducksecrets:ducksecrets /data
COPY --from=builder /out/ducksecretsd /usr/local/bin/ducksecretsd
COPY --from=builder /out/ducksecrets /usr/local/bin/ducksecrets

USER ducksecrets
WORKDIR /data
VOLUME ["/data"]
EXPOSE 5179

ENV DUCKSECRETS_LISTEN=0.0.0.0:5179 \
    DUCKSECRETS_DB=/data/ducksecrets.db

ENTRYPOINT ["/usr/local/bin/ducksecretsd"]
