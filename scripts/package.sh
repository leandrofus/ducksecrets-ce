#!/usr/bin/env bash
# Package Ducksecrets release binaries into .deb, .rpm, .pkg.tar.zst (Arch), and .msi installers.
# Expects binaries produced by `make dist` inside DIST_DIR (default: dist).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIST_DIR="${DIST_DIR:-dist}"
VERSION="${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || jq -r .version web/package.json 2>/dev/null || echo 0.2.0)}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dist)    DIST_DIR="$2"; shift 2 ;;
    -h|--help)
      echo "usage: $0 [--version X.Y.Z] [--dist dist]"
      exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

PKG_VERSION="${VERSION#v}"
# MSI Product/@Version strictly requires numeric X.Y.Z(.W) without prerelease tags.
MSI_VERSION="$(printf '%s' "$PKG_VERSION" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')"
if ! [[ "$MSI_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid semantic version for MSI: $VERSION" >&2
  exit 1
fi

for req in \
  "$DIST_DIR/ducksecrets-linux-amd64" \
  "$DIST_DIR/ducksecretsd-linux-amd64" \
  "$DIST_DIR/ducksecrets-linux-arm64" \
  "$DIST_DIR/ducksecretsd-linux-arm64" \
  "$DIST_DIR/ducksecrets-windows-amd64.exe" \
  "$DIST_DIR/ducksecretsd-windows-amd64.exe"; do
  if [[ ! -f "$req" ]]; then
    echo "missing binary $req — run 'make dist VERSION=$VERSION' first" >&2
    exit 1
  fi
done

NFPM_TMP=""
cleanup() { [[ -n "$NFPM_TMP" ]] && rm -rf "$NFPM_TMP"; }
trap cleanup EXIT

if command -v nfpm >/dev/null 2>&1; then
  NFPM_BIN="$(command -v nfpm)"
  NFPM_TMP="$(mktemp -d)"
else
  NFPM_TMP="$(mktemp -d)"
  (cd gateway && GOBIN="$NFPM_TMP" go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.1)
  NFPM_BIN="$NFPM_TMP/nfpm"
fi

echo "==> Packaging .deb, .rpm, and .pkg.tar.zst (version $PKG_VERSION)"
for arch in amd64 arm64; do
  cfg="$NFPM_TMP/nfpm-${arch}.yaml"
  sed -e "s|@VERSION@|${PKG_VERSION}|g" \
      -e "s|@ARCH@|${arch}|g" \
      -e "s|@DIST_DIR@|${DIST_DIR}|g" \
      "$ROOT/deploy/packaging/nfpm.yaml" > "$cfg"
  "$NFPM_BIN" package --config "$cfg" --packager deb \
    --target "$ROOT/$DIST_DIR/ducksecrets-${PKG_VERSION}-linux-${arch}.deb"
  "$NFPM_BIN" package --config "$cfg" --packager rpm \
    --target "$ROOT/$DIST_DIR/ducksecrets-${PKG_VERSION}-linux-${arch}.rpm"
  "$NFPM_BIN" package --config "$cfg" --packager archlinux \
    --target "$ROOT/$DIST_DIR/ducksecrets-${PKG_VERSION}-linux-${arch}.pkg.tar.zst"
done

MSI_OUT="$DIST_DIR/ducksecrets-${PKG_VERSION}-windows-amd64.msi"
echo "==> Packaging .msi ($MSI_OUT, MsiVersion=$MSI_VERSION)"
if command -v wixl >/dev/null 2>&1; then
  wixl --arch x64 \
    -D "MsiVersion=$MSI_VERSION" \
    -D "DistDir=$DIST_DIR" \
    -o "$MSI_OUT" \
    deploy/packaging/ducksecrets.wxs
elif command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$ROOT:/src" -w /src debian:bookworm-slim \
    sh -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends wixl >/dev/null && wixl --arch x64 -D MsiVersion='$MSI_VERSION' -D DistDir='$DIST_DIR' -o '$MSI_OUT' deploy/packaging/ducksecrets.wxs"
else
  echo "error: wixl (msitools) or docker is required to build .msi packages" >&2
  exit 1
fi

echo "==> Updating $DIST_DIR/SHA256SUMS"
(cd "$DIST_DIR" && sha256sum ducksecrets-* ducksecretsd-* > SHA256SUMS)
ls -lh "$DIST_DIR"/ducksecrets-*.deb "$DIST_DIR"/ducksecrets-*.rpm "$DIST_DIR"/ducksecrets-*.pkg.tar.zst "$DIST_DIR"/ducksecrets-*.msi
