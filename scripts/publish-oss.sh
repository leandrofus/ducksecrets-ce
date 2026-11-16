#!/usr/bin/env bash
# Publishes a sanitized Open-Core snapshot from this private development repo
# to a public repository (dry-run by default; pass --push to push remotely).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/publish-oss.sh --target <git-url-or-path> [options]

Options:
  --target <url>     Destination public Git repository (required)
  --branch <name>    Destination branch (default: main)
  --ref <git-ref>    Source commit/branch/tag in this repo (default: HEAD)
  --tag <vX.Y.Z>     Create and push an annotated release tag on the public snapshot
  --orphan           Create a single root commit (strips all prior commit history)
  --skip-check       Skip running CI=1 ./scripts/check.sh inside the exported snapshot
  --push             Push branch (and --tag if set) to --target (otherwise dry-run)
  -h, --help         Show this help
EOF
}

TARGET=""
DEST_BRANCH="main"
SRC_REF="HEAD"
REL_TAG=""
ORPHAN=0
SKIP_CHECK=0
DO_PUSH=0

while [ $# -gt 0 ]; do
  case "$1" in
    --target)     TARGET="${2:-}"; shift 2 ;;
    --branch)     DEST_BRANCH="${2:-}"; shift 2 ;;
    --ref)        SRC_REF="${2:-}"; shift 2 ;;
    --tag)        REL_TAG="${2:-}"; shift 2 ;;
    --orphan)     ORPHAN=1; shift ;;
    --skip-check) SKIP_CHECK=1; shift ;;
    --push)       DO_PUSH=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[ -n "$TARGET" ] || { echo "error: --target is required" >&2; usage >&2; exit 1; }

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

if ! git rev-parse --verify "${SRC_REF}^{commit}" >/dev/null 2>&1; then
  echo "error: invalid source ref '$SRC_REF'" >&2
  exit 1
fi

SRC_SHA=$(git rev-parse --short "$SRC_REF")
WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

EXPORT_DIR="$WORK/export"
REPO_DIR="$WORK/repo"
mkdir -p "$EXPORT_DIR"

echo "== Exporting clean archive of $SRC_REF ($SRC_SHA)"
git archive --format=tar "$SRC_REF" | tar -xf - -C "$EXPORT_DIR"

# Strip development/internal-only paths and artifacts from the public snapshot.
STRIP_PATHS=(
  ".dev"
  ".claude"
  "CLAUDE.md"
  "docker-compose.dev.yml"
  "docs"
  "skills"
  "data"
  "dist"
  "gateway/bin"
  "gateway/cmd/ducksecrets-license"
  "gateway/internal/ee"
)
for rel in "${STRIP_PATHS[@]}"; do
  rm -rf "${EXPORT_DIR:?}/$rel"
done
find "$EXPORT_DIR" \( -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm' -o -name '*.audit-key' -o -name '*.encryption-key' \) -delete

if [ "$SKIP_CHECK" -eq 0 ]; then
  echo "== Running CI=1 ./scripts/check.sh on exported snapshot"
  if [ -f "$ROOT_DIR/gateway/bin/sqlc" ] && [ ! -f "$EXPORT_DIR/gateway/bin/sqlc" ]; then
    mkdir -p "$EXPORT_DIR/gateway/bin"
    cp "$ROOT_DIR/gateway/bin/sqlc" "$EXPORT_DIR/gateway/bin/sqlc"
  fi
  (cd "$EXPORT_DIR" && CI=1 ./scripts/check.sh)
  rm -f "$EXPORT_DIR/gateway/bin/sqlc"
  rmdir "$EXPORT_DIR/gateway/bin" 2>/dev/null || true
fi

echo "== Preparing destination repository ($TARGET @ $DEST_BRANCH)"
if git ls-remote "$TARGET" >/dev/null 2>&1; then
  git clone --quiet "$TARGET" "$REPO_DIR"
else
  echo "error: cannot reach target repo '$TARGET'" >&2
  exit 1
fi

cd "$REPO_DIR"
if [ "$ORPHAN" -eq 1 ]; then
  # Checkout a temporary orphan name so --orphan succeeds even when clone checked out $DEST_BRANCH.
  git checkout --orphan "__publish_orphan"
elif git show-ref --verify --quiet "refs/remotes/origin/$DEST_BRANCH"; then
  git checkout -B "$DEST_BRANCH" "origin/$DEST_BRANCH"
else
  git checkout --orphan "$DEST_BRANCH"
fi

# Replace tracked/untracked workspace content cleanly while keeping .git.
find "$REPO_DIR" -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +
cp -a "$EXPORT_DIR/." "$REPO_DIR/"

git add -A
MSG="Release snapshot ${REL_TAG:-$SRC_SHA}"
if git diff --cached --quiet && [ -n "$(git rev-list -n1 --all 2>/dev/null || true)" ]; then
  echo "== No file changes to commit against $TARGET ($DEST_BRANCH)"
else
  git commit -m "$MSG"
fi
if [ "$ORPHAN" -eq 1 ]; then
  git branch -M "$DEST_BRANCH"
fi

if [ -n "$REL_TAG" ]; then
  if git rev-parse -q --verify "refs/tags/$REL_TAG" >/dev/null; then
    echo "error: tag '$REL_TAG' already exists in target repo" >&2
    exit 1
  fi
  git tag -a "$REL_TAG" -m "DuckSecrets $REL_TAG"
fi

if [ "$DO_PUSH" -eq 1 ]; then
  if [ "$ORPHAN" -eq 1 ]; then
    git push --force-with-lease origin "$DEST_BRANCH"
  else
    git push origin "$DEST_BRANCH"
  fi
  if [ -n "$REL_TAG" ]; then
    git push origin "$REL_TAG"
  fi
  echo "== Published to $TARGET ($DEST_BRANCH${REL_TAG:+ @ $REL_TAG})"
else
  echo
  echo "== Dry-run complete (no push performed)"
  git --no-pager log -n 1 --stat
  echo "To push, re-run with --push"
fi
