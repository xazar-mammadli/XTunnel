#!/usr/bin/env bash
# Build xtunnel + xtunneld for every supported platform into dist/, with
# SHA-256 checksums. Usage: scripts/build-release.sh [version]
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.appVersion=${VERSION}"

TARGETS=(
  linux/amd64 linux/arm64
  darwin/amd64 darwin/arm64
  windows/amd64 windows/arm64
)

rm -rf dist
mkdir -p dist

for target in "${TARGETS[@]}"; do
  GOOS="${target%/*}"
  GOARCH="${target#*/}"
  suffix=""
  [ "$GOOS" = "windows" ] && suffix=".exe"
  outdir="dist/xtunnel_${VERSION}_${GOOS}_${GOARCH}"
  mkdir -p "$outdir"

  echo "building ${target}..."
  for cmd in xtunnel xtunneld; do
    GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
      go build -trimpath -ldflags "$LDFLAGS" \
      -o "${outdir}/${cmd}${suffix}" "./cmd/${cmd}"
  done

  # Package: .zip for Windows, .tar.gz elsewhere.
  base="xtunnel_${VERSION}_${GOOS}_${GOARCH}"
  if [ "$GOOS" = "windows" ]; then
    (cd dist && zip -qr "${base}.zip" "$base")
  else
    (cd dist && tar -czf "${base}.tar.gz" "$base")
  fi
  rm -rf "$outdir"
done

echo "checksums..."
(cd dist && shasum -a 256 ./* > SHA256SUMS 2>/dev/null || sha256sum ./* > SHA256SUMS)

echo "artifacts:"
ls -1 dist/
