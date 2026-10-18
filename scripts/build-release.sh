#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
version="${version#v}"
ldflags="-s -w -X main.appVersion=${version}"
targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)

rm -rf dist
mkdir -p dist

for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  suffix=""
  [ "$goos" = windows ] && suffix=".exe"
  name="xtunnel_${goos}_${goarch}"
  stage="dist/${name}"
  mkdir -p "$stage"

  echo "Building ${target}..."
  for cmd in xtunnel xtunneld; do
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
      go build -trimpath -ldflags "$ldflags" -o "${stage}/${cmd}${suffix}" "./cmd/${cmd}"
  done
  cp LICENSE "$stage/"

  if [ "$goos" = windows ]; then
    (cd "$stage" && zip -qr "../${name}.zip" .)
  else
    (cd "$stage" && tar -czf "../${name}.tar.gz" .)
  fi
  rm -rf "$stage"
done

cd dist
archives=(*.tar.gz *.zip)
if command -v sha256sum > /dev/null; then
  sha256sum "${archives[@]}" > SHA256SUMS
else
  shasum -a 256 "${archives[@]}" > SHA256SUMS
fi
cd ..

echo "Done:"
ls -1 dist
