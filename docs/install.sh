#!/bin/sh
set -eu

repo="xazar-mammadli/XTunnel"
base="${XTUNNEL_DOWNLOAD_URL:-https://github.com/$repo/releases/latest/download}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "This installer supports Linux and macOS. Download XTunnel from https://github.com/$repo/releases/latest" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) echo "Unsupported processor: $(uname -m). Download XTunnel from https://github.com/$repo/releases/latest" >&2; exit 1 ;;
esac

archive="xtunnel_${os}_${arch}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $archive..."
curl -fsSL "$base/$archive" -o "$tmp/$archive"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"

expected=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
if command -v sha256sum > /dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | awk '{ print $1 }')
else
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "The checksum of $archive does not match SHA256SUMS. Nothing was installed." >&2
  exit 1
fi

tar -xzf "$tmp/$archive" -C "$tmp" ./xtunnel

dir="${XTUNNEL_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    dir=/usr/local/bin
  else
    dir="$HOME/.local/bin"
  fi
fi
mkdir -p "$dir"
cp "$tmp/xtunnel" "$dir/xtunnel"
chmod 0755 "$dir/xtunnel"

echo "Installed XTunnel $("$dir/xtunnel" version) to $dir/xtunnel"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to run xtunnel from anywhere." ;;
esac
