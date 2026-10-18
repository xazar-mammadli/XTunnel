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

system=/usr/local/bin

writable() {
  mkdir -p "$1" 2> /dev/null && [ -w "$1" ]
}

on_path() {
  case ":$PATH:" in
    *":$1:"*) return 0 ;;
  esac
  return 1
}

place() {
  cp "$tmp/xtunnel" "$1/xtunnel" && chmod 0755 "$1/xtunnel"
}

dir=""
if [ -n "${XTUNNEL_INSTALL_DIR:-}" ]; then
  if ! writable "$XTUNNEL_INSTALL_DIR"; then
    echo "Can't write to $XTUNNEL_INSTALL_DIR. Choose another folder in XTUNNEL_INSTALL_DIR." >&2
    exit 1
  fi
  dir="$XTUNNEL_INSTALL_DIR"
elif [ -d "$system" ] && [ -w "$system" ]; then
  dir="$system"
else
  for candidate in "$HOME/.local/bin" "$HOME/bin"; do
    if on_path "$candidate" && writable "$candidate"; then
      dir="$candidate"
      break
    fi
  done
fi

if [ -n "$dir" ]; then
  place "$dir"
elif command -v sudo > /dev/null 2>&1; then
  echo "Installing to $system needs administrator rights, so sudo may ask for your password."
  if ! sudo sh -c "mkdir -p '$system' && cp '$tmp/xtunnel' '$system/xtunnel' && chmod 0755 '$system/xtunnel'"; then
    echo "Could not install to $system. Run again with XTUNNEL_INSTALL_DIR set to a folder you can write to." >&2
    exit 1
  fi
  dir="$system"
elif writable "$HOME/.local/bin"; then
  dir="$HOME/.local/bin"
  place "$dir"
else
  echo "No folder to install into. Run again with XTUNNEL_INSTALL_DIR set to a folder you can write to." >&2
  exit 1
fi

echo "Installed XTunnel $("$dir/xtunnel" version) to $dir/xtunnel"
if ! on_path "$dir"; then
  echo "Add $dir to your PATH to run xtunnel from anywhere."
fi
