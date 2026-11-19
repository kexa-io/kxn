#!/bin/sh
# Install kxn from the GitHub releases of kexa-io/kxn.
#
#   curl -fsSL https://raw.githubusercontent.com/kexa-io/kxn/main/install.sh | sh
#
# Options (environment variables):
#   KXN_VERSION      release tag to install (default: latest), e.g. v0.57.1
#   KXN_INSTALL_DIR  where to put the binary (default: /usr/local/bin, with
#                    sudo when needed; ~/.local/bin when sudo is unavailable)
set -eu

REPO="kexa-io/kxn"
VERSION="${KXN_VERSION:-latest}"

fail() { echo "kxn install: $*" >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64|Linux-amd64)   TARGET="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64|Linux-arm64)  TARGET="aarch64-unknown-linux-gnu" ;;
  Darwin-x86_64)              TARGET="x86_64-apple-darwin" ;;
  Darwin-arm64)               TARGET="aarch64-apple-darwin" ;;
  *) fail "no prebuilt binary for $(uname -s) $(uname -m); see https://github.com/$REPO#install" ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi
ASSET="kxn-$TARGET.tar.gz"

# /usr/local/bin is on every PATH, so `kxn` works in the same shell right
# after the install; ~/.local/bin often is not until the next login.
SUDO=""
if [ -n "${KXN_INSTALL_DIR:-}" ]; then
  DIR="$KXN_INSTALL_DIR"
elif [ -w /usr/local/bin ]; then
  DIR=/usr/local/bin
elif command -v sudo >/dev/null 2>&1; then
  DIR=/usr/local/bin
  SUDO=sudo
else
  DIR="$HOME/.local/bin"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "Downloading kxn ($VERSION, $TARGET)..."
curl -fsSL "$BASE/$ASSET" -o "$TMP/$ASSET" || fail "download failed: $BASE/$ASSET"

# Verify the archive against the release's checksums when a tool is available.
if curl -fsSL "$BASE/checksums.txt" -o "$TMP/checksums.txt" 2>/dev/null; then
  EXPECTED=$(awk -v f="$ASSET" '$2 == f { print $1 }' "$TMP/checksums.txt")
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$TMP/$ASSET" | awk '{ print $1 }')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$TMP/$ASSET" | awk '{ print $1 }')
  else
    ACTUAL=""
  fi
  if [ -n "$EXPECTED" ] && [ -n "$ACTUAL" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
    fail "checksum mismatch for $ASSET"
  fi
fi

tar -xzf "$TMP/$ASSET" -C "$TMP"
[ -n "$SUDO" ] && echo "Installing to $DIR (sudo may ask for your password)..."
$SUDO mkdir -p "$DIR"
$SUDO install -m 0755 "$TMP/kxn" "$DIR/kxn"

echo "kxn installed to $DIR/kxn"
case ":$PATH:" in
  *":$DIR:"*) "$DIR/kxn" --version ;;
  *) echo "Add it to your PATH:  export PATH=\"$DIR:\$PATH\"" ;;
esac
