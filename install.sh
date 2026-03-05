#!/bin/bash
set -euo pipefail

REPO="kexa-io/kxn"
INSTALL_DIR="${KXN_INSTALL_DIR:-/usr/local/bin}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin) ;;
  linux) ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64) ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Map to Rust target triple
case "$OS-$ARCH" in
  darwin-x86_64)   TARGET="x86_64-apple-darwin" ;;
  darwin-aarch64)  TARGET="aarch64-apple-darwin" ;;
  linux-x86_64)    TARGET="x86_64-unknown-linux-gnu" ;;
  *) echo "No binary available for $OS-$ARCH"; exit 1 ;;
esac

ASSET="kxn-${TARGET}.tar.gz"

# Get latest version if not specified
VERSION="${KXN_VERSION:-latest}"
if [ "$VERSION" = "latest" ]; then
  VERSION=$(gh release view --repo "$REPO" --json tagName --jq '.tagName' 2>/dev/null) || {
    echo "Failed to get latest version. Is 'gh' installed and authenticated?"
    echo "  brew install gh && gh auth login"
    exit 1
  }
fi

echo "Installing kxn $VERSION ($TARGET)..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

gh release download "$VERSION" --repo "$REPO" --pattern "$ASSET" --dir "$TMPDIR" || {
  echo "Download failed. Check that:"
  echo "  1. 'gh' is authenticated: gh auth status"
  echo "  2. You have access to $REPO"
  exit 1
}

tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"

if [ -w "$INSTALL_DIR" ]; then
  cp "$TMPDIR/kxn" "$INSTALL_DIR/kxn"
else
  echo "Installing to $INSTALL_DIR (requires sudo)..."
  sudo cp "$TMPDIR/kxn" "$INSTALL_DIR/kxn"
fi

chmod +x "$INSTALL_DIR/kxn"
echo "kxn $VERSION installed to $INSTALL_DIR/kxn"
"$INSTALL_DIR/kxn" --version
