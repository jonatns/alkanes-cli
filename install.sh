#!/bin/bash
# Install script for alkanes-cli
# Usage: curl -sSf https://raw.githubusercontent.com/jonatns/alkanes-cli/main/install.sh | bash

set -e

REPO="jonatns/alkanes-cli"
BINARY_NAME="alkanes"
INSTALL_DIR="${HOME}/.local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)
        case "$ARCH" in
            x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
            aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    darwin)
        case "$ARCH" in
            x86_64) TARGET="x86_64-apple-darwin" ;;
            arm64) TARGET="aarch64-apple-darwin" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "Please install manually or use: cargo install --git https://github.com/$REPO"
        exit 1
        ;;
esac

echo "Detected: $OS ($ARCH)"
echo "Installing alkanes-cli for $TARGET..."

# Get latest release
LATEST_RELEASE=$(curl -sSf "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_RELEASE" ]; then
    echo "Could not find latest release. Please install manually:"
    echo "  cargo install --git https://github.com/$REPO"
    exit 1
fi

echo "Latest version: $LATEST_RELEASE"

# Download
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_RELEASE/alkanes-$TARGET.tar.gz"
echo "Downloading from: $DOWNLOAD_URL"

TEMP_DIR=$(mktemp -d)
curl -sSfL "$DOWNLOAD_URL" -o "$TEMP_DIR/alkanes.tar.gz"

# Extract
tar -xzf "$TEMP_DIR/alkanes.tar.gz" -C "$TEMP_DIR"

# Install
mkdir -p "$INSTALL_DIR"
mv "$TEMP_DIR/$BINARY_NAME" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "✅ alkanes-cli installed to $INSTALL_DIR/$BINARY_NAME"
echo ""

# Check if in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "⚠️  $INSTALL_DIR is not in your PATH."
    echo "   Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    echo ""
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
fi

echo "Run 'alkanes --help' to get started!"

