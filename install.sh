#!/bin/bash
set -e

# ConnLog Agent Installer
# Usage: curl -fsSL https://connlog.com/install.sh | sh

REPO="connlog/connlog-agent"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="connlog-agent"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}✓${NC} $1"
}

warn() {
    echo -e "${YELLOW}!${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
    exit 1
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)
            OS="linux"
            ;;
        *)
            error "Unsupported OS: $OS (only Linux is supported)"
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        *)
            error "Unsupported architecture: $ARCH"
            ;;
    esac

    info "Detected platform: $OS-$ARCH"
}

# Get latest release version
get_latest_version() {
    LATEST_VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$LATEST_VERSION" ]; then
        error "Failed to fetch latest version"
    fi

    info "Latest version: $LATEST_VERSION"
}

# Download and verify binary
download_binary() {
    ARTIFACT_NAME="connlog-agent-${LATEST_VERSION}-${OS}-${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_VERSION/$ARTIFACT_NAME"
    CHECKSUM_URL="https://github.com/$REPO/releases/download/$LATEST_VERSION/${ARTIFACT_NAME}.sha256"

    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR"

    info "Downloading $ARTIFACT_NAME..."
    curl -fsSL "$DOWNLOAD_URL" -o "$ARTIFACT_NAME" || error "Download failed"

    info "Downloading checksum..."
    curl -fsSL "$CHECKSUM_URL" -o "${ARTIFACT_NAME}.sha256" || error "Checksum download failed"

    info "Verifying checksum..."
    if command -v sha256sum &> /dev/null; then
        sha256sum -c "${ARTIFACT_NAME}.sha256" || error "Checksum verification failed"
    else
        warn "sha256sum not found, skipping checksum verification"
    fi

    info "Extracting binary..."
    tar -xzf "$ARTIFACT_NAME" || error "Extraction failed"

    BINARY_PATH="$TMP_DIR/$BINARY_NAME"
}

# Install binary
install_binary() {
    info "Installing to $INSTALL_DIR/$BINARY_NAME..."

    # Check if we need sudo
    if [ -w "$INSTALL_DIR" ]; then
        mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
    else
        if command -v sudo &> /dev/null; then
            sudo mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
            sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
        else
            error "Cannot write to $INSTALL_DIR and sudo not available"
        fi
    fi

    # Cleanup
    cd - > /dev/null
    rm -rf "$TMP_DIR"

    info "Installation complete!"
}

# Print next steps
print_next_steps() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    info "ConnLog Agent installed successfully!"
    echo ""
    echo "Next steps:"
    echo ""
    echo "  1. Get your agent token from the ConnLog dashboard"
    echo "  2. Run the agent:"
    echo ""
    echo "     $BINARY_NAME --token <your-token>"
    echo ""
    echo "  Or install as a systemd service:"
    echo ""
    echo "     sudo $BINARY_NAME install --token <your-token>"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# Main installation flow
main() {
    echo ""
    echo "ConnLog Agent Installer"
    echo ""

    detect_platform
    get_latest_version
    download_binary
    install_binary
    print_next_steps
}

main
