#!/bin/bash
set -e

# ConnLog Agent Installer
# Usage: curl -fsSL https://connlog.com/install.sh | sudo sh -s -- --install --token <token>

REPO="connlog/connlog-agent"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="connlog-agent"

# Parse command line arguments
INSTALL_MODE=false
AGENT_TOKEN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --install)
            INSTALL_MODE=true
            shift
            ;;
        --token)
            AGENT_TOKEN="$2"
            shift 2
            ;;
        *)
            error "Unknown argument: $1"
            ;;
    esac
done

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

# Cleanup function for rollback
cleanup() {
    if [ $? -ne 0 ]; then
        warn "Installation failed, cleaning up..."
        if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
            rm -rf "$TMP_DIR"
        fi
    fi
}

trap cleanup EXIT ERR

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
    elif command -v shasum &> /dev/null; then
        shasum -a 256 -c "${ARTIFACT_NAME}.sha256" || error "Checksum verification failed"
    else
        error "Neither sha256sum nor shasum found. Cannot verify download integrity."
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

# Run agent installation
run_agent_install() {
    if [ -z "$AGENT_TOKEN" ]; then
        error "Token is required for --install mode. Use: --token <your-token>"
    fi

    # Validate token format
    if [[ ! "$AGENT_TOKEN" =~ ^agent_ ]]; then
        error "Invalid token format. Token must start with 'agent_'"
    fi

    info "Running agent installation..."

    # Run the agent's install command
    if ! "$INSTALL_DIR/$BINARY_NAME" install --token "$AGENT_TOKEN"; then
        error "Agent installation failed. Check logs above for details."
    fi

    info "Agent installed and started successfully!"

    # Post-install smoke tests — these confirm the install actually works
    # before declaring success. Both run in-process against the platform; a
    # green pair means token + endpoint + heartbeat path are all healthy.
    info "Verifying platform connectivity (--check-config)..."
    if ! CONNLOG_TOKEN="$AGENT_TOKEN" "$INSTALL_DIR/$BINARY_NAME" --check-config; then
        warn "Smoke test '--check-config' failed. Service is installed but"
        warn "couldn't reach the platform. Run it manually for details:"
        warn "  sudo CONNLOG_TOKEN=<token> $BINARY_NAME --check-config"
    fi

    info "Sending one test heartbeat (--test-heartbeat)..."
    if ! CONNLOG_TOKEN="$AGENT_TOKEN" "$INSTALL_DIR/$BINARY_NAME" --test-heartbeat; then
        warn "Smoke test '--test-heartbeat' failed. Check the platform side"
        warn "for the agent — the service will keep retrying."
    fi
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    info "Installation complete!"
    echo ""
    echo "  • Agent is running as a systemd service"
    echo "  • Check status: sudo systemctl status connlog-agent"
    echo "  • View logs: sudo journalctl -u connlog-agent -f"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# Print next steps (manual mode)
print_next_steps() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    info "ConnLog Agent binary installed successfully!"
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

    # If --install flag is provided, run full installation
    if [ "$INSTALL_MODE" = true ]; then
        run_agent_install
    else
        print_next_steps
    fi
}

main
