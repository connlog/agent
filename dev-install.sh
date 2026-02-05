#!/bin/bash
set -e

# ConnLog Agent - Development Install Script
# Usage: ./dev-install.sh <token>

if [ -z "$1" ]; then
    echo "❌ Error: Token required"
    echo ""
    echo "Usage: ./dev-install.sh <agent-token>"
    echo ""
    echo "Example:"
    echo "  ./dev-install.sh agent_abc123..."
    exit 1
fi

TOKEN="$1"
ENDPOINT="${CONNLOG_ENDPOINT:-http://localhost:3000}"

echo "🔧 ConnLog Agent - Development Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Token:    ${TOKEN:0:20}..."
echo "Endpoint: $ENDPOINT"
echo ""

# Check if token format is valid
if [[ ! "$TOKEN" =~ ^agent_ ]]; then
    echo "❌ Error: Invalid token format (must start with 'agent_')"
    exit 1
fi

# Build the agent in release mode for better performance
echo "📦 Building agent..."
cargo build

echo ""
echo "🚀 Installing agent..."
echo ""

# Run the install command
# For dev, we need to pass the endpoint through environment
if [ "$ENDPOINT" = "http://localhost:3000" ]; then
    echo "⚠️  Installing with LOCAL endpoint: $ENDPOINT"
    echo "   (This is for development only)"
    echo ""
    # Pass endpoint via environment variable
    sudo CONNLOG_PLATFORM_URL="$ENDPOINT" ./target/debug/connlog-agent --install --token "$TOKEN"
else
    echo "Installing with production endpoint: https://connlog.com"
    echo ""
    sudo ./target/debug/connlog-agent --install --token "$TOKEN"
fi

echo ""
echo "✅ Agent installed successfully!"
echo ""
echo "📊 Check status:"
echo "  sudo systemctl status connlog-agent"
echo ""
echo "📝 View logs:"
echo "  sudo journalctl -u connlog-agent -f"
echo ""
echo "🛑 Stop agent:"
echo "  sudo systemctl stop connlog-agent"
echo ""
echo "🔄 Restart agent:"
echo "  sudo systemctl restart connlog-agent"
echo ""
