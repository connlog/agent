#!/bin/bash
set -e

echo "🗑️  ConnLog Agent - Development Uninstall"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root"
    echo "Please run: sudo ./dev-uninstall.sh"
    exit 1
fi

echo "🛑 Stopping agent service..."
systemctl stop connlog-agent 2>/dev/null || echo "  (service not running)"

echo "🔌 Disabling agent service..."
systemctl disable connlog-agent 2>/dev/null || echo "  (service not enabled)"

echo "📄 Removing systemd service file..."
rm -f /etc/systemd/system/connlog-agent.service

echo "🔄 Reloading systemd..."
systemctl daemon-reload

echo "🗑️  Removing binary..."
rm -f /usr/local/bin/connlog-agent

echo "📁 Removing config directory..."
rm -rf /etc/connlog

echo "👤 Removing system user..."
userdel connlog-agent 2>/dev/null || echo "  (user not found)"

echo ""
echo "✅ Agent uninstalled successfully!"
echo ""
