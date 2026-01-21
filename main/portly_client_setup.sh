#!/bin/bash
# Portly Client Installation Script
# Run this on your home server/homelab machine

set -e

echo "======================================"
echo "  Portly Client Setup"
echo "======================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (or with sudo)" 
   exit 1
fi

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt-get"
    PKG_UPDATE="apt-get update"
    PKG_INSTALL="apt-get install -y"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum update -y"
    PKG_INSTALL="yum install -y"
else
    echo "Unsupported package manager. Please install WireGuard manually."
    exit 1
fi

# Install WireGuard
echo "[1/3] Installing WireGuard..."
$PKG_UPDATE
$PKG_INSTALL wireguard wireguard-tools

# Check if config file is provided
if [ ! -f "portly-client.conf" ]; then
    echo ""
    echo "ERROR: portly-client.conf not found!"
    echo ""
    echo "Please download your WireGuard configuration from the Portly dashboard"
    echo "and place it in the current directory as 'portly-client.conf'"
    echo ""
    echo "Steps:"
    echo "1. Open the Portly dashboard in your browser"
    echo "2. Click 'Download Config'"
    echo "3. Save the file as portly-client.conf"
    echo "4. Copy it to this directory"
    echo "5. Run this script again"
    exit 1
fi

# Install WireGuard config
echo "[2/3] Installing WireGuard configuration..."
cp portly-client.conf /etc/wireguard/portly.conf
chmod 600 /etc/wireguard/portly.conf

# Enable and start WireGuard
echo "[3/3] Starting WireGuard tunnel..."
systemctl enable wg-quick@portly
systemctl start wg-quick@portly

# Check status
echo ""
echo "======================================"
echo "  Installation Complete!"
echo "======================================"
echo ""

if systemctl is-active --quiet wg-quick@portly; then
    echo "✓ WireGuard tunnel is ACTIVE"
    echo ""
    echo "Tunnel status:"
    wg show portly
    echo ""
    echo "Your services are now publicly accessible!"
else
    echo "✗ WireGuard tunnel failed to start"
    echo ""
    echo "Check logs with: journalctl -u wg-quick@portly -n 50"
fi

echo ""
echo "Useful commands:"
echo "  Status:  systemctl status wg-quick@portly"
echo "  Stop:    systemctl stop wg-quick@portly"
echo "  Start:   systemctl start wg-quick@portly"
echo "  Restart: systemctl restart wg-quick@portly"
echo "  Logs:    journalctl -u wg-quick@portly -f"
echo ""