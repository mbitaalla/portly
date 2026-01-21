#!/bin/bash
# Portly Server Installation Script
# Run this on your VPS as root

set -e

echo "======================================"
echo "  Portly Server Installation"
echo "======================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Update system
echo "[1/8] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install dependencies
echo "[2/8] Installing dependencies..."
apt-get install -y \
    python3 \
    python3-pip \
    wireguard \
    iptables \
    iptables-persistent \
    nginx \
    certbot \
    python3-certbot-nginx \
    curl \
    git

# Install Python packages
echo "[3/8] Installing Python packages..."
pip3 install flask flask-cors gunicorn

# Create application directory
echo "[4/8] Setting up application directory..."
mkdir -p /opt/portly
cd /opt/portly

# Download or copy the application file
cat > /opt/portly/app.py << 'EOFAPP'
# The app.py content goes here - copy from the artifact above
EOFAPP

# Create systemd service
echo "[5/8] Creating systemd service..."
cat > /etc/systemd/system/portly.service << 'EOF'
[Unit]
Description=Portly Port Forwarding Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/portly
ExecStart=/usr/local/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Setup WireGuard
echo "[6/8] Configuring WireGuard..."

# Generate server keys
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

# Create WireGuard config
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 192.169.66.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Configure Nginx
echo "[7/8] Configuring Nginx..."
cat > /etc/nginx/sites-available/portly << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

ln -sf /etc/nginx/sites-available/portly /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configure firewall
echo "[8/8] Configuring firewall..."
ufw --force enable
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 51820/udp
ufw allow 10000:60000/tcp
ufw allow 10000:60000/udp

# Start services
systemctl restart nginx
systemctl enable portly
systemctl start portly

echo ""
echo "======================================"
echo "  Installation Complete!"
echo "======================================"
echo ""
echo "Server Public Key: $PUBLIC_KEY"
echo ""
echo "Next steps:"
echo "1. Note your server's public IP address"
echo "2. (Optional) Set up a domain and run: certbot --nginx -d yourdomain.com"
echo "3. Create your first user:"
echo "   curl -X POST http://localhost:5000/api/register -H 'Content-Type: application/json' -d '{\"username\":\"admin\"}'"
echo ""
echo "Check service status:"
echo "  systemctl status portly"
echo "  systemctl status wg-quick@wg0"
echo ""
echo "View logs:"
echo "  journalctl -u portly -f"
echo ""