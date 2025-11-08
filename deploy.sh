#!/bin/bash

# Pager-proper Deployment Script
# This script helps deploy the server to a cloud VPS

echo "=== Pager-proper Deployment Script ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Update system
echo "1. Updating system packages..."
apt update && apt upgrade -y

# Install Python and pip
echo "2. Installing Python and pip..."
apt install -y python3 python3-pip python3-venv git ufw

# Create application directory
echo "3. Setting up application directory..."
mkdir -p /opt/pager-proper
cd /opt/pager-proper

# Copy files (assuming they're in current directory)
echo "4. Copying application files..."
cp server.py /opt/pager-proper/
cp requirements.txt /opt/pager-proper/

# Create virtual environment
echo "5. Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "6. Installing Python dependencies..."
pip install -r requirements.txt

# Configure firewall
echo "7. Configuring firewall..."
ufw allow 22/tcp    # SSH
ufw allow 5050/tcp  # Pager-proper server
ufw --force enable

# Create systemd service
echo "8. Creating systemd service..."
cat > /etc/systemd/system/pager-proper.service << EOF
[Unit]
Description=Pager-proper Secure Messaging Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/pager-proper
Environment=PATH=/opt/pager-proper/venv/bin
ExecStart=/opt/pager-proper/venv/bin/python server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo "9. Starting service..."
systemctl daemon-reload
systemctl enable pager-proper
systemctl start pager-proper

# Display status
echo "10. Deployment complete!"
echo
echo "Service status:"
systemctl status pager-proper --no-pager

echo
echo "Server is now running on port 5050"
echo "Your server IP: $(curl -s ifconfig.me)"
echo
echo "To check logs: journalctl -u pager-proper -f"
echo "To restart: systemctl restart pager-proper"
echo "To stop: systemctl stop pager-proper"
echo
echo "Make sure clients connect to: $(curl -s ifconfig.me):5050"