#!/bin/bash

# Client launcher for Pager-proper
# Automatically detects and suggests server IPs

echo "=== Pager-proper Client Launcher ==="
echo

# Get local IP
LOCAL_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)

echo "🔍 Available server options:"
echo "1) This laptop (localhost): 127.0.0.1"
echo "2) This laptop from network: $LOCAL_IP"
echo "3) Remote server (enter custom IP/domain)"
echo

read -p "Choose server (1-3) or press Enter for localhost: " choice

case $choice in
    1|"")
        SERVER_IP="127.0.0.1"
        ;;
    2)
        SERVER_IP="$LOCAL_IP"
        ;;
    3)
        read -p "Enter server IP or domain: " SERVER_IP
        ;;
    *)
        echo "Invalid choice, using localhost"
        SERVER_IP="127.0.0.1"
        ;;
esac

echo
echo "🚀 Connecting to server at: $SERVER_IP"
echo "🔐 Starting secure messenger client..."
echo

# Set environment variable and start client
export PAGER_SERVER_IP="$SERVER_IP"
/Users/macbook/Pager-proper/.venv/bin/python client.py