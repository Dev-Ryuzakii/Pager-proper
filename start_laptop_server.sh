#!/bin/bash

# Laptop Server Setup for Pager-proper
# Run this to use your laptop as the messaging server

echo "=== Pager-proper Laptop Server Setup ==="
echo

# Get local IP
LOCAL_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)

echo "📍 Your laptop's IP addresses:"
echo "   Local network: $LOCAL_IP"
echo "   Localhost: 127.0.0.1"
echo

# Check if port 5050 is available
if lsof -Pi :5050 -sTCP:LISTEN -t >/dev/null ; then
    echo "⚠️  Port 5050 is already in use. Stopping existing process..."
    pkill -f "python.*server.py" 2>/dev/null || true
    sleep 2
fi

echo "🔧 Starting server on your laptop..."
echo

# Option selection
echo "Choose connection type:"
echo "1) Local only (127.0.0.1) - Only this laptop can connect"
echo "2) Local network ($LOCAL_IP) - Other devices on WiFi can connect"
echo "3) All interfaces (0.0.0.0) - Maximum compatibility"
echo

read -p "Enter choice (1-3): " choice

case $choice in
    1)
        echo "Starting server for localhost only..."
        sed -i.bak 's/HOST = "0.0.0.0"/HOST = "127.0.0.1"/' server.py
        ;;
    2)
        echo "Starting server for local network access..."
        sed -i.bak 's/HOST = "0.0.0.0"/HOST = "0.0.0.0"/' server.py
        ;;
    3)
        echo "Starting server for all interfaces..."
        sed -i.bak 's/HOST = "127.0.0.1"/HOST = "0.0.0.0"/' server.py
        ;;
    *)
        echo "Invalid choice, using default (all interfaces)"
        ;;
esac

echo
echo "🚀 Starting Pager-proper server..."
echo "📱 Connection info for clients:"
echo "   Same laptop: 127.0.0.1"
echo "   Other devices on WiFi: $LOCAL_IP"
echo
echo "Press Ctrl+C to stop the server"
echo "=" * 50

# Start the server
/Users/macbook/Pager-proper/.venv/bin/python server.py