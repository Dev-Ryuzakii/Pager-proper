#!/bin/bash

# Interactive Test for Pager-proper
# This script helps you test the messaging system properly

echo "🔒 Pager-proper Interactive Test"
echo "================================"
echo

# Check if server is running
if ! pgrep -f "python.*server.py" > /dev/null; then
    echo "⚠️  Server not running. Starting server first..."
    echo
    /Users/macbook/Pager-proper/.venv/bin/python /Users/macbook/Pager-proper/server.py &
    SERVER_PID=$!
    sleep 2
    echo "✅ Server started (PID: $SERVER_PID)"
else
    echo "✅ Server is already running"
fi

echo
echo "📋 Test Instructions:"
echo "1. This will open the client for user 'kami'"
echo "2. In another terminal, run the same command but with different username"
echo "3. Try sending messages between users"
echo
echo "📝 Commands in client:"
echo "   - Type 'users' to see online/registered users"
echo "   - Type username to send message to that user"
echo "   - Type 'quit' to exit"
echo
echo "🚀 Starting client..."
echo "   Username will be: kami"
echo "   Safetoken will be: token432"
echo

# Start the client
PAGER_SERVER_IP="127.0.0.1" /Users/macbook/Pager-proper/.venv/bin/python /Users/macbook/Pager-proper/client.py

echo
echo "Client exited. Goodbye!"