#!/bin/bash

# Simple test script for Pager-proper
# This script will help you test the system step by step

echo "🔒 Pager-proper Manual Test Guide"
echo "================================="
echo
echo "Current status:"
echo "✅ Server should be running on localhost:5050"
echo "✅ Dependencies installed (pycryptodome)"
echo

echo "📋 Testing Instructions:"
echo
echo "1️⃣  FIRST USER TEST:"
echo "   Open a new terminal and run:"
echo "   cd /Users/macbook/Pager-proper"
echo "   PAGER_SERVER_IP=\"127.0.0.1\" /Users/macbook/Pager-proper/.venv/bin/python client.py"
echo "   - Enter username: alice"
echo "   - Enter safetoken: alice123"
echo "   - Should see 'Ready to send messages!'"
echo

echo "2️⃣  SECOND USER TEST:"
echo "   Open another terminal and run:"
echo "   cd /Users/macbook/Pager-proper"
echo "   PAGER_SERVER_IP=\"127.0.0.1\" /Users/macbook/Pager-proper/.venv/bin/python client.py"
echo "   - Enter username: bob"
echo "   - Enter safetoken: bob456"
echo "   - Should see 'Ready to send messages!'"
echo

echo "3️⃣  SEND MESSAGE TEST:"
echo "   In Alice's terminal:"
echo "   - Type: bob"
echo "   - Type: Hello Bob, this is Alice!"
echo "   - Should see 'Message sent to bob'"
echo

echo "4️⃣  RECEIVE MESSAGE TEST:"
echo "   In Bob's terminal:"
echo "   - Should automatically receive encrypted message"
echo "   - Message will be decrypted and shown"
echo

echo "5️⃣  LIST USERS TEST:"
echo "   In any client terminal:"
echo "   - Type: users"
echo "   - Should see both alice and bob listed"
echo

echo "🎯 Expected Results:"
echo "   - Alice and Bob can exchange encrypted messages"
echo "   - Each user has unique RSA keys"
echo "   - Messages are encrypted end-to-end"
echo "   - Server logs show connections and messages"
echo

echo "🔧 Quick Commands:"
echo "   Start client: PAGER_SERVER_IP=\"127.0.0.1\" ./venv/bin/python client.py"
echo "   Check server: ps aux | grep server.py"
echo "   Stop server: pkill -f \"python.*server.py\""
echo

echo "Ready to test! Follow steps 1-5 above."
echo "Press Enter to continue, or Ctrl+C to exit..."
read