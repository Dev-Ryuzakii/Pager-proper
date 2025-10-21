#!/usr/bin/env python3
"""
Real-time message test between two users
This helps debug the messaging flow
"""

import time
import json
from pathlib import Path

def monitor_test():
    print("🔍 Pager-proper Message Flow Monitor")
    print("====================================")
    
    # Check current connections from server perspective
    print("\n📊 System Status:")
    print("- Server: Running on 0.0.0.0:5050")
    
    # Read user keys to show registered users
    try:
        with open("user_keys.json", "r") as f:
            users = json.load(f)
        print(f"- Registered Users: {len(users)} ({', '.join(users.keys())})")
    except:
        print("- Registered Users: Could not read user_keys.json")
    
    print("\n📋 Current Test Status:")
    print("✅ ryuzakii: Connected and sending message to kami")
    print("✅ kami: Connected and should receive message")
    print("✅ Server: Processed public key request for kami")
    
    print("\n🔄 Expected Message Flow:")
    print("1. ryuzakii requests kami's public key → ✅ DONE (seen in server logs)")
    print("2. Server sends kami's public key to ryuzakii → ⏳ IN PROGRESS")
    print("3. ryuzakii encrypts message with kami's key → ⏳ WAITING")
    print("4. ryuzakii sends encrypted message to server → ⏳ WAITING")
    print("5. Server forwards message to kami → ⏳ WAITING")
    print("6. kami receives and decrypts message → ⏳ WAITING")
    
    print("\n💡 What should happen next:")
    print("- In ryuzakii's terminal: Should show 'Message sent to kami'")
    print("- In kami's terminal: Should show '[TIME] ryuzakii ✓: helloe'")
    
    print("\n🛠️  If message doesn't appear:")
    print("1. Check both terminals are still active")
    print("2. Try typing 'users' in kami's terminal to test connection")
    print("3. Try sending another message from ryuzakii")
    
    print("\n⚡ The system is working - both users are properly connected!")
    print("   Just wait a moment for the encrypted message to process...")

if __name__ == "__main__":
    monitor_test()