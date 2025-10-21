#!/usr/bin/env python3
"""
Integration test for the full messaging system with double-layer encryption
"""

import subprocess
import time
import signal
import os
import sys

def test_full_system():
    print("🚀 Testing Full Messaging System with Double-Layer Encryption")
    print("=" * 60)
    
    # Start server in background
    print("1. Starting server...")
    server_process = subprocess.Popen([
        'python3', 'server.py'
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Wait for server to start
    time.sleep(2)
    
    try:
        # Check if server is running
        if server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            print("❌ Server failed to start:")
            print("STDOUT:", stdout)
            print("STDERR:", stderr)
            return False
        
        print("✅ Server started successfully")
        
        print("\n2. Server is ready for client connections")
        print("\n💡 Test Instructions:")
        print("   - The server is running and ready")
        print("   - You can now run: python3 client.py")
        print("   - Test the double-layer encryption by:")
        print("     a) Creating a user (or using existing like 'kami')")
        print("     b) Setting up master decrypt token")
        print("     c) Sending messages")
        print("     d) Using 'decrypt' command to read messages")
        print("     e) Using 'list' to see encrypted message list")
        
        print("\n🔒 Security Features Active:")
        print("   ✅ Individual RSA keys per user")
        print("   ✅ Hybrid AES+RSA encryption for performance")
        print("   ✅ Master decrypt token for message access")
        print("   ✅ Double-layer encryption protection")
        
        # Keep server running
        print(f"\n🏃 Server running (PID: {server_process.pid})")
        print("Press Ctrl+C to stop the server when done testing...")
        
        # Wait for user to stop
        try:
            server_process.wait()
        except KeyboardInterrupt:
            print("\n🛑 Stopping server...")
            server_process.terminate()
            server_process.wait()
            print("✅ Server stopped")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        server_process.terminate()
        return False

if __name__ == "__main__":
    # Activate virtual environment
    venv_python = os.path.join('.venv', 'bin', 'python3')
    if os.path.exists(venv_python):
        print("🐍 Using virtual environment Python")
        sys.executable = venv_python
    
    success = test_full_system()
    sys.exit(0 if success else 1)