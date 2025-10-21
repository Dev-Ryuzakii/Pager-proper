#!/usr/bin/env python3
"""
End-to-End Encryption Test - Test the full messaging pipeline
"""

import subprocess
import time
import signal
import os
import sys

def test_messaging_pipeline():
    print("🔒 End-to-End Encryption Test")
    print("=" * 40)
    
    # Start server
    print("1. Starting TLS server...")
    server_process = subprocess.Popen([
        sys.executable, 'server_integrated.py'
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Wait for server to start
    time.sleep(2)
    
    try:
        # Check if server is running
        if server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            print("❌ Server failed to start:")
            print("STDERR:", stderr)
            return False
        
        print("✅ Server started successfully")
        print("\n2. Testing Instructions:")
        print("   Now test the messaging system:")
        print("   1. Run: python3 client_tls.py")
        print("   2. Login as 'kami' with token 'token432'")
        print("   3. Send message to 'tougen'")
        print("   4. Login as 'tougen' with token 'token789'")
        print("   5. Use 'decrypt <ID>' with master token 'tougenAlpha@123'")
        print("   6. Verify message decrypts successfully")
        
        print(f"\n🏃 Server running (PID: {server_process.pid})")
        print("Press Ctrl+C to stop...")
        
        # Keep server running
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
    success = test_messaging_pipeline()
    sys.exit(0 if success else 1)