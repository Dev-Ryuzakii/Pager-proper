#!/usr/bin/env python3
"""
Test script for TLS server modifications
"""

import sys
import os
import json
import hashlib
import base64
from datetime import datetime

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all required modules can be imported"""
    try:
        # Test importing the TLS database utilities
        from tls_database_utils import store_master_token, validate_master_token, DATABASE_AVAILABLE
        print("✅ TLS database utilities imported successfully")
        
        # Test importing the TLS server
        import server_tls
        print("✅ TLS server imported successfully")
        
        return True
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False

def test_master_token_storage():
    """Test master token storage functionality"""
    try:
        from tls_database_utils import store_master_token, validate_master_token, DATABASE_AVAILABLE
        
        if not DATABASE_AVAILABLE:
            print("⚠️  Database not available, skipping storage test")
            return True
        
        # Test data
        username = "test_tls_user"
        token = "TestMasterToken123!"
        
        # Store the master token
        print(f"🔧 Storing master token for user: {username}")
        result = store_master_token(username, token)
        
        if result:
            print("✅ Master token stored successfully")
            
            # Validate the stored token
            print(f"🔧 Validating master token for user: {username}")
            validate_result = validate_master_token(username, token)
            
            if validate_result:
                print("✅ Master token validation successful")
                return True
            else:
                print("❌ Master token validation failed")
                return False
        else:
            print("❌ Failed to store master token")
            return False
            
    except Exception as e:
        print(f"❌ Error in master token storage test: {e}")
        return False

def test_tls_server_functions():
    """Test TLS server functions"""
    try:
        import server_tls
        
        # Test that the database functions are properly imported
        if hasattr(server_tls, 'DATABASE_AVAILABLE'):
            if server_tls.DATABASE_AVAILABLE:
                print("✅ TLS server database integration available")
            else:
                print("⚠️  TLS server database integration not available")
        else:
            print("❌ DATABASE_AVAILABLE flag not found in TLS server")
            return False
        
        # Test that the new decrypt handler exists
        if hasattr(server_tls, 'handle_decrypt_request'):
            print("✅ TLS server decrypt handler found")
        else:
            print("❌ TLS server decrypt handler not found")
            return False
            
        # Test that the message type handler includes decrypt
        # We'll check this by looking at the source code
        import inspect
        source = inspect.getsource(server_tls)
        if '"decrypt"' in source and 'handle_decrypt_request' in source:
            print("✅ TLS server decrypt message type handler found")
        else:
            print("❌ TLS server decrypt message type handler not found")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Error in TLS server test: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 Testing TLS Server Modifications")
    print("=" * 50)
    
    # Test imports
    print("1. Testing imports...")
    if not test_imports():
        return False
    
    # Test master token storage
    print("\n2. Testing master token storage...")
    if not test_master_token_storage():
        return False
    
    # Test TLS server functions
    print("\n3. Testing TLS server functions...")
    if not test_tls_server_functions():
        return False
    
    print("\n🎉 All tests passed!")
    return True

if __name__ == "__main__":
    success = main()
    
    if success:
        print("\n✅ All TLS modification tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some TLS modification tests failed!")
        sys.exit(1)