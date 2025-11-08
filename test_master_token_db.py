#!/usr/bin/env python3
"""
Test script for master token database functions
"""

import sys
import os

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_database_functions():
    """Test the database functions for master token storage and validation"""
    try:
        # Import the database utilities
        from tls_database_utils import store_master_token, validate_master_token, DATABASE_AVAILABLE
        
        if not DATABASE_AVAILABLE:
            print("❌ Database not available. Skipping tests.")
            return False
        
        print("✅ Database functions imported successfully")
        
        # Test storing a master token
        test_username = "testuser_db"
        test_token = "TestToken123!@#"
        
        print(f"🔧 Testing master token storage for user: {test_username}")
        store_result = store_master_token(test_username, test_token)
        
        if store_result:
            print("✅ Master token stored successfully")
        else:
            print("❌ Failed to store master token")
            return False
        
        # Test validating the correct master token
        print(f"🔧 Testing master token validation for user: {test_username}")
        validate_result = validate_master_token(test_username, test_token)
        
        if validate_result:
            print("✅ Master token validated successfully")
        else:
            print("❌ Failed to validate master token")
            return False
        
        # Test validating an incorrect master token
        print(f"🔧 Testing master token validation with incorrect token for user: {test_username}")
        invalid_validate_result = validate_master_token(test_username, "WrongToken123")
        
        if not invalid_validate_result:
            print("✅ Invalid master token correctly rejected")
        else:
            print("❌ Invalid master token was incorrectly accepted")
            return False
        
        print("🎉 All database function tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Testing Master Token Database Functions")
    print("=" * 50)
    
    success = test_database_functions()
    
    if success:
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)