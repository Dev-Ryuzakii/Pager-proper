#!/usr/bin/env python3
"""
Test the double-layer encryption system
"""

import sys
sys.path.insert(0, '.')

from client import SecureMessenger
import tempfile
import os

def test_double_layer_encryption():
    print("🔒 Testing Double-Layer Encryption System")
    print("=" * 50)
    
    # Create test messenger
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chdir(tmpdir)
        
        messenger = SecureMessenger()
        messenger.username = "testuser"
        messenger.generate_key_pair()
        messenger.setup_master_decrypt_token()
        
        # Test message and master token
        test_message = "This is a secret military message!"
        master_token = "SecretPassword123!"
        
        print(f"Original message: {test_message}")
        print(f"Master token: {master_token}")
        print()
        
        # Test double-layer encryption
        print("1. Testing double-layer encryption...")
        encrypted = messenger.encrypt_message(test_message, messenger.public_key, master_token)
        
        if encrypted:
            print("✅ Double-layer encryption successful")
            print(f"Encrypted size: {len(encrypted)} characters")
        else:
            print("❌ Double-layer encryption failed")
            return False
        
        # Test decryption with correct master token
        print("\n2. Testing decryption with correct master token...")
        decrypted_correct = messenger.decrypt_message(encrypted, master_token)
        
        if decrypted_correct == test_message:
            print("✅ Decryption with correct master token successful")
        else:
            print(f"❌ Decryption failed: {decrypted_correct}")
            return False
        
        # Test decryption with wrong master token
        print("\n3. Testing decryption with wrong master token...")
        decrypted_wrong = messenger.decrypt_message(encrypted, "WrongPassword!")
        
        if decrypted_wrong.startswith("["):
            print("✅ Wrong master token properly rejected")
            print(f"Result: {decrypted_wrong}")
        else:
            print("❌ Wrong master token was accepted (security issue!)")
            return False
        
        # Test decryption without master token
        print("\n4. Testing decryption without master token...")
        decrypted_none = messenger.decrypt_message(encrypted, None)
        
        if decrypted_none.startswith("["):
            print("✅ Missing master token properly handled")
            print(f"Result: {decrypted_none}")
        else:
            print("❌ Missing master token was accepted (security issue!)")
            return False
        
        print("\n🎉 All double-layer encryption tests passed!")
        print("\n💡 Security Features Verified:")
        print("✅ Messages encrypted with master token + RSA/AES")
        print("✅ Wrong master token rejected")
        print("✅ Missing master token handled")
        print("✅ Only correct master token reveals message")
        
        return True

if __name__ == "__main__":
    success = test_double_layer_encryption()
    sys.exit(0 if success else 1)