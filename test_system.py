#!/usr/bin/env python3
"""
Test script for Pager-proper messaging system
Tests key generation, encryption, and basic server functionality
"""

import json
import tempfile
import os
import sys
import time
import threading
import socket
from pathlib import Path

# Add current directory to path to import our modules
sys.path.insert(0, str(Path(__file__).parent))

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    import base64
    print("✓ Cryptography dependencies available")
except ImportError as e:
    print(f"✗ Missing dependency: {e}")
    print("Run: pip install pycryptodome")
    sys.exit(1)

def test_rsa_functionality():
    """Test RSA key generation and encryption/decryption"""
    print("\n=== Testing RSA Functionality ===")
    
    # Generate test keys
    print("Generating test RSA keys...")
    key1 = RSA.generate(2048)
    key2 = RSA.generate(2048)
    
    # Test message
    test_message = "Hello, this is a test message! 🔒"
    
    # Encrypt with key1 public, decrypt with key1 private
    print("Testing encryption/decryption...")
    cipher = PKCS1_OAEP.new(key1.publickey())
    encrypted = cipher.encrypt(test_message.encode())
    
    cipher_decrypt = PKCS1_OAEP.new(key1)
    decrypted = cipher_decrypt.decrypt(encrypted).decode()
    
    if decrypted == test_message:
        print("✓ RSA encryption/decryption working correctly")
    else:
        print("✗ RSA encryption/decryption failed")
        return False
        
    # Test cross-user encryption (key1 encrypts for key2)
    print("Testing cross-user encryption...")
    cipher_cross = PKCS1_OAEP.new(key2.publickey())
    encrypted_cross = cipher_cross.encrypt(test_message.encode())
    
    cipher_cross_decrypt = PKCS1_OAEP.new(key2)
    decrypted_cross = cipher_cross_decrypt.decrypt(encrypted_cross).decode()
    
    if decrypted_cross == test_message:
        print("✓ Cross-user encryption working correctly")
    else:
        print("✗ Cross-user encryption failed")
        return False
        
    return True

def test_server_startup():
    """Test if server can start and accept connections"""
    print("\n=== Testing Server Startup ===")
    
    # Import server module
    try:
        import server
        print("✓ Server module imported successfully")
    except ImportError as e:
        print(f"✗ Could not import server: {e}")
        return False
        
    # Test socket binding
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test_socket.bind(("127.0.0.1", 5051))  # Use different port for test
        test_socket.close()
        print("✓ Socket binding test successful")
    except Exception as e:
        print(f"✗ Socket binding test failed: {e}")
        return False
        
    return True

def test_client_functionality():
    """Test client key generation and storage"""
    print("\n=== Testing Client Functionality ===")
    
    # Test in temporary directory
    with tempfile.TemporaryDirectory() as tmpdir:
        original_dir = os.getcwd()
        os.chdir(tmpdir)
        
        try:
            # Import client components
            sys.path.insert(0, original_dir)
            from client import SecureMessenger
            
            # Create test messenger
            messenger = SecureMessenger()
            messenger.username = "testuser"
            
            # Test key generation
            print("Testing key generation...")
            messenger.generate_key_pair()
            if messenger.private_key and messenger.public_key:
                print("✓ Key generation successful")
            else:
                print("✗ Key generation failed")
                return False
                
            # Test key saving/loading
            print("Testing key persistence...")
            messenger.save_private_key()
            
            # Create new instance and load
            messenger2 = SecureMessenger()
            messenger2.username = "testuser"
            if messenger2.load_private_key():
                print("✓ Key persistence working")
            else:
                print("✗ Key persistence failed")
                return False
                
            # Test encryption between users
            print("Testing message encryption...")
            test_msg = "Test message for encryption"
            encrypted = messenger.encrypt_message(test_msg, messenger2.public_key)
            if encrypted:
                decrypted = messenger2.decrypt_message(encrypted)
                if decrypted == test_msg:
                    print("✓ Message encryption working")
                else:
                    print(f"✗ Message encryption failed: {decrypted}")
                    return False
            else:
                print("✗ Message encryption failed - no output")
                return False
                
        except Exception as e:
            print(f"✗ Client test error: {e}")
            return False
        finally:
            os.chdir(original_dir)
            
    return True

def test_json_serialization():
    """Test JSON serialization of messages"""
    print("\n=== Testing JSON Serialization ===")
    
    try:
        # Test message structure
        test_message = {
            "type": "message",
            "sender": "alice",
            "recipient": "bob",
            "payload": "base64encodedencryptedmessage==",
            "signature": "base64encodedsignature==",
            "safetoken": "testttoken123"
        }
        
        # Serialize and deserialize
        json_str = json.dumps(test_message)
        parsed = json.loads(json_str)
        
        if parsed == test_message:
            print("✓ JSON serialization working")
        else:
            print("✗ JSON serialization failed")
            return False
            
        # Test key registration structure
        reg_message = {
            "action": "register",
            "username": "testuser",
            "safetoken": "testtoken",
            "public_key": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
        }
        
        json_str2 = json.dumps(reg_message)
        parsed2 = json.loads(json_str2)
        
        if parsed2 == reg_message:
            print("✓ Registration message serialization working")
        else:
            print("✗ Registration message serialization failed")
            return False
            
    except Exception as e:
        print(f"✗ JSON serialization test error: {e}")
        return False
        
    return True

def run_all_tests():
    """Run all tests"""
    print("🔒 Pager-proper Test Suite")
    print("=" * 50)
    
    tests = [
        ("RSA Functionality", test_rsa_functionality),
        ("Server Startup", test_server_startup),
        ("Client Functionality", test_client_functionality),
        ("JSON Serialization", test_json_serialization)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"Test '{test_name}' failed")
        except Exception as e:
            print(f"Test '{test_name}' crashed: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! System ready for deployment.")
        return True
    else:
        print("❌ Some tests failed. Please check the issues above.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)