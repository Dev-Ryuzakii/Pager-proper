#!/usr/bin/env python3
"""
RSA Debug Test - Diagnose exact RSA encryption/decryption issues
"""

import json
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def load_user_keys():
    """Load the user keys from server storage"""
    try:
        with open('user_keys_secure.json', 'r') as f:
            data = json.load(f)
            return data.get('users', {})
    except:
        return {}

def load_private_key(username):
    """Load user's private RSA key"""
    key_file = f"auth/private_keys/{username}_user_private_key.pem"
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return RSA.import_key(f.read())
    return None

def test_rsa_encryption():
    """Test RSA encryption/decryption with actual keys"""
    print("🔍 RSA Encryption/Decryption Debug Test")
    print("=" * 50)
    
    # Load server's user keys
    user_keys = load_user_keys()
    print(f"📂 Loaded user keys for: {list(user_keys.keys())}")
    
    for username in ['kami', 'tougen']:
        if username not in user_keys:
            print(f"❌ No server keys for {username}")
            continue
            
        print(f"\n🔍 Testing {username}:")
        
        # Get public key from server storage
        server_public_key_pem = user_keys[username].get('public_key')
        if not server_public_key_pem:
            print(f"❌ No public key in server storage for {username}")
            continue
            
        # Load private key from file
        private_key = load_private_key(username)
        if not private_key:
            print(f"❌ No private key file for {username}")
            continue
            
        try:
            # Parse server public key
            server_public_key = RSA.import_key(server_public_key_pem)
            print(f"✅ Server public key loaded: {server_public_key.size_in_bits()} bits")
            
            # Compare keys
            private_public = private_key.publickey()
            print(f"✅ Private key loaded: {private_key.size_in_bits()} bits")
            
            # Check if keys match
            if server_public_key.n == private_public.n:
                print("✅ Keys match! Public key corresponds to private key")
            else:
                print("❌ KEY MISMATCH! Server public key doesn't match private key")
                print(f"   Server public key n: {hex(server_public_key.n)[:50]}...")
                print(f"   Private key public n: {hex(private_public.n)[:50]}...")
                continue
            
            # Test encryption/decryption
            test_data = b"test_aes_key_32_bytes_long_12345"
            
            # Encrypt with server's public key (what sender does)
            cipher_rsa = PKCS1_OAEP.new(server_public_key)
            encrypted = cipher_rsa.encrypt(test_data)
            print(f"✅ Encrypted {len(test_data)} bytes -> {len(encrypted)} bytes")
            
            # Decrypt with private key (what receiver does)
            decipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted = decipher_rsa.decrypt(encrypted)
            print(f"✅ Decrypted {len(encrypted)} bytes -> {len(decrypted)} bytes")
            
            if decrypted == test_data:
                print("✅ RSA round-trip successful!")
            else:
                print("❌ RSA round-trip failed - data mismatch")
                
        except Exception as e:
            print(f"❌ RSA test failed: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n🔍 Key Storage Analysis:")
    print("-" * 30)
    
    for username in user_keys:
        user_data = user_keys[username]
        if isinstance(user_data, dict):
            print(f"\n👤 {username}:")
            print(f"   Has public_key: {'public_key' in user_data}")
            print(f"   Has token: {'token' in user_data}")
            print(f"   Last login: {user_data.get('last_login', 'Never')}")
            
            if 'public_key' in user_data:
                try:
                    key = RSA.import_key(user_data['public_key'])
                    print(f"   Public key bits: {key.size_in_bits()}")
                    print(f"   Key fingerprint: {hex(key.n)[:20]}...")
                except Exception as e:
                    print(f"   Public key error: {e}")

if __name__ == "__main__":
    test_rsa_encryption()