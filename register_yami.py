#!/usr/bin/env python3
"""
Register Yami User - Add yami to the server's user database
"""

import json
import os
import time
from Crypto.PublicKey import RSA

def register_yami_user():
    """Register the yami user in the server's user database"""
    print("🔧 Registering yami user...")
    
    # Load existing user database
    try:
        with open('user_keys_secure.json', 'r') as f:
            data = json.load(f)
    except:
        print("❌ Could not load user database")
        return False
    
    # Check if yami already exists
    if 'yami' in data['users']:
        print("✅ Yami is already registered")
        return True
    
    # Load yami's public key from private key file
    try:
        with open('auth/private_keys/yami_user_private_key.pem', 'rb') as f:
            private_key = RSA.import_key(f.read())
        
        public_key = private_key.publickey()
        public_key_pem = public_key.export_key().decode()
        
        print("✅ Loaded yami's RSA keys")
        
    except Exception as e:
        print(f"❌ Could not load yami's private key: {e}")
        return False
    
    # Add yami to the database
    data['users']['yami'] = {
        "public_key": public_key_pem,
        "token": "token123",  # Using same token as requested
        "registered": time.time(),
        "registration_ip": "127.0.0.1"
    }
    
    # Update timestamp
    data['last_updated'] = time.time()
    
    # Save the updated database
    try:
        with open('user_keys_secure.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        print("✅ Yami successfully registered!")
        print("   Username: yami")
        print("   Token: token123")
        print("   Public key registered")
        return True
        
    except Exception as e:
        print(f"❌ Could not save user database: {e}")
        return False

if __name__ == "__main__":
    register_yami_user()