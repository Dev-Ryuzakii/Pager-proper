#!/usr/bin/env python3
"""
Key Resync Tool - Fix RSA key mismatches between server and client
"""

import json
import os
from Crypto.PublicKey import RSA

def load_user_keys():
    """Load the user keys from server storage"""
    try:
        with open('user_keys_secure.json', 'r') as f:
            return json.load(f)
    except:
        return {}

def save_user_keys(data):
    """Save user keys to server storage"""
    with open('user_keys_secure.json', 'w') as f:
        json.dump(data, f, indent=2)

def resync_user_keys():
    """Resync server public keys with actual private key files"""
    print("🔄 RSA Key Resync Tool")
    print("=" * 30)
    
    # Load server data
    server_data = load_user_keys()
    if 'users' not in server_data:
        print("❌ No users in server data")
        return
    
    users = server_data['users']
    updated_users = []
    
    # Check each user
    for username in list(users.keys()):
        if not isinstance(users[username], dict):
            continue
            
        print(f"\n🔍 Checking {username}:")
        
        # Load private key file
        key_file = f"auth/private_keys/{username}_user_private_key.pem"
        if not os.path.exists(key_file):
            print(f"   ❌ No private key file: {key_file}")
            continue
            
        try:
            # Load private key
            with open(key_file, 'rb') as f:
                private_key = RSA.import_key(f.read())
            
            # Get corresponding public key
            public_key = private_key.publickey()
            public_key_pem = public_key.export_key().decode()
            
            # Check if server has different key
            server_public_key_pem = users[username].get('public_key', '')
            
            if server_public_key_pem:
                server_public_key = RSA.import_key(server_public_key_pem)
                
                if server_public_key.n == public_key.n:
                    print(f"   ✅ Keys already match")
                else:
                    print(f"   🔄 Keys mismatch - updating server")
                    users[username]['public_key'] = public_key_pem
                    updated_users.append(username)
            else:
                print(f"   ➕ No server public key - adding")
                users[username]['public_key'] = public_key_pem
                updated_users.append(username)
                
        except Exception as e:
            print(f"   ❌ Error processing {username}: {e}")
    
    # Save if any updates
    if updated_users:
        server_data['last_updated'] = __import__('time').time()
        save_user_keys(server_data)
        print(f"\n✅ Updated keys for: {', '.join(updated_users)}")
        print("🔄 Server keys resynced successfully!")
    else:
        print("\n✅ All keys already in sync")

if __name__ == "__main__":
    resync_user_keys()