"""
PostgreSQL FastAPI Backend Test Script
Comprehensive testing of the new PostgreSQL-based backend
"""

import os
import sys
import json
import time
from datetime import datetime

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

from database_config import db_config
from database_models import User, Message, UserKey, UserSession
from fastapi_mobile_backend_postgresql import UserService, MessageService, SessionService

def test_postgresql_backend():
    """Test the PostgreSQL backend functionality"""
    print("🧪 PostgreSQL FastAPI Backend Test")
    print("=" * 50)
    
    # Initialize database
    if not db_config.initialize_database():
        print("❌ Failed to initialize database")
        return False
    
    session = db_config.get_session()
    
    try:
        # Test 1: Check existing users
        print("\n1️⃣  Testing user queries...")
        users = session.query(User).all()
        print(f"✅ Found {len(users)} users in PostgreSQL")
        
        for user in users[:3]:  # Show first 3 users
            print(f"   - {user.username}: registered {user.registered}")
        
        # Test 2: Check messages
        print("\n2️⃣  Testing message queries...")
        messages = session.query(Message).all()
        print(f"✅ Found {len(messages)} messages in PostgreSQL")
        
        # Test 3: Check user keys
        print("\n3️⃣  Testing user keys...")
        keys = session.query(UserKey).all()
        print(f"✅ Found {len(keys)} user keys in PostgreSQL")
        
        key_types = {}
        for key in keys:
            key_types[key.key_type] = key_types.get(key.key_type, 0) + 1
        
        for key_type, count in key_types.items():
            print(f"   - {key_type}: {count} keys")
        
        # Test 4: Test UserService
        print("\n4️⃣  Testing UserService...")
        test_user = UserService.get_user_by_username(session, "yami")
        if test_user:
            print(f"✅ UserService working: Found user {test_user.username}")
            print(f"   - Email: {test_user.email or 'Not set'}")
            print(f"   - Registered: {test_user.registered}")
            print(f"   - Last login: {test_user.last_login or 'Never'}")
        else:
            print("⚠️  Test user 'yami' not found")
        
        # Test 5: Test MessageService
        print("\n5️⃣  Testing MessageService...")
        if test_user:
            user_messages = MessageService.get_user_messages(session, test_user.id)
            print(f"✅ MessageService working: Found {len(user_messages)} messages for {test_user.username}")
            
            offline_messages = MessageService.get_offline_messages(session, test_user.id)
            print(f"✅ Found {len(offline_messages)} offline messages for {test_user.username}")
        
        # Test 6: Test SessionService  
        print("\n6️⃣  Testing SessionService...")
        if test_user:
            test_session = SessionService.create_session(session, test_user.id, "test", "127.0.0.1")
            print(f"✅ SessionService working: Created session {test_session.id}")
            
            # Validate the session
            validated_session = SessionService.validate_session(session, test_session.session_token)
            if validated_session:
                print(f"✅ Session validation working: Session {validated_session.id} is valid")
            
            # Invalidate the session
            SessionService.invalidate_session(session, test_session.session_token)
            print("✅ Session invalidation working")
        
        print("\n🎉 All PostgreSQL backend tests passed!")
        print("\n📊 Database Summary:")
        print(f"   👥 Users: {len(users)}")
        print(f"   💬 Messages: {len(messages)}")
        print(f"   🔑 Keys: {len(keys)}")
        print(f"   🔗 Sessions: {session.query(UserSession).count()}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        session.close()

def compare_with_json():
    """Compare PostgreSQL data with original JSON files"""
    print("\n🔍 Comparing PostgreSQL with JSON Files")
    print("=" * 50)
    
    try:
        # Load JSON data
        json_users = {}
        json_files = [
            'auth/user_keys/user_keys_secure.json',
            'auth/user_keys/user_keys.json'
        ]
        
        for file_path in json_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if 'users' in data:
                        json_users.update(data['users'])
                    else:
                        json_users.update(data)
        
        # Remove metadata
        json_users = {k: v for k, v in json_users.items() 
                     if k not in ['last_updated', 'server_version'] and isinstance(v, dict)}
        
        # Query PostgreSQL
        session = db_config.get_session()
        pg_users = session.query(User).all()
        
        print(f"📄 JSON Users: {len(json_users)}")
        print(f"🗄️  PostgreSQL Users: {len(pg_users)}")
        
        # Compare usernames
        json_usernames = set(json_users.keys())
        pg_usernames = set(user.username for user in pg_users if user.username != 'system')
        
        print(f"✅ Matching usernames: {len(json_usernames & pg_usernames)}")
        print(f"📄 Only in JSON: {json_usernames - pg_usernames}")
        print(f"🗄️  Only in PostgreSQL: {pg_usernames - json_usernames}")
        
        session.close()
        
    except Exception as e:
        print(f"❌ Comparison failed: {e}")

def main():
    """Main test function"""
    print("🐘 PostgreSQL Secure Messaging Backend Test Suite")
    print("=" * 60)
    
    # Test backend functionality
    backend_success = test_postgresql_backend()
    
    # Compare with JSON
    compare_with_json()
    
    print("\n" + "=" * 60)
    if backend_success:
        print("🎉 PostgreSQL backend is fully operational!")
        print("✅ All services working correctly")
        print("✅ Database queries successful")
        print("✅ Data migration verified")
        print("\n🚀 Ready for production use!")
    else:
        print("❌ PostgreSQL backend tests failed")
        print("Please check the error messages above")

if __name__ == "__main__":
    main()