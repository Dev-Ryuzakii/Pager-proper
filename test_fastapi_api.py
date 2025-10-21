#!/usr/bin/env python3
"""
Test FastAPI Mobile Backend - Verify all endpoints work correctly
"""

import asyncio
import httpx
import json
import time

# API base URL
BASE_URL = "http://localhost:8000"

class APITester:
    def __init__(self):
        self.base_url = BASE_URL
        self.session_token = None
        self.user_token = None
        
    async def test_health(self):
        """Test health endpoint"""
        print("🔍 Testing health endpoint...")
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.base_url}/api/v1/health")
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Health check passed")
                print(f"   📊 Users: {data['users_count']}")
                print(f"   📨 Offline messages: {data['offline_messages_count']}")
                return True
            else:
                print(f"   ❌ Health check failed: {response.status_code}")
                return False
    
    async def test_register(self, username="testuser_mobile"):
        """Test user registration"""
        print(f"📝 Testing user registration for {username}...")
        
        # Mock RSA public key for testing
        mock_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8Vzvdd+hnycCxXCwBgm
iesqxhG0SqGlbk0R+H5ORo3Hj7W3MxLmDmYZtiI6r/vqKXrkOT9BJeWnV5tMy735
vMzF1+SC9Dw04wBPPLlFiMw5hIrL6yU1tmNabLhOqx8tBvyAfTKwj9GEx5kkGBKP
lZ6zjkdqfELhXTt0Cs4M8uXgl29B5nWg/rHP5VVy1Gp6XW3UakMzVS0IUzvD8k82
tw45wd1lWHB90vHmPDEPUoRrrsvmoDYXp3ZeJbnXhjAOdpHcrdASJvuB0+xPAh9r
wO4YCbp9CMl/5hhjfE+crJc7kARy2xR/zUpM9OQ8l8LNlRQGhTNwAdOm77nP8mQE
UQIDAQAB
-----END PUBLIC KEY-----"""
        
        registration_data = {
            "username": username,
            "email": f"{username}@example.com",
            "public_key": mock_public_key,
            "device_id": "test_device_123",
            "push_token": "test_push_token"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/auth/register",
                json=registration_data
            )
            
            if response.status_code == 200:
                data = response.json()
                self.user_token = data.get("token")
                print(f"   ✅ Registration successful")
                print(f"   🔑 User token: {self.user_token}")
                return True
            else:
                print(f"   ❌ Registration failed: {response.status_code}")
                print(f"   📄 Response: {response.text}")
                return False
    
    async def test_login(self, username="testuser_mobile"):
        """Test user login"""
        print(f"🔐 Testing user login for {username}...")
        
        if not self.user_token:
            print("   ❌ No user token available. Register first.")
            return False
        
        login_data = {
            "username": username,
            "token": self.user_token,
            "device_info": {
                "device_id": "test_device_123",
                "os_version": "iOS 17.1",
                "app_version": "1.0.0"
            }
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/auth/login",
                json=login_data
            )
            
            if response.status_code == 200:
                data = response.json()
                self.session_token = data.get("session_token")
                print(f"   ✅ Login successful")
                print(f"   🎫 Session token: {self.session_token[:20]}...")
                return True
            else:
                print(f"   ❌ Login failed: {response.status_code}")
                print(f"   📄 Response: {response.text}")
                return False
    
    async def test_get_contacts(self):
        """Test getting contacts list"""
        print("👥 Testing get contacts...")
        
        if not self.session_token:
            print("   ❌ No session token. Login first.")
            return False
        
        headers = {"Authorization": f"Bearer {self.session_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/users/contacts",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                contacts = data.get("contacts", [])
                print(f"   ✅ Retrieved {len(contacts)} contacts")
                for contact in contacts[:3]:  # Show first 3
                    print(f"      👤 {contact['username']} ({contact['status']})")
                return True
            else:
                print(f"   ❌ Get contacts failed: {response.status_code}")
                return False
    
    async def test_send_message(self, recipient="yami"):
        """Test sending a message"""
        print(f"💬 Testing send message to {recipient}...")
        
        if not self.session_token:
            print("   ❌ No session token. Login first.")
            return False
        
        # Mock encrypted message data
        message_data = {
            "recipient_id": recipient,
            "message_type": "hybrid_rsa_aes",
            "encrypted_content": {
                "encrypted_aes_key": "base64_mock_encrypted_aes_key",
                "encrypted_message": "base64_mock_encrypted_message",
                "nonce": "base64_mock_nonce",
                "message_hash": "sha256_mock_hash"
            },
            "metadata": {
                "message_type": "text",
                "timestamp": time.time()
            }
        }
        
        headers = {"Authorization": f"Bearer {self.session_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/messages/send",
                json=message_data,
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Message sent successfully")
                print(f"   📨 Message ID: {data.get('message_id')}")
                print(f"   📋 Status: {data.get('delivery_status')}")
                return True
            else:
                print(f"   ❌ Send message failed: {response.status_code}")
                print(f"   📄 Response: {response.text}")
                return False
    
    async def test_get_messages(self):
        """Test getting inbox messages"""
        print("📥 Testing get messages (inbox)...")
        
        if not self.session_token:
            print("   ❌ No session token. Login first.")
            return False
        
        headers = {"Authorization": f"Bearer {self.session_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/messages/inbox?limit=10",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                messages = data.get("messages", [])
                print(f"   ✅ Retrieved {len(messages)} messages")
                print(f"   📊 Total count: {data.get('total_count', 0)}")
                return True
            else:
                print(f"   ❌ Get messages failed: {response.status_code}")
                return False
    
    async def test_logout(self):
        """Test user logout"""
        print("🚪 Testing logout...")
        
        if not self.session_token:
            print("   ❌ No session token. Login first.")
            return False
        
        headers = {"Authorization": f"Bearer {self.session_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/auth/logout",
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"   ✅ Logout successful")
                self.session_token = None
                return True
            else:
                print(f"   ❌ Logout failed: {response.status_code}")
                return False

async def run_comprehensive_test():
    """Run all API tests"""
    print("🚀 FastAPI Mobile Backend - Comprehensive API Test")
    print("=" * 60)
    
    tester = APITester()
    
    tests = [
        ("Health Check", tester.test_health),
        ("User Registration", tester.test_register),
        ("User Login", tester.test_login),
        ("Get Contacts", tester.test_get_contacts),
        ("Send Message", tester.test_send_message),
        ("Get Messages", tester.test_get_messages),
        ("User Logout", tester.test_logout),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 {test_name}")
        print("-" * 40)
        try:
            result = await test_func()
            if result:
                passed += 1
        except Exception as e:
            print(f"   ❌ Test failed with exception: {e}")
        
        # Small delay between tests
        await asyncio.sleep(0.5)
    
    print(f"\n📊 Test Results")
    print("=" * 30)
    print(f"✅ Passed: {passed}/{total}")
    print(f"❌ Failed: {total - passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed! FastAPI backend is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above.")

if __name__ == "__main__":
    print("📱 Make sure the FastAPI server is running on http://localhost:8000")
    print("   Start with: python fastapi_mobile_backend.py")
    print()
    
    asyncio.run(run_comprehensive_test())