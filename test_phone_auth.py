#!/usr/bin/env python3
"""
Test script for phone number-based authentication system
Tests admin-only user management and phone number login
"""

import requests
import json
import sys

# Configuration
BASE_URL = "http://localhost:8001"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "adminuser@123"

# Test data
TEST_PHONE_1 = "+1234567890"
TEST_PHONE_2 = "+0987654321"
TEST_TOKEN_1 = "test_token_123"
TEST_TOKEN_2 = "test_token_456"

class PhoneAuthTester:
    def __init__(self):
        self.admin_token = None
        self.user_session_token = None
        
    def print_header(self, text):
        print("\n" + "=" * 60)
        print(f"  {text}")
        print("=" * 60)
    
    def print_test(self, text):
        print(f"\n🧪 {text}")
    
    def print_success(self, text):
        print(f"   ✅ {text}")
    
    def print_error(self, text):
        print(f"   ❌ {text}")
    
    def test_health(self):
        """Test API health endpoint"""
        self.print_test("Testing API health...")
        try:
            response = requests.get(f"{BASE_URL}/status")
            if response.status_code == 200:
                data = response.json()
                self.print_success(f"API is running - v{data.get('version')}")
                self.print_success(f"Database: {data.get('database')}")
                self.print_success(f"Users: {data.get('users_count', 0)}")
                return True
            else:
                self.print_error(f"Health check failed: {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"Connection error: {e}")
            return False
    
    def test_public_registration_disabled(self):
        """Test that public registration is disabled"""
        self.print_test("Testing public registration is disabled...")
        try:
            data = {
                "phone_number": TEST_PHONE_1,
                "token": TEST_TOKEN_1
            }
            response = requests.post(f"{BASE_URL}/auth/register", json=data)
            
            if response.status_code == 403:
                self.print_success("Public registration correctly disabled (HTTP 403)")
                return True
            else:
                self.print_error(f"Unexpected response: {response.status_code}")
                print(f"      Response: {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Test error: {e}")
            return False
    
    def test_admin_login(self):
        """Test admin login"""
        self.print_test(f"Testing admin login (username: {ADMIN_USERNAME})...")
        try:
            data = {
                "username": ADMIN_USERNAME,
                "password": ADMIN_PASSWORD
            }
            response = requests.post(f"{BASE_URL}/admin/login", json=data)
            
            if response.status_code == 200:
                result = response.json()
                self.admin_token = result.get("token")
                must_change = result.get("must_change_password", False)
                
                self.print_success(f"Admin logged in successfully")
                self.print_success(f"Token: {self.admin_token[:20]}...")
                if must_change:
                    print(f"      ⚠️  Password change required on first login")
                return True
            else:
                self.print_error(f"Login failed: {response.status_code}")
                print(f"      Response: {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Test error: {e}")
            return False
    
    def test_admin_create_user(self, phone_number, token):
        """Test admin creating a user"""
        self.print_test(f"Testing admin create user (phone: {phone_number})...")
        
        if not self.admin_token:
            self.print_error("Admin not logged in. Run admin_login first.")
            return False
        
        try:
            data = {
                "phone_number": phone_number,
                "token": token
            }
            headers = {"Authorization": f"Bearer {self.admin_token}"}
            response = requests.post(
                f"{BASE_URL}/admin/users",
                json=data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                username = result.get("username")
                self.print_success(f"User created successfully")
                self.print_success(f"Phone: {phone_number}")
                self.print_success(f"Username: {username}")
                return True
            elif response.status_code == 400:
                self.print_error("User already exists (this is expected if running test multiple times)")
                return True  # Not a failure if user exists
            else:
                self.print_error(f"Create user failed: {response.status_code}")
                print(f"      Response: {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Test error: {e}")
            return False
    
    def test_user_login(self, phone_number, token):
        """Test user login with phone number"""
        self.print_test(f"Testing user login (phone: {phone_number})...")
        try:
            data = {
                "phone_number": phone_number,
                "token": token
            }
            response = requests.post(f"{BASE_URL}/auth/login", json=data)
            
            if response.status_code == 200:
                result = response.json()
                self.user_session_token = result.get("token")
                username = result.get("username")
                phone = result.get("phone_number")
                
                self.print_success(f"User logged in successfully")
                self.print_success(f"Phone: {phone}")
                self.print_success(f"Username: {username}")
                self.print_success(f"Session token: {self.user_session_token[:20]}...")
                return True
            else:
                self.print_error(f"Login failed: {response.status_code}")
                print(f"      Response: {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Test error: {e}")
            return False
    
    def test_send_message(self, recipient_phone, message_text="Test message"):
        """Test sending message using phone number"""
        self.print_test(f"Testing send message to {recipient_phone}...")
        
        if not self.user_session_token:
            self.print_error("User not logged in. Run user_login first.")
            return False
        
        try:
            data = {
                "phone_number": recipient_phone,
                "message": message_text
            }
            headers = {"Authorization": f"Bearer {self.user_session_token}"}
            response = requests.post(
                f"{BASE_URL}/messages/send",
                json=data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                self.print_success(f"Message sent to {recipient_phone}")
                self.print_success(f"Status: {result.get('message')}")
                return True
            else:
                self.print_error(f"Send message failed: {response.status_code}")
                print(f"      Response: {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Test error: {e}")
            return False
    
    def test_admin_list_users(self):
        """Test admin listing all users"""
        self.print_test("Testing admin list all users...")
        
        if not self.admin_token:
            self.print_error("Admin not logged in. Run admin_login first.")
            return False
        
        try:
            headers = {"Authorization": f"Bearer {self.admin_token}"}
            response = requests.get(f"{BASE_URL}/admin/users", headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                users = result.get("users", [])
                count = result.get("count", 0)
                
                self.print_success(f"Retrieved {count} users")
                for user in users[:5]:  # Show first 5
                    phone = user.get("phone_number", "N/A")
                    username = user.get("username", "N/A")
                    is_admin = user.get("is_admin", False)
                    admin_label = " [ADMIN]" if is_admin else ""
                    print(f"      👤 {phone} ({username}){admin_label}")
                return True
            else:
                self.print_error(f"List users failed: {response.status_code}")
                print(f"      Response: {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Test error: {e}")
            return False
    
    def test_admin_delete_user(self, phone_number):
        """Test admin deleting a user"""
        self.print_test(f"Testing admin delete user (phone: {phone_number})...")
        
        if not self.admin_token:
            self.print_error("Admin not logged in. Run admin_login first.")
            return False
        
        try:
            headers = {"Authorization": f"Bearer {self.admin_token}"}
            response = requests.delete(
                f"{BASE_URL}/admin/users/{phone_number}",
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                self.print_success(f"User deleted: {phone_number}")
                self.print_success(f"Message: {result.get('message')}")
                return True
            elif response.status_code == 404:
                self.print_error(f"User not found: {phone_number}")
                return False
            else:
                self.print_error(f"Delete user failed: {response.status_code}")
                print(f"      Response: {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Test error: {e}")
            return False
    
    def test_user_logout(self):
        """Test user logout"""
        self.print_test("Testing user logout...")
        
        if not self.user_session_token:
            self.print_error("User not logged in.")
            return False
        
        try:
            headers = {"Authorization": f"Bearer {self.user_session_token}"}
            response = requests.post(f"{BASE_URL}/auth/logout", headers=headers)
            
            if response.status_code == 200:
                self.print_success("User logged out successfully")
                self.user_session_token = None
                return True
            else:
                self.print_error(f"Logout failed: {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"Test error: {e}")
            return False


def run_all_tests():
    """Run complete test suite"""
    print("\n" + "=" * 60)
    print("  PHONE NUMBER AUTHENTICATION - TEST SUITE")
    print("=" * 60)
    print(f"\n📍 Testing API at: {BASE_URL}")
    print(f"📱 Test phone numbers: {TEST_PHONE_1}, {TEST_PHONE_2}")
    
    tester = PhoneAuthTester()
    results = []
    
    # Test 1: Health check
    tester.print_header("Test 1: API Health Check")
    results.append(("Health Check", tester.test_health()))
    
    # Test 2: Public registration disabled
    tester.print_header("Test 2: Public Registration Disabled")
    results.append(("Registration Disabled", tester.test_public_registration_disabled()))
    
    # Test 3: Admin login
    tester.print_header("Test 3: Admin Login")
    results.append(("Admin Login", tester.test_admin_login()))
    
    # Test 4: Admin create user
    tester.print_header("Test 4: Admin Create User")
    results.append(("Create User 1", tester.test_admin_create_user(TEST_PHONE_1, TEST_TOKEN_1)))
    results.append(("Create User 2", tester.test_admin_create_user(TEST_PHONE_2, TEST_TOKEN_2)))
    
    # Test 5: User login with phone number
    tester.print_header("Test 5: User Login (Phone Number)")
    results.append(("User Login", tester.test_user_login(TEST_PHONE_1, TEST_TOKEN_1)))
    
    # Test 6: Send message using phone number
    tester.print_header("Test 6: Send Message (Phone Number)")
    results.append(("Send Message", tester.test_send_message(TEST_PHONE_2, "Hello from phone auth test!")))
    
    # Test 7: Admin list users
    tester.print_header("Test 7: Admin List Users")
    results.append(("List Users", tester.test_admin_list_users()))
    
    # Test 8: User logout
    tester.print_header("Test 8: User Logout")
    results.append(("User Logout", tester.test_user_logout()))
    
    # Test 9: Admin delete user (cleanup)
    tester.print_header("Test 9: Admin Delete User (Cleanup)")
    results.append(("Delete User", tester.test_admin_delete_user(TEST_PHONE_2)))
    
    # Print summary
    tester.print_header("TEST SUMMARY")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print("\n📊 Results:")
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status} - {test_name}")
    
    print(f"\n📈 Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    try:
        exit_code = run_all_tests()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        sys.exit(1)
