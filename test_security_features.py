"""
Test script to verify security features of the Secure Messaging API
"""

import requests
import json
import time

# Base URL for the API
BASE_URL = "http://localhost:8001"

def test_token_format_validation():
    """Test token format validation"""
    print("Testing Token Format Validation...")
    
    # Test cases for invalid tokens
    invalid_tokens = [
        "",  # Empty token
        "short",  # Too short
        "nouppercase123!",  # No uppercase
        "NOLOWERCASE123!",  # No lowercase
        "NoDigits!",  # No digits
        "NoSpecialChars123",  # No special characters
    ]
    
    # Register a test user
    user_data = {
        "username": "testuser_format",
        "token": "testtoken123"
    }
    
    response = requests.post(f"{BASE_URL}/auth/register", json=user_data)
    if response.status_code != 200:
        print("Failed to register test user")
        return
    
    session_token = response.json()["token"]
    
    # Test invalid master tokens
    for token in invalid_tokens:
        master_token_data = {
            "mastertoken": token
        }
        
        response = requests.post(
            f"{BASE_URL}/mastertoken/create",
            json=master_token_data,
            headers={"Authorization": f"Bearer {session_token}"}
        )
        
        if response.status_code == 422 or (response.status_code == 400 and "must" in response.json().get("detail", "")):
            print(f"✓ Correctly rejected invalid token: '{token}'")
        else:
            print(f"✗ Failed to reject invalid token: '{token}'")
    
    # Test valid token
    valid_token = "ValidToken123!"
    master_token_data = {
        "mastertoken": valid_token
    }
    
    response = requests.post(
        f"{BASE_URL}/mastertoken/create",
        json=master_token_data,
        headers={"Authorization": f"Bearer {session_token}"}
    )
    
    if response.status_code == 200:
        print("✓ Correctly accepted valid token")
    else:
        print("✗ Failed to accept valid token")

def test_failed_attempt_protection():
    """Test failed attempt protection"""
    print("\nTesting Failed Attempt Protection...")
    
    # Register a test user
    user_data = {
        "username": "testuser_attempts",
        "token": "testtoken123"
    }
    
    response = requests.post(f"{BASE_URL}/auth/register", json=user_data)
    if response.status_code != 200:
        print("Failed to register test user")
        return
    
    session_token = response.json()["token"]
    
    # Try to decrypt with invalid master tokens 3 times
    for i in range(3):
        decrypt_data = {
            "message_id": 999999,  # Non-existent message
            "mastertoken": f"invalidtoken{i}"
        }
        
        response = requests.post(
            f"{BASE_URL}/decrypt",
            json=decrypt_data,
            headers={"Authorization": f"Bearer {session_token}"}
        )
        
        if response.status_code == 401:
            print(f"✓ Attempt {i+1}: Correctly rejected invalid master token")
        else:
            print(f"✗ Attempt {i+1}: Unexpected response for invalid master token")
    
    # Try one more time - should be barred
    decrypt_data = {
        "message_id": 999999,
        "mastertoken": "finalinvalidtoken"
    }
    
    response = requests.post(
        f"{BASE_URL}/decrypt",
        json=decrypt_data,
        headers={"Authorization": f"Bearer {session_token}"}
    )
    
    if response.status_code == 403 and "barred" in response.json().get("detail", ""):
        print("✓ Account correctly barred after 3 failed attempts")
    else:
        print("✗ Account was not barred after 3 failed attempts")

def test_token_binding_validation():
    """Test token binding validation"""
    print("\nTesting Token Binding Validation...")
    
    # Register two test users
    user1_data = {
        "username": "testuser_binding1",
        "token": "testtoken123"
    }
    
    user2_data = {
        "username": "testuser_binding2",
        "token": "testtoken456"
    }
    
    # Register user 1
    response1 = requests.post(f"{BASE_URL}/auth/register", json=user1_data)
    if response1.status_code != 200:
        print("Failed to register test user 1")
        return
    
    session_token1 = response1.json()["token"]
    
    # Register user 2
    response2 = requests.post(f"{BASE_URL}/auth/register", json=user2_data)
    if response2.status_code != 200:
        print("Failed to register test user 2")
        return
    
    session_token2 = response2.json()["token"]
    
    # Create master token for user 1
    master_token_data = {
        "mastertoken": "User1Token123!"
    }
    
    response = requests.post(
        f"{BASE_URL}/mastertoken/create",
        json=master_token_data,
        headers={"Authorization": f"Bearer {session_token1}"}
    )
    
    if response.status_code != 200:
        print("Failed to create master token for user 1")
        return
    
    # Confirm master token for user 1
    response = requests.post(
        f"{BASE_URL}/mastertoken/confirm",
        json=master_token_data,
        headers={"Authorization": f"Bearer {session_token1}"}
    )
    
    if response.status_code != 200:
        print("Failed to confirm master token for user 1")
        return
    
    # Try to use user 1's master token with user 2's session - should fail
    decrypt_data = {
        "message_id": 999999,
        "mastertoken": "User1Token123!"
    }
    
    response = requests.post(
        f"{BASE_URL}/decrypt",
        json=decrypt_data,
        headers={"Authorization": f"Bearer {session_token2}"}
    )
    
    if response.status_code == 401 or response.status_code == 404:
        print("✓ Correctly rejected master token from different user")
    else:
        print("✗ Failed to reject master token from different user")

if __name__ == "__main__":
    print("Running Security Feature Tests...\n")
    
    try:
        test_token_format_validation()
        test_failed_attempt_protection()
        test_token_binding_validation()
        
        print("\nAll tests completed!")
    except Exception as e:
        print(f"Error running tests: {e}")