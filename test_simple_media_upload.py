#!/usr/bin/env python3
"""
Test script for simple media upload functionality
"""

import requests
import base64
import json

# Configuration
BASE_URL = "http://localhost:8001"
TEST_USER_TOKEN = "test_token"  # Replace with actual token
TEST_RECIPIENT = "test_recipient"  # Replace with actual recipient

def create_test_user(username, token):
    """Create a test user"""
    url = f"{BASE_URL}/auth/register"
    data = {
        "username": username,
        "token": token
    }
    response = requests.post(url, json=data)
    return response

def login_test_user(username, token):
    """Login test user"""
    url = f"{BASE_URL}/auth/login"
    data = {
        "username": username,
        "token": token
    }
    response = requests.post(url, json=data)
    return response

def upload_simple_media(token, media_data):
    """Upload simple media"""
    url = f"{BASE_URL}/media/simple_upload"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, json=media_data)
    return response

def main():
    print("Testing simple media upload functionality...")
    
    # Create a test user
    print("Creating test user...")
    response = create_test_user("test_user", TEST_USER_TOKEN)
    print(f"Create user response: {response.status_code} - {response.text}")
    
    # Login test user
    print("Logging in test user...")
    response = login_test_user("test_user", TEST_USER_TOKEN)
    print(f"Login response: {response.status_code} - {response.text}")
    
    if response.status_code == 200:
        login_data = response.json()
        user_token = login_data.get("token")
        print(f"User token: {user_token}")
        
        # Create test media data
        # 1x1 transparent PNG image in base64
        test_image_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
        
        media_data = {
            "username": TEST_RECIPIENT,
            "media_type": "photo",
            "content": test_image_base64,
            "filename": "test_image.png",
            "file_size": len(test_image_base64),
            "content_type": "image/png",
            "disappear_after_hours": None
        }
        
        print("Uploading simple media...")
        response = upload_simple_media(user_token, media_data)
        print(f"Upload response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            print("✅ Simple media upload test passed!")
        else:
            print("❌ Simple media upload test failed!")
            print(f"Response: {response.text}")
    else:
        print("❌ Failed to login test user")

if __name__ == "__main__":
    main()