#!/usr/bin/env python3
"""
Test script for decoy image messaging functionality
"""

import requests
import base64
import json
import time

# Configuration
BASE_URL = "http://localhost:8001"
TEST_USER_TOKEN = "test_token"
TEST_RECIPIENT = "test_recipient"
TEST_MASTER_TOKEN = "test_master_token"

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

def send_decoy_image(token, image_data):
    """Send decoy image"""
    url = f"{BASE_URL}/messages/send_decoy_image"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, json=image_data)
    return response

def extract_hidden_image(token, extract_data):
    """Extract hidden image using master token"""
    url = f"{BASE_URL}/messages/extract_decoy_image"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, json=extract_data)
    return response

def main():
    print("Testing decoy image messaging functionality...")
    
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
        
        # Create test image data
        # 1x1 transparent PNG image in base64
        test_image_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
        
        image_data = {
            "username": TEST_RECIPIENT,
            "image_content": test_image_base64,
            "filename": "test_hidden_image.png",
            "file_size": len(test_image_base64),
            "disappear_after_hours": None
        }
        
        print("Sending decoy image...")
        response = send_decoy_image(user_token, image_data)
        print(f"Send image response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            send_result = response.json()
            message_id = send_result.get("message_id")
            print(f"✅ Decoy image sent successfully! Message ID: {message_id}")
            
            # Wait a moment for the message to be processed
            time.sleep(1)
            
            # Test extraction (this would normally be done by the recipient)
            extract_data = {
                "mastertoken": TEST_MASTER_TOKEN,
                "message_id": message_id
            }
            
            print("Extracting hidden image...")
            response = extract_hidden_image(user_token, extract_data)
            print(f"Extract image response: {response.status_code} - {response.text}")
            
            if response.status_code == 200:
                extract_result = response.json()
                print("✅ Hidden image extracted successfully!")
                print(f"Filename: {extract_result.get('filename')}")
                print(f"File size: {extract_result.get('file_size')}")
                print(f"Image data length: {len(extract_result.get('image_data', ''))}")
            else:
                print("❌ Failed to extract hidden image!")
                print(f"Response: {response.text}")
        else:
            print("❌ Failed to send decoy image!")
            print(f"Response: {response.text}")
    else:
        print("❌ Failed to login test user")

if __name__ == "__main__":
    main()