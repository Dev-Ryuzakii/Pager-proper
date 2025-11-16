#!/usr/bin/env python3
"""
Test script to create users and send messages between them
"""

import requests
import json
import time

# Configuration
BASE_URL = "http://localhost:8001"  # Default FastAPI port

def create_user(username, phone_number, password):
    """Create a new user"""
    url = f"{BASE_URL}/admin/users"
    payload = {
        "username": username,
        "phone_number": phone_number,
        "password": password
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        print(f"Create {username} - Status: {response.status_code}")
        if response.status_code == 200:
            print(f"User creation successful: {response.json()}")
            return response.json()
        else:
            print(f"User creation failed: {response.text}")
            return None
    except Exception as e:
        print(f"Error during user creation: {e}")
        return None

def login_user(username, password):
    """Login user"""
    url = f"{BASE_URL}/auth/login"
    payload = {
        "username": username,
        "token": password  # In this system, token is used like password
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        print(f"Login {username} - Status: {response.status_code}")
        if response.status_code == 200:
            print(f"Login successful: {response.json()}")
            return response.json()
        else:
            print(f"Login failed: {response.text}")
            return None
    except Exception as e:
        print(f"Error during login: {e}")
        return None

def send_message(token, recipient_username, message, disappear_after_hours=None):
    """Send a message"""
    url = f"{BASE_URL}/messages/send"
    payload = {
        "username": recipient_username,
        "message": message
    }
    if disappear_after_hours is not None:
        payload["disappear_after_hours"] = disappear_after_hours
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        print(f"Send message to {recipient_username} - Status: {response.status_code}")
        if response.status_code == 200:
            print(f"Message sent successfully: {response.json()}")
            return response.json()
        else:
            print(f"Failed to send message: {response.text}")
            return None
    except Exception as e:
        print(f"Error sending message: {e}")
        return None

def main():
    print("=== Pager User Creation and Message Test ===")
    
    # Create two users with known phone numbers
    print("\n1. Creating users...")
    user1 = create_user("Ryuzakii", "09076655506", "@1257_Shadow")
    user2 = create_user("Jules", "0987654321", "bigjules123")
    
    # Login with the created users
    if user1 and user2:
        print("\n2. Logging in with created users...")
        ryuzakii = login_user("Ryuzakii", "@1257_Shadow")
        jules = login_user("Jules", "bigjules123")
        
        # If we have both users, let's send messages
        if ryuzakii and jules:
            print("\n3. Sending message from Ryuzakii to Jules...")
            ryuzakii_token = ryuzakii.get("token")
            jules_username = "Jules"
            message = "Hello Jules! This is a test message from Ryuzakii."
            send_message(ryuzakii_token, jules_username, message)
            
            print("\n4. Sending message from Jules to Ryuzakii...")
            jules_token = jules.get("token")
            ryuzakii_username = "Ryuzakii"
            message = "Hi Ryuzakii! This is a reply from Jules."
            send_message(jules_token, ryuzakii_username, message)
        else:
            print("Could not authenticate both users. Cannot send messages.")
    else:
        print("Could not create both users. Cannot proceed with messaging test.")

if __name__ == "__main__":
    main()