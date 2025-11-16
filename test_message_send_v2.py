#!/usr/bin/env python3
"""
Test script to send a message between existing users
"""

import requests
import json
import time

# Configuration
BASE_URL = "http://localhost:8001"  # Default FastAPI port

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

def get_users(token):
    """Get list of users"""
    url = f"{BASE_URL}/users"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    
    try:
        response = requests.get(url, headers=headers)
        print(f"Get users - Status: {response.status_code}")
        if response.status_code == 200:
            print(f"Users retrieved successfully: {response.json()}")
            return response.json()
        else:
            print(f"Failed to get users: {response.text}")
            return None
    except Exception as e:
        print(f"Error getting users: {e}")
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
        print(f"Send message - Status: {response.status_code}")
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
    print("=== Pager Message Test ===")
    
    # Login with existing users
    print("\n1. Logging in with existing users...")
    ryuzakii = login_user("Ryuzakii", "@1257_Shadow")
    jules = login_user("Jules", "bigjules123")
    
    # If we have both users, let's check the user list and send messages
    if ryuzakii and jules:
        print("\n2. Getting list of users...")
        users = get_users(ryuzakii.get("token"))
        
        if users and "users" in users:
            print("\nAvailable users:")
            for user in users["users"]:
                print(f"  - {user.get('username', 'N/A')} (phone: {user.get('phone_number', 'N/A')})")
            
            # Try to send a message between the users
            print("\n3. Sending message from Ryuzakii to Jules...")
            ryuzakii_token = ryuzakii.get("token")
            
            # Use Jules' username
            jules_username = "Jules"
            message = "Hello Jules! This is a test message from Ryuzakii."
            send_message(ryuzakii_token, jules_username, message)
            
            print("\n4. Sending message from Jules to Ryuzakii...")
            jules_token = jules.get("token")
            
            # Use Ryuzakii's username
            ryuzakii_username = "Ryuzakii"
            message = "Hi Ryuzakii! This is a reply from Jules."
            send_message(jules_token, ryuzakii_username, message)
        else:
            print("Could not retrieve user list")
    else:
        print("Could not authenticate both users. Cannot send messages.")

if __name__ == "__main__":
    main()