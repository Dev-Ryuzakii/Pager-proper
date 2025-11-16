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

def try_common_usernames(token, sender_name):
    """Try sending messages to common usernames"""
    common_usernames = [
        "Jules",
        "Ryuzakii",
        "TestUser",
        "User1",
        "User2"
    ]
    
    message = f"Hello! This is a test message from {sender_name}."
    
    for username in common_usernames:
        print(f"\nTrying to send message to: {username}")
        result = send_message(token, username, message)
        if result:
            print(f"Successfully sent message to {username}")
            return username
    
    return None

def main():
    print("=== Pager Message Test ===")
    
    # Login with existing users
    print("\n1. Logging in with existing users...")
    ryuzakii = login_user("Ryuzakii", "@1257_Shadow")
    jules = login_user("Jules", "bigjules123")
    
    # If we have both users, let's try to send messages
    if ryuzakii and jules:
        print("\n2. Trying to send message from Ryuzakii to common usernames...")
        ryuzakii_token = ryuzakii.get("token")
        found_username = try_common_usernames(ryuzakii_token, "Ryuzakii")
        
        if found_username:
            print(f"\n3. Found valid username: {found_username}")
            print("4. Trying to send reply from Jules...")
            jules_token = jules.get("token")
            reply_message = "Hi Ryuzakii! This is a reply from Jules."
            send_message(jules_token, found_username, reply_message)
        else:
            print("\n3. Could not find a valid username for Jules")
            print("Let's try to send a message from Jules to common usernames...")
            jules_token = jules.get("token")
            try_common_usernames(jules_token, "Jules")
    else:
        print("Could not authenticate both users. Cannot send messages.")

if __name__ == "__main__":
    main()