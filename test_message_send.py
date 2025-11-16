#!/usr/bin/env python3
"""
Test script to send a message between two users
User 1: Ryuzakii with password @1257_Shadow
User 2: Jules with password bigjules123
"""

import requests
import json
import time

# Configuration
BASE_URL = "http://localhost:8001"  # Default FastAPI port

def register_user(username, phone_number, password):
    """Register a new user"""
    url = f"{BASE_URL}/register"
    payload = {
        "username": username,
        "phone_number": phone_number,
        "password": password,
        "public_key": f"public_key_for_{username}",  # Placeholder
        "token": f"token_for_{username}"  # Placeholder
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        print(f"Register {username} - Status: {response.status_code}")
        if response.status_code == 200:
            print(f"Registration successful: {response.json()}")
            return response.json()
        else:
            print(f"Registration failed: {response.text}")
            return None
    except Exception as e:
        print(f"Error during registration: {e}")
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
    
    # First, let's try to register our users
    print("\n1. Registering users...")
    ryuzakii = register_user("Ryuzakii", "+1234567890", "@1257_Shadow")
    jules = register_user("Jules", "+0987654321", "bigjules123")
    
    # If registration fails, let's try to login with existing users
    if not ryuzakii or not jules:
        print("\n2. Trying to login with existing users...")
        ryuzakii = login_user("Ryuzakii", "@1257_Shadow")
        jules = login_user("Jules", "bigjules123")
    
    # If we have both users, let's send a message
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

if __name__ == "__main__":
    main()