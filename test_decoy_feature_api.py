"""
Test script to verify decoy text feature is working
"""

import requests
import json
import time

def test_decoy_text_feature():
    """Test the decoy text feature"""
    print("Testing Decoy Text Feature")
    print("=" * 50)
    
    # Base URL for the API
    BASE_URL = "http://localhost:8001"
    
    # Test user credentials
    test_user = {
        "username": "testuser",
        "token": "testtoken123"
    }
    
    try:
        # Register a test user
        print("1. Registering test user...")
        register_response = requests.post(
            f"{BASE_URL}/auth/register",
            json=test_user
        )
        
        if register_response.status_code == 200:
            session_data = register_response.json()
            session_token = session_data["token"]
            print("   ✅ User registered successfully")
        else:
            print(f"   ❌ Registration failed: {register_response.text}")
            return
        
        # Login as the test user
        print("2. Logging in...")
        login_response = requests.post(
            f"{BASE_URL}/auth/login",
            json=test_user
        )
        
        if login_response.status_code == 200:
            session_data = login_response.json()
            session_token = session_data["token"]
            print("   ✅ User logged in successfully")
        else:
            print(f"   ❌ Login failed: {login_response.text}")
            return
        
        # Set up headers with session token
        headers = {
            "Authorization": f"Bearer {session_token}"
        }
        
        # Send a test message
        print("3. Sending test message...")
        message_data = {
            "username": test_user["username"],  # Send to self for testing
            "message": "This is a secret test message that should be encrypted"
        }
        
        send_response = requests.post(
            f"{BASE_URL}/messages/send",
            json=message_data,
            headers=headers
        )
        
        if send_response.status_code == 200:
            print("   ✅ Message sent successfully")
        else:
            print(f"   ❌ Failed to send message: {send_response.text}")
            return
        
        # Wait a moment for the message to be processed
        time.sleep(1)
        
        # Get inbox to check for decoy text
        print("4. Checking inbox for decoy text...")
        inbox_response = requests.get(
            f"{BASE_URL}/messages/inbox",
            headers=headers
        )
        
        if inbox_response.status_code == 200:
            inbox_data = inbox_response.json()
            messages = inbox_data.get("messages", [])
            
            if messages:
                message = messages[0]  # Get the first message
                print(f"   ✅ Message received")
                print(f"   Sender: {message.get('sender')}")
                print(f"   Content: {message.get('content')}")
                print(f"   Is Encrypted: {message.get('is_encrypted', False)}")
                
                # Verify that the message has the expected properties
                if message.get('is_encrypted') == True:
                    print("   ✅ Message correctly marked as encrypted")
                else:
                    print("   ❌ Message not marked as encrypted")
                    
                # Check if the content looks like decoy text (not encrypted data)
                content = message.get('content', '')
                if content.startswith('[ENCRYPTED') or 'ENCRYPTED' in content.upper():
                    print("   ⚠️  Content still shows encrypted data")
                else:
                    print("   ✅ Content shows realistic decoy text")
            else:
                print("   ⚠️  No messages found in inbox")
        else:
            print(f"   ❌ Failed to get inbox: {inbox_response.text}")
            
        print("\n✅ Decoy text feature test completed!")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")

if __name__ == "__main__":
    test_decoy_text_feature()