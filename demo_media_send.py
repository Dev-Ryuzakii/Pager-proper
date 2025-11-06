#!/usr/bin/env python3
"""
Demo script to show how to send an image to a user and decrypt messages with a master token
"""

import requests
import base64

# Base URL for the API
BASE_URL = "http://localhost:8001"

def main():
    print("🔐 Demo: Sending Image and Decrypting Messages")
    print("=" * 50)
    
    # Admin login
    print("1. Admin login...")
    admin_response = requests.post(
        f"{BASE_URL}/admin/login",
        json={
            "username": "admin",
            "password": "NewPassword123!"
        }
    )
    
    if admin_response.status_code != 200:
        print("❌ Admin login failed")
        return
    
    admin_token = admin_response.json()["token"]
    print("✅ Admin logged in successfully")
    
    # Create users if they don't exist
    print("\n2. Ensuring users exist...")
    users_data = [
        {"username": "shadow", "token": "kamisama"},
        {"username": "ryuzakii", "token": "shadow"}
    ]
    
    for user_data in users_data:
        create_response = requests.post(
            f"{BASE_URL}/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=user_data
        )
        if create_response.status_code == 200:
            print(f"✅ User {user_data['username']} created/verified")
        else:
            print(f"ℹ️  User {user_data['username']} already exists or creation failed (this is OK)")
    
    # Login as ryuzakii
    print("\n3. Logging in as ryuzakii...")
    ryuzakii_response = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": "ryuzakii",
            "token": "shadow"
        }
    )
    
    if ryuzakii_response.status_code != 200:
        print("❌ ryuzakii login failed")
        return
    
    ryuzakii_token = ryuzakii_response.json()["token"]
    print("✅ ryuzakii logged in successfully")
    
    # Login as shadow
    print("\n4. Logging in as shadow...")
    shadow_response = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": "shadow",
            "token": "kamisama"
        }
    )
    
    if shadow_response.status_code != 200:
        print("❌ shadow login failed")
        return
    
    shadow_token = shadow_response.json()["token"]
    print("✅ shadow logged in successfully")
    
    # Send an image from ryuzakii to shadow
    print("\n5. Sending image from ryuzakii to shadow...")
    # Create dummy image data (in a real app, this would be actual encrypted image data)
    dummy_image_data = base64.b64encode(b"dummy image content for testing").decode('utf-8')
    
    media_response = requests.post(
        f"{BASE_URL}/media/upload",
        headers={
            "Authorization": f"Bearer {ryuzakii_token}",
            "Content-Type": "application/json"
        },
        json={
            "username": "shadow",
            "media_type": "photo",
            "encrypted_content": dummy_image_data,
            "filename": "Screenshot 2025-11-05 at 08.56.37.png",
            "file_size": len(dummy_image_data)
        }
    )
    
    if media_response.status_code == 200:
        media_id = media_response.json()["media_id"]
        print("✅ Image sent successfully")
        print(f"   Media ID: {media_id}")
    else:
        print("❌ Failed to send image")
        print(f"   Status code: {media_response.status_code}")
        print(f"   Response: {media_response.text}")
        return
    
    # Send a text message from ryuzakii to shadow
    print("\n6. Sending text message from ryuzakii to shadow...")
    message_response = requests.post(
        f"{BASE_URL}/messages/send",
        headers={
            "Authorization": f"Bearer {ryuzakii_token}",
            "Content-Type": "application/json"
        },
        json={
            "username": "shadow",
            "message": "Secret test message for decryption with master token",
            "disappear_after_hours": 24
        }
    )
    
    if message_response.status_code == 200:
        print("✅ Text message sent successfully")
    else:
        print("❌ Failed to send text message")
        return
    
    # Check shadow's inbox for the message
    print("\n7. Checking shadow's inbox...")
    inbox_response = requests.get(
        f"{BASE_URL}/messages/inbox",
        headers={"Authorization": f"Bearer {shadow_token}"}
    )
    
    if inbox_response.status_code == 200:
        messages = inbox_response.json()["messages"]
        print(f"✅ Found {len(messages)} messages in inbox")
        if messages:
            # Get the latest message
            latest_message = messages[0]
            message_id = latest_message["id"]
            print(f"   Latest message ID: {message_id}")
        else:
            print("❌ No messages found")
            return
    else:
        print("❌ Failed to get inbox")
        return
    
    # Create and confirm master token for shadow
    print("\n8. Creating master token for shadow...")
    master_token_response = requests.post(
        f"{BASE_URL}/mastertoken/create",
        headers={"Authorization": f"Bearer {shadow_token}"},
        json={
            "mastertoken": "aminahmybby@123"
        }
    )
    
    if master_token_response.status_code == 200:
        print("✅ Master token created")
    else:
        print("❌ Failed to create master token")
        return
    
    print("\n9. Confirming master token...")
    confirm_token_response = requests.post(
        f"{BASE_URL}/mastertoken/confirm",
        headers={"Authorization": f"Bearer {shadow_token}"},
        json={
            "mastertoken": "aminahmybby@123"
        }
    )
    
    if confirm_token_response.status_code == 200:
        print("✅ Master token confirmed")
    else:
        print("❌ Failed to confirm master token")
        return
    
    # Decrypt the message
    print("\n10. Decrypting message with master token...")
    decrypt_response = requests.post(
        f"{BASE_URL}/decrypt",
        headers={"Authorization": f"Bearer {shadow_token}"},
        json={
            "message_id": message_id,
            "mastertoken": "aminahmybby@123"
        }
    )
    
    if decrypt_response.status_code == 200:
        decrypted_data = decrypt_response.json()
        print("✅ Message decrypted successfully")
        print(f"   Sender: {decrypted_data['sender']}")
        print(f"   Content: {decrypted_data['content']}")
        print(f"   Decrypt time: {decrypted_data['decrypt_time']} seconds")
    else:
        print("❌ Failed to decrypt message")
        print(f"   Status code: {decrypt_response.status_code}")
        print(f"   Response: {decrypt_response.text}")
        # This is expected to fail in our test because we didn't send properly encrypted content
    
    print("\n🎉 Demo completed!")

if __name__ == "__main__":
    main()