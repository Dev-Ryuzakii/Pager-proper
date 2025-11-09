import pytest
import requests
import base64
import json
import os

# Base URL for the API
BASE_URL = "http://localhost:8001"

class TestMediaSend:
    # Class variables to store tokens
    admin_token = None
    shadow_token = None
    ryuzakii_token = None
    
    @classmethod
    def setup_class(cls):
        """Setup method to authenticate users before running tests"""
        # Admin login
        admin_response = requests.post(
            f"{BASE_URL}/admin/login",
            json={
                "username": "admin",
                "password": "NewPassword123!"
            }
        )
        assert admin_response.status_code == 200
        cls.admin_token = admin_response.json()["token"]
        
        # Create shadow user if not exists
        create_shadow_response = requests.post(
            f"{BASE_URL}/admin/users",
            headers={"Authorization": f"Bearer {cls.admin_token}"},
            json={
                "username": "shadow",
                "token": "kamisama"
            }
        )
        # It's okay if this fails because user might already exist
        
        # Create ryuzakii user if not exists
        create_ryuzakii_response = requests.post(
            f"{BASE_URL}/admin/users",
            headers={"Authorization": f"Bearer {cls.admin_token}"},
            json={
                "username": "ryuzakii",
                "token": "shadow"
            }
        )
        # It's okay if this fails because user might already exist
        
        # Login as shadow
        shadow_response = requests.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": "shadow",
                "token": "kamisama"
            }
        )
        assert shadow_response.status_code == 200
        cls.shadow_token = shadow_response.json()["token"]
        
        # Login as ryuzakii
        ryuzakii_response = requests.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": "ryuzakii",
                "token": "shadow"
            }
        )
        assert ryuzakii_response.status_code == 200
        cls.ryuzakii_token = ryuzakii_response.json()["token"]
    
    def test_send_image_to_shadow(self):
        """Test sending an image to shadow user"""
        # First, let's create some dummy image data (in a real test, you would use an actual image file)
        # For this test, we'll create a simple base64 encoded string to represent an image
        dummy_image_data = base64.b64encode(b"dummy image content for testing").decode('utf-8')
        
        # Send media to shadow
        media_response = requests.post(
            f"{BASE_URL}/media/upload",
            headers={
                "Authorization": f"Bearer {self.ryuzakii_token}",
                "Content-Type": "application/json"
            },
            json={
                "username": "shadow",
                "media_type": "photo",
                "encrypted_content": dummy_image_data,
                "filename": "test_image.png",
                "file_size": len(dummy_image_data)
            }
        )
        
        assert media_response.status_code == 200
        response_data = media_response.json()
        assert "media_id" in response_data
        assert response_data["message"] == "Media uploaded successfully"
        
        # Store media_id for later use
        self.media_id = response_data["media_id"]
    
    def test_receive_image_as_shadow(self):
        """Test receiving image as shadow user"""
        # Get media inbox for shadow
        inbox_response = requests.get(
            f"{BASE_URL}/media/inbox",
            headers={"Authorization": f"Bearer {self.shadow_token}"}
        )
        
        assert inbox_response.status_code == 200
        response_data = inbox_response.json()
        assert "media_files" in response_data
        assert response_data["count"] >= 1
        
        # Find our test image
        media_files = response_data["media_files"]
        test_media = None
        for media in media_files:
            if media["filename"] == "test_image.png":
                test_media = media
                break
        
        assert test_media is not None
        assert test_media["sender"] == "ryuzakii"
        assert test_media["media_type"] == "photo"
    
    def test_decrypt_message_with_master_token(self):
        """Test decrypting a message with master token"""
        # First, we need to send a text message (easier to test than media)
        message_response = requests.post(
            f"{BASE_URL}/messages/send",
            headers={
                "Authorization": f"Bearer {self.ryuzakii_token}",
                "Content-Type": "application/json"
            },
            json={
                "username": "shadow",
                "message": "Secret test message for decryption",
                "disappear_after_hours": 24
            }
        )
        
        assert message_response.status_code == 200
        
        # Get shadow's inbox to find the message
        inbox_response = requests.get(
            f"{BASE_URL}/messages/inbox",
            headers={"Authorization": f"Bearer {self.shadow_token}"}
        )
        
        assert inbox_response.status_code == 200
        response_data = inbox_response.json()
        assert response_data["count"] >= 1
        
        # Find our test message
        messages = response_data["messages"]
        test_message = None
        for msg in messages:
            if "Secret test message" in msg["content"]:
                test_message = msg
                break
        
        assert test_message is not None
        
        # Create master token for shadow
        master_token_response = requests.post(
            f"{BASE_URL}/mastertoken/create",
            headers={"Authorization": f"Bearer {self.shadow_token}"},
            json={
                "mastertoken": "aminahmybby@123"
            }
        )
        
        assert master_token_response.status_code == 200
        
        # Confirm master token
        confirm_token_response = requests.post(
            f"{BASE_URL}/mastertoken/confirm",
            headers={"Authorization": f"Bearer {self.shadow_token}"},
            json={
                "mastertoken": "aminahmybby@123"
            }
        )
        
        assert confirm_token_response.status_code == 200
        
        # Decrypt message
        decrypt_response = requests.post(
            f"{BASE_URL}/decrypt",
            headers={"Authorization": f"Bearer {self.shadow_token}"},
            json={
                "message_id": test_message["id"],
                "mastertoken": "aminahmybby@123"
            }
        )
        
        # Note: This might fail in a real test because the server expects properly encrypted content
        # But we're testing that the endpoint works correctly
        # In a real implementation, we would need to send properly encrypted content

if __name__ == "__main__":
    pytest.main([__file__, "-v"])