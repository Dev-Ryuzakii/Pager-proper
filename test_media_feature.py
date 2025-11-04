#!/usr/bin/env python3
"""
Test for Media Feature
This script tests the media upload and download functionality.
"""

import os
import sys
import json
import base64
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from database_config import db_config
from database_models import User, Media, Message

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_media_feature():
    """Test the media feature functionality"""
    print("🧪 Testing Media Feature")
    print("=" * 50)
    
    # Get database session
    session = db_config.get_session()
    if not session:
        print("❌ Failed to get database session")
        return False
    
    try:
        # Create test users if they don't exist
        sender = session.query(User).filter(User.username == "test_media_sender").first()
        if not sender:
            sender = User(
                username="test_media_sender",
                token="test_token_media_1",
                is_active=True,
                is_verified=True,
                user_type="mobile"
            )
            session.add(sender)
            session.commit()
        
        recipient = session.query(User).filter(User.username == "test_media_recipient").first()
        if not recipient:
            recipient = User(
                username="test_media_recipient",
                token="test_token_media_2",
                is_active=True,
                is_verified=True,
                user_type="mobile"
            )
            session.add(recipient)
            session.commit()
        
        print(f"✅ Test users created: {sender.username} → {recipient.username}")
        
        # Create test media data
        test_content = b"This is a test encrypted media file content for testing purposes."
        encoded_content = base64.b64encode(test_content).decode('utf-8')
        
        media_data = {
            "filename": "test_photo.jpg",
            "file_size": len(test_content),
            "media_type": "photo",
            "content_type": "image/jpeg",
            "encrypted_content": encoded_content,
            "encryption_metadata": {"algorithm": "AES-256-GCM", "key_length": 256},
            "disappear_after_hours": 24
        }
        
        print("✅ Test media data prepared")
        
        # Test media upload
        import uuid
        media_id = str(uuid.uuid4())
        
        # Create message for the media
        message = Message(
            sender_id=sender.id,
            recipient_id=recipient.id,
            encrypted_content=encoded_content,
            content_type="media/photo",
            delivered=False,
            read=False,
            is_offline=True
        )
        
        session.add(message)
        session.commit()
        session.refresh(message)
        
        print(f"✅ Test message created: {message.id}")
        
        # Create media record
        upload_dir = "media_uploads"
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        encrypted_file_path = os.path.join(upload_dir, f"{media_id}.enc")
        with open(encrypted_file_path, "wb") as f:
            f.write(test_content)
        
        from datetime import datetime, timedelta, timezone
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        media = Media(
            media_id=media_id,
            filename=media_data["filename"],
            file_size=media_data["file_size"],
            media_type=media_data["media_type"],
            content_type=media_data["content_type"],
            encryption_metadata=media_data["encryption_metadata"],
            encrypted_file_path=encrypted_file_path,
            message_id=message.id,
            sender_id=sender.id,
            recipient_id=recipient.id,
            expires_at=expires_at,
            auto_delete=True
        )
        
        session.add(media)
        session.commit()
        session.refresh(media)
        
        print(f"✅ Test media uploaded: {media.media_id}")
        
        # Test media retrieval
        retrieved_media = session.query(Media).filter(Media.id == media.id).first()
        if not retrieved_media:
            print("❌ Failed to retrieve media")
            return False
        
        print(f"✅ Media retrieved successfully: {retrieved_media.filename}")
        
        # Test file reading
        if not os.path.exists(retrieved_media.encrypted_file_path):
            print("❌ Media file not found on disk")
            return False
        
        with open(retrieved_media.encrypted_file_path, "rb") as f:
            file_content = f.read()
        
        if file_content != test_content:
            print("❌ Media file content mismatch")
            return False
        
        print("✅ Media file content verified")
        
        # Test media deletion
        os.remove(retrieved_media.encrypted_file_path)
        session.delete(retrieved_media)
        session.delete(message)
        session.commit()
        
        print("✅ Media cleanup completed")
        
        print("\n🎉 All media feature tests passed!")
        return True
        
    except Exception as e:
        logger.error(f"Media feature test error: {e}")
        print(f"❌ Media feature test failed: {e}")
        return False
    finally:
        session.close()

if __name__ == "__main__":
    success = test_media_feature()
    sys.exit(0 if success else 1)