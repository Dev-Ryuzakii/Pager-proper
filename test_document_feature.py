#!/usr/bin/env python3
"""
Test for Document Feature
This script tests the document upload and download functionality.
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

def test_document_feature():
    """Test the document feature functionality"""
    print("🧪 Testing Document Feature")
    print("=" * 50)
    
    # Get database session
    session = db_config.get_session()
    if not session:
        print("❌ Failed to get database session")
        return False
    
    try:
        # Create test users if they don't exist
        sender = session.query(User).filter(User.username == "test_document_sender").first()
        if not sender:
            sender = User(
                username="test_document_sender",
                token="test_token_document_1",
                is_active=True,
                is_verified=True,
                user_type="mobile"
            )
            session.add(sender)
            session.commit()
        
        recipient = session.query(User).filter(User.username == "test_document_recipient").first()
        if not recipient:
            recipient = User(
                username="test_document_recipient",
                token="test_token_document_2",
                is_active=True,
                is_verified=True,
                user_type="mobile"
            )
            session.add(recipient)
            session.commit()
        
        print(f"✅ Test users created: {sender.username} → {recipient.username}")
        
        # Create test document data
        test_content = b"This is a test encrypted document file content for testing purposes."
        encoded_content = base64.b64encode(test_content).decode('utf-8')
        
        document_data = {
            "filename": "test_document.pdf",
            "file_size": len(test_content),
            "media_type": "document",
            "content_type": "application/pdf",
            "encrypted_content": encoded_content,
            "encryption_metadata": {"algorithm": "AES-256-GCM", "key_length": 256},
            "disappear_after_hours": 24
        }
        
        print("✅ Test document data prepared")
        
        # Test document upload
        import uuid
        media_id = str(uuid.uuid4())
        
        # Create message for the document
        message = Message(
            sender_id=sender.id,
            recipient_id=recipient.id,
            encrypted_content=encoded_content,
            content_type="media/document",
            delivered=False,
            read=False,
            is_offline=True
        )
        
        session.add(message)
        session.commit()
        session.refresh(message)
        
        print(f"✅ Test message created: {message.id}")
        
        # Create document record
        upload_dir = "media_uploads"
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        encrypted_file_path = os.path.join(upload_dir, f"{media_id}.enc")
        with open(encrypted_file_path, "wb") as f:
            f.write(test_content)
        
        from datetime import datetime, timedelta, timezone
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        document = Media(
            media_id=media_id,
            filename=document_data["filename"],
            file_size=document_data["file_size"],
            media_type=document_data["media_type"],
            content_type=document_data["content_type"],
            encryption_metadata=document_data["encryption_metadata"],
            encrypted_file_path=encrypted_file_path,
            message_id=message.id,
            sender_id=sender.id,
            recipient_id=recipient.id,
            expires_at=expires_at,
            auto_delete=True
        )
        
        session.add(document)
        session.commit()
        session.refresh(document)
        
        print(f"✅ Test document uploaded: {document.media_id}")
        
        # Test document retrieval
        retrieved_document = session.query(Media).filter(Media.id == document.id).first()
        if not retrieved_document:
            print("❌ Failed to retrieve document")
            return False
        
        print(f"✅ Document retrieved successfully: {retrieved_document.filename}")
        
        # Test file reading
        if not os.path.exists(retrieved_document.encrypted_file_path):
            print("❌ Document file not found on disk")
            return False
        
        with open(retrieved_document.encrypted_file_path, "rb") as f:
            file_content = f.read()
        
        if file_content != test_content:
            print("❌ Document file content mismatch")
            return False
        
        print("✅ Document file content verified")
        
        # Test document deletion
        os.remove(retrieved_document.encrypted_file_path)
        session.delete(retrieved_document)
        session.delete(message)
        session.commit()
        
        print("✅ Document cleanup completed")
        
        print("\n🎉 All document feature tests passed!")
        return True
        
    except Exception as e:
        logger.error(f"Document feature test error: {e}")
        print(f"❌ Document feature test failed: {e}")
        return False
    finally:
        session.close()

if __name__ == "__main__":
    success = test_document_feature()
    sys.exit(0 if success else 1)