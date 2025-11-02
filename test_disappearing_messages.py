#!/usr/bin/env python3
"""
Test for Disappearing Messages Feature
This script tests the disappearing messages functionality.
"""

import os
import sys
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from database_config import db_config
from database_models import Message, User
from message_cleanup import cleanup_expired_messages

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_disappearing_messages():
    """Test the disappearing messages functionality"""
    print("🧪 Testing Disappearing Messages Feature")
    print("=" * 50)
    
    # Get database session
    session = db_config.get_session()
    if not session:
        print("❌ Failed to get database session")
        return False
    
    try:
        # Create test users if they don't exist
        sender = session.query(User).filter(User.username == "test_sender").first()
        if not sender:
            sender = User(
                username="test_sender",
                token="test_token_1",
                is_active=True,
                is_verified=True,
                user_type="mobile"
            )
            session.add(sender)
        
        recipient = session.query(User).filter(User.username == "test_recipient").first()
        if not recipient:
            recipient = User(
                username="test_recipient",
                token="test_token_2",
                is_active=True,
                is_verified=True,
                user_type="mobile"
            )
            session.add(recipient)
        
        session.commit()
        
        # Create a regular message
        regular_message = Message(
            sender_id=sender.id,
            recipient_id=recipient.id,
            encrypted_content="This is a regular message",
            content_type="text",
            auto_delete=False
        )
        session.add(regular_message)
        
        # Create a disappearing message that expires in 1 hour
        future_expiration = datetime.now(timezone.utc) + timedelta(hours=1)
        disappearing_message = Message(
            sender_id=sender.id,
            recipient_id=recipient.id,
            encrypted_content="This is a disappearing message",
            content_type="text",
            auto_delete=True,
            expires_at=future_expiration
        )
        session.add(disappearing_message)
        
        # Create an expired message
        past_expiration = datetime.now(timezone.utc) - timedelta(hours=1)
        expired_message = Message(
            sender_id=sender.id,
            recipient_id=recipient.id,
            encrypted_content="This is an expired message",
            content_type="text",
            auto_delete=True,
            expires_at=past_expiration
        )
        session.add(expired_message)
        
        session.commit()
        
        print(f"✅ Created test messages:")
        print(f"  - Regular message ID: {regular_message.id}")
        print(f"  - Disappearing message ID: {disappearing_message.id} (expires at {disappearing_message.expires_at})")
        print(f"  - Expired message ID: {expired_message.id} (expired at {expired_message.expires_at})")
        
        # Test cleanup function
        print("\n🧹 Testing cleanup function...")
        deleted_count = cleanup_expired_messages(session)
        
        if deleted_count == 1:
            print(f"✅ Cleanup successful: {deleted_count} expired message deleted")
        else:
            print(f"❌ Cleanup failed: Expected 1 deleted message, got {deleted_count}")
            return False
        
        # Verify that the expired message was deleted
        deleted_message = session.query(Message).filter(Message.id == expired_message.id).first()
        if deleted_message is None:
            print("✅ Expired message was successfully deleted")
        else:
            print("❌ Expired message was not deleted")
            return False
        
        # Verify that other messages still exist
        remaining_messages = session.query(Message).filter(
            Message.id.in_([regular_message.id, disappearing_message.id])
        ).count()
        
        if remaining_messages == 2:
            print("✅ Regular and disappearing messages still exist")
        else:
            print(f"❌ Expected 2 remaining messages, found {remaining_messages}")
            return False
        
        print("\n🎉 All tests passed!")
        return True
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        print(f"❌ Test failed with error: {e}")
        return False
    finally:
        session.close()

if __name__ == "__main__":
    success = test_disappearing_messages()
    sys.exit(0 if success else 1)