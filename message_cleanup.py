#!/usr/bin/env python3
"""
Message Cleanup Utility
Handles automatic cleanup of expired disappearing messages.
"""

import os
import sys
import time
import logging
from datetime import datetime, timezone
from sqlalchemy import and_
from sqlalchemy.orm import Session
from database_config import db_config
from database_models import Message

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def cleanup_expired_messages(session: Session) -> int:
    """
    Delete expired messages from the database.
    
    Args:
        session: Database session
        
    Returns:
        Number of deleted messages
    """
    try:
        current_time = datetime.now(timezone.utc)
        expired_messages = session.query(Message).filter(
            and_(
                Message.auto_delete == True,
                Message.expires_at <= current_time
            )
        ).all()
        
        deleted_count = len(expired_messages)
        
        # Delete expired messages
        for message in expired_messages:
            session.delete(message)
        
        if deleted_count > 0:
            session.commit()
            logger.info(f"🗑️  Deleted {deleted_count} expired messages")
        
        return deleted_count
        
    except Exception as e:
        logger.error(f"Error cleaning up expired messages: {e}")
        session.rollback()
        return 0

def run_cleanup_once() -> int:
    """
    Run message cleanup once and return the number of deleted messages.
    
    Returns:
        Number of deleted messages
    """
    try:
        # Get database session
        session = db_config.get_session()
        if not session:
            logger.error("Failed to get database session")
            return 0
            
        try:
            deleted_count = cleanup_expired_messages(session)
            return deleted_count
        finally:
            session.close()
            
    except Exception as e:
        logger.error(f"Error running cleanup: {e}")
        return 0

def run_cleanup_continuously(interval_seconds: int = 3600) -> None:
    """
    Run message cleanup continuously at specified intervals.
    
    Args:
        interval_seconds: Interval between cleanup runs in seconds (default: 3600 = 1 hour)
    """
    logger.info(f"🔄 Starting continuous message cleanup (every {interval_seconds} seconds)")
    
    while True:
        try:
            deleted_count = run_cleanup_once()
            if deleted_count > 0:
                logger.info(f"🧹 Cleanup completed: {deleted_count} messages deleted")
            else:
                logger.info("🔍 Cleanup completed: No expired messages found")
                
            # Wait for next cleanup
            time.sleep(interval_seconds)
            
        except KeyboardInterrupt:
            logger.info("🛑 Cleanup process interrupted by user")
            break
        except Exception as e:
            logger.error(f"Error in cleanup loop: {e}")
            # Wait before retrying
            time.sleep(60)

if __name__ == "__main__":
    # Run cleanup once if called directly
    logger.info("🧹 Running message cleanup...")
    deleted_count = run_cleanup_once()
    logger.info(f"✅ Cleanup completed: {deleted_count} messages deleted")
    sys.exit(0)