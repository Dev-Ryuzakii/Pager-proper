#!/usr/bin/env python3
"""
Background Cleanup Task
Runs periodic cleanup of expired disappearing messages.
This script should be run as a separate process or cron job.
"""

import os
import sys
import time
import logging
from message_cleanup import run_cleanup_continuously

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main function to run the background cleanup task"""
    logger.info("🚀 Starting background message cleanup task")
    
    # Get cleanup interval from environment variable or default to 1 hour
    interval_seconds = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "3600"))
    
    try:
        # Run cleanup continuously
        run_cleanup_continuously(interval_seconds)
    except Exception as e:
        logger.error(f"Fatal error in background cleanup: {e}")
        return 1
    
    logger.info("👋 Background cleanup task stopped")
    return 0

if __name__ == "__main__":
    sys.exit(main())