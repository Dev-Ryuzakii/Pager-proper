#!/usr/bin/env python3
"""
Database Initialization Script
This script initializes the PostgreSQL database for the Secure Messaging API.
"""

import os
import sys
import logging
from database_config import db_config, init_database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Initialize the database"""
    print("🔧 Initializing PostgreSQL database...")
    print("=" * 50)
    
    # Show configuration
    if hasattr(db_config, 'DATABASE_URL'):
        print(f"Database URL: {db_config.DATABASE_URL}")
    
    # Initialize database with retry logic
    try:
        success = init_database(max_retries=5, retry_delay=10)
        
        if success:
            print("\n🎉 Database initialization completed successfully!")
            print("You can now use PostgreSQL with your secure messaging system.")
            return 0
        else:
            print("\n❌ Database initialization failed after multiple attempts!")
            return 1
            
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        print(f"\n❌ Database initialization failed with error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())