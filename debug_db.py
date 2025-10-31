#!/usr/bin/env python3
"""
Database Debug Script
This script helps debug database connection issues.
"""

import os
import sys
import logging
from database_config import db_config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Debug the database connection"""
    print("🔍 Debugging PostgreSQL Database Connection")
    print("=" * 50)
    
    # Show all environment variables
    print("All environment variables:")
    for key, value in sorted(os.environ.items()):
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 50)
    
    # Show database configuration
    print("Database Configuration:")
    print(f"  DATABASE_URL: {getattr(db_config, 'DATABASE_URL', 'Not set')}")
    
    if hasattr(db_config, 'DB_HOST'):
        print(f"  DB_HOST: {db_config.DB_HOST}")
        print(f"  DB_PORT: {db_config.DB_PORT}")
        print(f"  DB_NAME: {db_config.DB_NAME}")
        print(f"  DB_USER: {db_config.DB_USER}")
    
    print(f"  POOL_SIZE: {db_config.POOL_SIZE}")
    print(f"  MAX_OVERFLOW: {db_config.MAX_OVERFLOW}")
    
    # Test connection
    print("\n" + "=" * 50)
    print("Testing database connection...")
    
    try:
        success = db_config.initialize_database(max_retries=1, retry_delay=1)
        if success:
            print("✅ Database initialization successful")
            
            test_success = db_config.test_connection(max_retries=1, retry_delay=1)
            if test_success:
                print("✅ Database connection test successful")
            else:
                print("❌ Database connection test failed")
        else:
            print("❌ Database initialization failed")
    except Exception as e:
        logger.error(f"Database test error: {e}")
        print(f"❌ Database test failed with error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())