#!/usr/bin/env python3
"""
Database Connection Test Script
This script tests the PostgreSQL database connection for the Secure Messaging API.
"""

import os
import sys
import logging
from database_config import db_config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Test the database connection"""
    print("🧪 Testing PostgreSQL Database Connection")
    print("=" * 50)
    
    # Show configuration
    if hasattr(db_config, 'DATABASE_URL'):
        print(f"Database URL: {db_config.DATABASE_URL}")
    
    # Test connection
    try:
        print("🔌 Testing database connection...")
        success = db_config.test_connection()
        
        if success:
            print("\n✅ Database connection test successful!")
            return 0
        else:
            print("\n❌ Database connection test failed!")
            return 1
            
    except Exception as e:
        logger.error(f"Database connection test error: {e}")
        print(f"\n❌ Database connection test failed with error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())