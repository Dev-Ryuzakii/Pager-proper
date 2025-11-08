#!/usr/bin/env python3
"""
Robust Database Initialization Script
This script initializes the PostgreSQL database for the Secure Messaging API,
handling permission issues gracefully.
"""

import os
import sys
import logging
from sqlalchemy.exc import ProgrammingError, OperationalError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

from database_models import engine, Base

def init_database_robust():
    """Initialize database with robust error handling"""
    print("🔧 Initializing PostgreSQL database with robust error handling...")
    print("=" * 60)
    
    # Show database URL for debugging
    database_url = os.getenv("DATABASE_URL", "Not set")
    if database_url and len(database_url) > 50:
        # Truncate for display but keep the end which often has important info
        display_url = database_url[:30] + "..." + database_url[-20:]
    else:
        display_url = database_url
    print(f"Database URL: {display_url}")
    
    # Try to create tables
    try:
        print("🆕 Creating database tables...")
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully!")
        return True
    except ProgrammingError as e:
        error_msg = str(e)
        if "InsufficientPrivilege" in error_msg:
            print("⚠️  Insufficient privileges to create tables.")
            print("💡 This might be OK if tables already exist.")
            return True
        elif "already exists" in error_msg:
            print("✅ Tables already exist, which is fine.")
            return True
        else:
            print(f"❌ Programming error creating tables: {e}")
            return False
    except OperationalError as e:
        error_msg = str(e)
        if "could not translate host name" in error_msg:
            print("❌ Database connection failed - hostname could not be resolved.")
            print("💡 Check your DATABASE_URL environment variable.")
            return False
        elif "connection refused" in error_msg:
            print("❌ Database connection refused.")
            print("💡 Check if your database is running and accessible.")
            return False
        else:
            print(f"❌ Operational error creating tables: {e}")
            return False
    except Exception as e:
        print(f"❌ Unexpected error creating tables: {e}")
        return False

def test_database_connection():
    """Test database connection"""
    print("🧪 Testing database connection...")
    
    try:
        # Try a simple query
        with engine.connect() as connection:
            from sqlalchemy import text
            result = connection.execute(text("SELECT 1"))
            print("✅ Database connection test successful!")
            return True
    except Exception as e:
        print(f"❌ Database connection test failed: {e}")
        return False

def main():
    """Main function"""
    print("🚀 Secure Messaging API Database Initialization")
    print("=" * 60)
    
    # Test connection first
    if not test_database_connection():
        return 1
    
    # Initialize database
    if not init_database_robust():
        return 1
    
    print("\n🎉 Database initialization completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())