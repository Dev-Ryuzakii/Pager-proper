"""
Script to recreate database tables with updated schema
"""

import os
import logging

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
from sqlalchemy.exc import ProgrammingError

def recreate_tables():
    """Drop and recreate all database tables"""
    print("🔧 Attempting to recreate database tables...")
    
    try:
        print("🗑️  Dropping all existing tables...")
        Base.metadata.drop_all(bind=engine)
        print("✅ All tables dropped successfully")
    except ProgrammingError as e:
        if "InsufficientPrivilege" in str(e):
            print("⚠️  Insufficient privileges to drop tables. This is common in hosted environments.")
            print("💡 Continuing with table creation only...")
        else:
            print(f"❌ Error dropping tables: {e}")
            print("💡 Continuing with table creation only...")
    except Exception as e:
        print(f"❌ Unexpected error dropping tables: {e}")
        print("💡 Continuing with table creation only...")
    
    try:
        print("🆕 Creating all tables with updated schema...")
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully!")
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = recreate_tables()
    if success:
        print("\n🎉 Database tables recreation completed!")
    else:
        print("\n❌ Database tables recreation failed!")
        exit(1)