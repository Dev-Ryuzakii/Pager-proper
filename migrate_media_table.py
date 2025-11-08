#!/usr/bin/env python3
"""
Migration Script: Add Media Table to PostgreSQL Database
Supports photos, videos, and document files
"""

import os
import sys
import logging
from sqlalchemy import text
from database_config import db_config
from database_models import Media, Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_media_table():
    """Add Media table to the database"""
    print("🔧 Migrating Media Table to PostgreSQL Database")
    print("=" * 50)
    
    try:
        # Initialize database connection
        if not db_config.initialize_database():
            print("❌ Failed to initialize database connection")
            return False
        
        # Get database engine
        engine = db_config.engine
        if not engine:
            print("❌ Database engine not available")
            return False
        
        # Create Media table
        print("📋 Creating Media table...")
        Media.__table__.create(engine, checkfirst=True)
        print("✅ Media table created successfully!")
        
        # Verify table creation
        print("🔍 Verifying table creation...")
        with engine.connect() as connection:
            result = connection.execute(text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'media');"))
            exists = result.fetchone()[0]
            
            if exists:
                print("✅ Media table verified in database")
                print("\n🎉 Media table migration completed successfully!")
                return True
            else:
                print("❌ Media table not found in database")
                return False
                
    except Exception as e:
        logger.error(f"Migration error: {e}")
        print(f"❌ Media table migration failed: {e}")
        return False

if __name__ == "__main__":
    success = migrate_media_table()
    sys.exit(0 if success else 1)