"""
Script to recreate database tables with updated schema
"""

import os

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

from database_models import engine, Base

def recreate_tables():
    """Drop and recreate all database tables"""
    print("🗑️  Dropping all existing tables...")
    Base.metadata.drop_all(bind=engine)
    
    print("🆕 Creating all tables with updated schema...")
    Base.metadata.create_all(bind=engine)
    
    print("✅ Database tables recreated successfully!")

if __name__ == "__main__":
    recreate_tables()