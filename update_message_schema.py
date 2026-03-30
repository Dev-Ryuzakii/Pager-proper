
import os
from sqlalchemy import create_engine, text
from database_config import DatabaseConfig

def update_schema():
    config = DatabaseConfig()
    database_url = config.DATABASE_URL
    
    print(f"Connecting to database: {database_url}")
    engine = create_engine(database_url)
    
    with engine.connect() as conn:
        print("Checking for missing columns in 'messages' table...")
        
        # Add is_admin_announcement
        try:
            conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_admin_announcement BOOLEAN DEFAULT FALSE"))
            conn.commit()
            print("✅ Column 'is_admin_announcement' added or already exists.")
        except Exception as e:
            print(f"❌ Error adding 'is_admin_announcement': {e}")
            
        # Add is_broadcast
        try:
            conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_broadcast BOOLEAN DEFAULT FALSE"))
            conn.commit()
            print("✅ Column 'is_broadcast' added or already exists.")
        except Exception as e:
            print(f"❌ Error adding 'is_broadcast': {e}")
            
    print("Schema update complete.")

if __name__ == "__main__":
    update_schema()
