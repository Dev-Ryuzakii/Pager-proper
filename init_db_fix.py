import os
import sys

# Load .env BEFORE any other imports that might use it
if os.path.exists('.env'):
    with open('.env') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                parts = line.strip().split('=', 1)
                if len(parts) == 2:
                    key, value = parts
                    os.environ[key] = value

# Now we can import database_config
from database_config import DatabaseConfig, Base

if __name__ == "__main__":
    db_config = DatabaseConfig()
    print(f"Using DATABASE_URL: {db_config.DATABASE_URL.replace(os.getenv('DB_PASSWORD', ''), '***')}")
    
    if db_config.initialize_database():
        Base.metadata.create_all(bind=db_config.engine)
        print("✅ Database tables (including groups and group_members) created successfully!")
    else:
        print("❌ Failed to initialize database.")
        sys.exit(1)
