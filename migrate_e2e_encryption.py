import os
import sys
import psycopg2
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def migrate_db():
    database_url = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/secure_messaging")
    print(f"Connecting to {database_url}...")
    
    # Parse the URL to get components
    result = urlparse(database_url)
    username = result.username
    password = result.password
    database = result.path[1:]
    hostname = result.hostname
    port = result.port
    
    try:
        conn = psycopg2.connect(
            database=database,
            user=username,
            password=password,
            host=hostname,
            port=port
        )
        cur = conn.cursor()
        
        # Check if columns exist and add them
        
        # 1. encrypted_key
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='messages' AND column_name='encrypted_key';")
        if not cur.fetchone():
            print("Adding encrypted_key column to messages table...")
            cur.execute("ALTER TABLE messages ADD COLUMN encrypted_key TEXT;")
        else:
            print("encrypted_key column already exists.")
            
        # 2. iv
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='messages' AND column_name='iv';")
        if not cur.fetchone():
            print("Adding iv column to messages table...")
            cur.execute("ALTER TABLE messages ADD COLUMN iv VARCHAR(255);")
        else:
            print("iv column already exists.")
            
        conn.commit()
        cur.close()
        conn.close()
        print("✅ Migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        sys.exit(1)

if __name__ == "__main__":
    migrate_db()
