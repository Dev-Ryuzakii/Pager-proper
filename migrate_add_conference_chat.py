#!/usr/bin/env python3
"""
Database Migration Script: Add in-meeting chat support

- messages.conference_id — nullable FK to conference_sessions.id. Reuses the
  existing encrypted_content/decoy_content/encrypted_key/iv columns, so
  meeting chat gets the same master-token decoy/unlock model as DMs and
  group chat for free.
"""

import os
from sqlalchemy import create_engine, text

if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost:5432/secure_messaging"
)


def run_migration():
    print("🔧 Starting database migration...")
    print(f"📊 Database: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else 'local'}")

    engine = create_engine(DATABASE_URL, echo=True)

    with engine.connect() as conn:
        trans = conn.begin()
        try:
            print("\n📌 Adding conference_id column to messages...")
            conn.execute(text("""
                ALTER TABLE messages
                ADD COLUMN IF NOT EXISTS conference_id INTEGER REFERENCES conference_sessions(id);
            """))
            trans.commit()
            print("✅ Migration completed successfully!")
            return True
        except Exception as e:
            trans.rollback()
            print(f"❌ Migration failed: {e}")
            return False


if __name__ == "__main__":
    import sys
    success = run_migration()
    sys.exit(0 if success else 1)
