#!/usr/bin/env python3
"""
Database Migration Script: Add waiting-room support

- meetings.waiting_room_enabled — host-set at scheduling time, gates
  /meetings/join_by_code (anyone with the code) for that meeting.
- conference_participants.status — "admitted"/"waiting"/"denied", separate
  from is_active (which already means "invited but hasn't accepted yet" on
  the invite+accept path).
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
            print("\n📌 Adding waiting_room_enabled column to meetings...")
            conn.execute(text("""
                ALTER TABLE meetings
                ADD COLUMN IF NOT EXISTS waiting_room_enabled BOOLEAN DEFAULT FALSE;
            """))
            print("📌 Adding status column to conference_participants...")
            conn.execute(text("""
                ALTER TABLE conference_participants
                ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'admitted';
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
