#!/usr/bin/env python3
"""
Database Migration Script: Add meeting_recordings table

Backs the new superadmin Drive site's recording list — a LiveKit Egress
room-composite recording of a conference, stored on local disk.
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
            print("\n📌 Creating meeting_recordings table...")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS meeting_recordings (
                    id SERIAL PRIMARY KEY,
                    conference_id INTEGER NOT NULL REFERENCES conference_sessions(id),
                    started_by_user_id INTEGER NOT NULL REFERENCES users(id),
                    egress_id VARCHAR(64) NOT NULL,
                    file_path VARCHAR(512),
                    status VARCHAR(20) DEFAULT 'recording',
                    file_size INTEGER,
                    started_at TIMESTAMP DEFAULT NOW(),
                    ended_at TIMESTAMP
                );
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
