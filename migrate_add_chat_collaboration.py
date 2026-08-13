#!/usr/bin/env python3
"""
Database Migration Script: Chat collaboration layer

Adds reply-to, forward-label, edit, soft-delete, pin, and @mention columns
to messages, plus new message_reactions and starred_messages tables.
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
            print("\n📌 Adding collaboration columns to messages...")
            conn.execute(text("""
                ALTER TABLE messages
                ADD COLUMN IF NOT EXISTS reply_to_message_id INTEGER REFERENCES messages(id),
                ADD COLUMN IF NOT EXISTS forwarded_from_message_id INTEGER REFERENCES messages(id),
                ADD COLUMN IF NOT EXISTS is_edited BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS edited_at TIMESTAMP,
                ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP,
                ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS pinned_by_id INTEGER REFERENCES users(id),
                ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMP,
                ADD COLUMN IF NOT EXISTS mentions JSON;
            """))

            print("📌 Creating message_reactions table...")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS message_reactions (
                    id SERIAL PRIMARY KEY,
                    message_id INTEGER NOT NULL REFERENCES messages(id),
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    emoji VARCHAR(16) NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    CONSTRAINT uq_message_reaction UNIQUE (message_id, user_id, emoji)
                );
            """))

            print("📌 Creating starred_messages table...")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS starred_messages (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    message_id INTEGER NOT NULL REFERENCES messages(id),
                    created_at TIMESTAMP DEFAULT NOW(),
                    CONSTRAINT uq_starred_message UNIQUE (user_id, message_id)
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
