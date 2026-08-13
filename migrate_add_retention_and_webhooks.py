#!/usr/bin/env python3
"""
Database Migration Script: Retention policy + webhooks

- retention_policy: single global row, superadmin-set auto-delete window.
- webhooks: superadmin-managed outbound event subscriptions.
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
            print("\n📌 Creating retention_policy table...")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS retention_policy (
                    id SERIAL PRIMARY KEY,
                    auto_delete_days INTEGER,
                    updated_by_id INTEGER REFERENCES users(id),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """))

            print("📌 Creating webhooks table...")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS webhooks (
                    id SERIAL PRIMARY KEY,
                    created_by_id INTEGER NOT NULL REFERENCES users(id),
                    url VARCHAR(512) NOT NULL,
                    secret VARCHAR(64) NOT NULL,
                    event_types JSON NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    last_triggered_at TIMESTAMP,
                    last_status_code INTEGER,
                    failure_count INTEGER DEFAULT 0
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
