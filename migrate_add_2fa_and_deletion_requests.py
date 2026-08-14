#!/usr/bin/env python3
"""
Database Migration Script: Master-token 2FA + account deletion requests

- users gains mastertoken_2fa_enabled/hash/salt.
- account_deletion_requests: self-service request, admin approve/deny.
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
            print("\n📌 Adding master-token 2FA columns to users...")
            conn.execute(text("""
                ALTER TABLE users
                ADD COLUMN IF NOT EXISTS mastertoken_2fa_enabled BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS mastertoken_2fa_hash VARCHAR(255),
                ADD COLUMN IF NOT EXISTS mastertoken_2fa_salt VARCHAR(255);
            """))

            print("📌 Creating account_deletion_requests table...")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS account_deletion_requests (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    reason TEXT,
                    status VARCHAR(20) DEFAULT 'pending',
                    requested_at TIMESTAMP DEFAULT NOW(),
                    processed_by_id INTEGER REFERENCES users(id),
                    processed_at TIMESTAMP
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
