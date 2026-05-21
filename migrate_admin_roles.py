#!/usr/bin/env python3
"""
Database Migration: Add admin_role column to users table
Roles: 'superadmin', 'admin', 'operator' — null for regular users
Existing is_admin=True users are migrated to role='admin'
"""

import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

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
    print("Running admin_role migration...")
    engine = create_engine(DATABASE_URL)
    with engine.connect() as conn:
        # Add column if not exists
        conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS admin_role VARCHAR(20) DEFAULT NULL;
        """))
        # Migrate existing admins to role='admin'
        conn.execute(text("""
            UPDATE users
            SET admin_role = 'admin'
            WHERE is_admin = TRUE AND admin_role IS NULL;
        """))
        conn.commit()
        result = conn.execute(text("SELECT COUNT(*) FROM users WHERE admin_role IS NOT NULL"))
        count = result.scalar()
        print(f"Migration complete. {count} admin-role users.")

if __name__ == "__main__":
    run_migration()
