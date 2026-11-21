#!/usr/bin/env python3
"""
Database Migration Script: user bio

Adds users.bio (VARCHAR(300), nullable): a short "about" line each user writes
for themselves, shown under their name in chat headers.

Idempotent: safe to run more than once.
"""

import os

from sqlalchemy import create_engine, text

if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ.setdefault(key, value)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost:5432/secure_messaging"
)


def run_migration():
    engine = create_engine(DATABASE_URL)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS bio VARCHAR(300)"))
    print("users.bio is ready.")


if __name__ == "__main__":
    run_migration()
