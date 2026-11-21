#!/usr/bin/env python3
"""
Database Migration Script: sign-in approval requests

Creates login_requests: a new device's pending sign-in, approved from an
already signed-in device, the email link or the master token.

Idempotent: only creates the table if it is missing.
"""

import os

from sqlalchemy import create_engine

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
    import login_approval
    from database_models import Base

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine, tables=[login_approval.LoginRequest.__table__])
    print("Sign-in approval table is ready.")


if __name__ == "__main__":
    run_migration()
