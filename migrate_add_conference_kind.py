#!/usr/bin/env python3
"""
Migration: conference_sessions.kind and call_type.

kind is "call" | "group_call" | "meeting". Existing rows are derived from
original_call_id: a conference that was upgraded from a 1:1 call is a call,
everything else (no original call) is a meeting. call_type is copied from
that original call when there is one. Idempotent.
"""

import os
from sqlalchemy import create_engine, text

if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/secure_messaging")

COLUMNS = [
    ("kind", "VARCHAR(20)"),
    ("call_type", "VARCHAR(10)"),
]


def run_migration():
    engine = create_engine(DATABASE_URL)
    with engine.begin() as conn:
        for name, ddl in COLUMNS:
            conn.execute(text(
                f"ALTER TABLE conference_sessions ADD COLUMN IF NOT EXISTS {name} {ddl}"
            ))
            print(f"ok: conference_sessions.{name}")
        conn.execute(text("""
            UPDATE conference_sessions
            SET kind = CASE WHEN original_call_id IS NOT NULL THEN 'call' ELSE 'meeting' END
            WHERE kind IS NULL
        """))
        print("ok: backfilled conference_sessions.kind")
        conn.execute(text("""
            UPDATE conference_sessions AS c
            SET call_type = calls.call_type
            FROM calls
            WHERE c.original_call_id = calls.id
              AND c.call_type IS NULL
              AND calls.call_type IS NOT NULL
        """))
        print("ok: backfilled conference_sessions.call_type from calls")
    return True


if __name__ == "__main__":
    run_migration()
