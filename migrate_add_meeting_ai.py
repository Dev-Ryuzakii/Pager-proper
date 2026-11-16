#!/usr/bin/env python3
"""
Migration: AI notes columns on meeting_recordings (transcript, summary,
action items, which providers processed it). Idempotent.
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
    ("ai_status", "VARCHAR(20)"),
    ("ai_error", "VARCHAR(255)"),
    ("transcript", "TEXT"),
    ("notes_json", "TEXT"),
    ("ai_providers", "VARCHAR(64)"),
    ("ai_processed_at", "TIMESTAMP"),
]


def run_migration():
    engine = create_engine(DATABASE_URL)
    with engine.begin() as conn:
        for name, ddl in COLUMNS:
            conn.execute(text(f"ALTER TABLE meeting_recordings ADD COLUMN IF NOT EXISTS {name} {ddl}"))
            print(f"ok: meeting_recordings.{name}")
    return True


if __name__ == "__main__":
    run_migration()
