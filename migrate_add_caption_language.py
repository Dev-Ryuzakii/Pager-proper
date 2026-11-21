#!/usr/bin/env python3
"""
Database Migration Script: live transcript language

Adds meeting_caption_sessions.language (VARCHAR(10), NULL = detect
automatically) so the host can pick the spoken language.

Idempotent: safe to run more than once. Creates the caption tables first if
they don't exist yet.
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
    import live_captions
    from database_models import Base

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine, tables=[
        live_captions.MeetingCaptionSession.__table__,
        live_captions.MeetingCaptionSegment.__table__,
    ])
    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE meeting_caption_sessions ADD COLUMN IF NOT EXISTS language VARCHAR(10)"
        ))
    print("Live transcript language column is ready.")


if __name__ == "__main__":
    run_migration()
