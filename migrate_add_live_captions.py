#!/usr/bin/env python3
"""
Database Migration Script: live meeting transcript tables

- meeting_caption_sessions — one live-transcript run per conference
- meeting_caption_segments — finished utterances (speaker, text, times)

Idempotent: only creates the two tables if they are missing.
"""

import os

from sqlalchemy import create_engine

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
    import live_captions
    from database_models import Base

    engine = create_engine(DATABASE_URL)
    tables = [live_captions.MeetingCaptionSession.__table__, live_captions.MeetingCaptionSegment.__table__]
    Base.metadata.create_all(engine, tables=tables)
    print("Live transcript tables are ready.")


if __name__ == "__main__":
    run_migration()
