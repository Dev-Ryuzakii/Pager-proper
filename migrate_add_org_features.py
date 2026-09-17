"""
Database Migration Script: personal calendar plans, Google Calendar linking,
task management (including breakout sub-groups), meeting breakout rooms,
password reset requests, profile pictures, and availability status.

Mostly new tables (Base.metadata.create_all() picks those up), plus a handful
of new columns on the existing conference_sessions/tasks/users tables.
"""

import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALTER_STATEMENTS = [
    "ALTER TABLE conference_sessions ADD COLUMN IF NOT EXISTS parent_conference_id INTEGER REFERENCES conference_sessions(id)",
    "ALTER TABLE conference_sessions ADD COLUMN IF NOT EXISTS breakout_name VARCHAR(100)",
    "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS recurrence VARCHAR(20)",
    "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS reminder_sent BOOLEAN DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture_path VARCHAR(512)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS availability_status VARCHAR(20) DEFAULT 'available'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS status_text VARCHAR(100)",
]


def migrate():
    url = get_database_url()
    engine = create_engine(url)

    logger.info("Creating personal_plans, google_calendar_links, tasks, "
                "task_assignees, task_groups, task_group_members (and any "
                "other new tables)...")
    Base.metadata.create_all(bind=engine)

    logger.info("Applying breakout-room columns to conference_sessions...")
    with engine.begin() as conn:
        for stmt in ALTER_STATEMENTS:
            logger.info(stmt)
            conn.execute(text(stmt))

    logger.info("Migration for org features complete.")


if __name__ == "__main__":
    migrate()
