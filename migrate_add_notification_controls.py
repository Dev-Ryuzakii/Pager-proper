"""
Database Migration Script: Phase 2 notification controls.

Adds quiet-hours + mute-all columns to users. All default to off, so existing
users are unaffected until they set preferences.

Idempotent: ADD COLUMN IF NOT EXISTS.
"""

import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate():
    engine = create_engine(get_database_url())
    with engine.begin() as conn:
        logger.info("Adding user notification-control columns ...")
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS quiet_hours_enabled BOOLEAN DEFAULT FALSE"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS quiet_hours_start INTEGER"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS quiet_hours_end INTEGER"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS quiet_hours_utc_offset INTEGER DEFAULT 0"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mute_all_notifications BOOLEAN DEFAULT FALSE"))
    logger.info("Migration for notification controls complete.")


if __name__ == "__main__":
    migrate()
