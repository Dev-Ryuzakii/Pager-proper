"""
Database Migration Script: device-bound sessions (one signed-in device per
platform) and call answer time (accurate call duration in history).
"""

import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate():
    url = get_database_url()
    engine = create_engine(url)

    statements = [
        "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_id VARCHAR(128)",
        "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_name VARCHAR(120)",
        "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS platform VARCHAR(20)",
        "CREATE INDEX IF NOT EXISTS ix_user_sessions_device_id ON user_sessions (device_id)",
        "ALTER TABLE calls ADD COLUMN IF NOT EXISTS answered_at TIMESTAMP",
    ]
    with engine.begin() as conn:
        for stmt in statements:
            logger.info(stmt)
            conn.execute(text(stmt))

    logger.info("Migration for device sessions and call answer time complete.")


if __name__ == "__main__":
    migrate()
