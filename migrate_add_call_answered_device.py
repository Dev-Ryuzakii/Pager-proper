"""
Database Migration Script: remember which device answered a call, so the
caller's other devices' call history can show "answered on another device".
"""

import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate():
    engine = create_engine(get_database_url())
    statements = [
        "ALTER TABLE calls ADD COLUMN IF NOT EXISTS answered_device_id VARCHAR(128)",
        "ALTER TABLE calls ADD COLUMN IF NOT EXISTS answered_device_name VARCHAR(120)",
    ]
    with engine.begin() as conn:
        for stmt in statements:
            logger.info(stmt)
            conn.execute(text(stmt))
    logger.info("Migration for call answered device complete.")


if __name__ == "__main__":
    migrate()
