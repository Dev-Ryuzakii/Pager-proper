"""
Database Migration Script: self-service account recovery code column, plus
username change support (no schema change needed there — username was
already a plain unique column, this just documents that it's mutable now).
"""

import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate():
    url = get_database_url()
    engine = create_engine(url)

    with engine.begin() as conn:
        stmt = "ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_code_hash VARCHAR(255)"
        logger.info(stmt)
        conn.execute(text(stmt))

    logger.info("Migration for recovery codes complete.")


if __name__ == "__main__":
    migrate()
