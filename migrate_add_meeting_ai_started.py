"""When a notes job was claimed, so a restart can fail a stuck processing row. Idempotent."""

import logging

from sqlalchemy import create_engine, text

from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATEMENTS = [
    "ALTER TABLE meeting_recordings ADD COLUMN IF NOT EXISTS ai_started_at TIMESTAMP",
]


def migrate():
    engine = create_engine(get_database_url())
    with engine.begin() as conn:
        for stmt in STATEMENTS:
            logger.info(stmt)
            conn.execute(text(stmt))
    logger.info("Meeting AI start-time migration complete.")


if __name__ == "__main__":
    migrate()
