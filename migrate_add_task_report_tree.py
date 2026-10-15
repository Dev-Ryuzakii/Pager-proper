"""
Database Migration Script: breakout report tree.

Adds tasks.compiled_sections — the AI-compiled report split into sections,
each tagged with the breakout team(s) it came from. Null on existing tasks
until they're (re)compiled; the apps still show the team/staff tree for them,
just without per-section attribution.

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
        logger.info("Adding tasks.compiled_sections ...")
        conn.execute(text("ALTER TABLE tasks ADD COLUMN IF NOT EXISTS compiled_sections TEXT"))
    logger.info("Migration for task report tree complete.")


if __name__ == "__main__":
    migrate()
