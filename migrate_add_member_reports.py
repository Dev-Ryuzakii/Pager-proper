"""
Database Migration Script: per-staff breakout reports.

Breakout task reports move from one shared report per team (TaskGroup.report_text)
to one report per staff member (task_group_members.report_text). Adds the two
per-member columns. Existing team reports stay where they are; the new columns
default to NULL so nothing breaks for tasks compiled before this change.

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
        logger.info("Adding per-staff report columns to task_group_members ...")
        conn.execute(text("ALTER TABLE task_group_members ADD COLUMN IF NOT EXISTS report_text TEXT"))
        conn.execute(text("ALTER TABLE task_group_members ADD COLUMN IF NOT EXISTS report_submitted_at TIMESTAMP"))
    logger.info("Migration for per-staff breakout reports complete.")


if __name__ == "__main__":
    migrate()
