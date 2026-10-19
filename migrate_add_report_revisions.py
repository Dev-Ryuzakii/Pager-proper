"""
Database Migration Script: report revision history ("branch tree").

Adds task_member_report_revisions — one row per (re)submission of a staff
member's breakout report, so the apps can show how a report evolved over time.

Idempotent: CREATE TABLE IF NOT EXISTS.
"""

import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate():
    engine = create_engine(get_database_url())
    with engine.begin() as conn:
        logger.info("Creating task_member_report_revisions ...")
        conn.execute(text(
            """
            CREATE TABLE IF NOT EXISTS task_member_report_revisions (
                id SERIAL PRIMARY KEY,
                task_group_member_id INTEGER NOT NULL REFERENCES task_group_members(id),
                report_text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
            """
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_report_rev_member ON task_member_report_revisions (task_group_member_id)"
        ))
    logger.info("Migration for report revisions complete.")


if __name__ == "__main__":
    migrate()
