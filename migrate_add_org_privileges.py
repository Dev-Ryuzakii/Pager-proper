"""
Database Migration Script: per-staff org-wide admin privileges.

Adds users.org_privileges (JSON). Null/empty = ordinary member; a list such
as ["broadcast","assign_tasks","call_control"] grants org-wide powers the
organization account delegated. The organization account itself needs no row
here — it implicitly holds every privilege.

Idempotent: ADD COLUMN IF NOT EXISTS.
"""

import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate():
    url = get_database_url()
    engine = create_engine(url)
    with engine.begin() as conn:
        logger.info("Adding users.org_privileges ...")
        conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS org_privileges JSON"
        ))
    logger.info("Creating org_announcements (and any other new tables) ...")
    Base.metadata.create_all(bind=engine)
    logger.info("Migration for org privileges complete.")


if __name__ == "__main__":
    migrate()
