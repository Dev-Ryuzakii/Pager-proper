"""
Database Migration Script: self-service groups — invite link code and the
group-wide disappearing-message timer. Group creation/editing no longer
needs a site admin; no schema change was needed for that part.
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
        "ALTER TABLE groups ADD COLUMN IF NOT EXISTS invite_code VARCHAR(64)",
        "ALTER TABLE groups ADD COLUMN IF NOT EXISTS disappear_after_hours INTEGER",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_groups_invite_code ON groups (invite_code)",
    ]
    with engine.begin() as conn:
        for stmt in statements:
            logger.info(stmt)
            conn.execute(text(stmt))

    logger.info("Migration for self-service groups complete.")


if __name__ == "__main__":
    migrate()
