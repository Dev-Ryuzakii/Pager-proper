"""Account suspension: an admin/operator freezes a user, silently.

Separate from `is_active` so a suspension stays distinguishable from an ordinary
deactivation with a reason attached, and can be reversed on its own. Idempotent
and safe to run before the new backend code is deployed.
"""
import logging

from sqlalchemy import create_engine, text

from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALTER_STATEMENTS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_by INTEGER REFERENCES users(id)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS suspension_reason TEXT",
    "CREATE INDEX IF NOT EXISTS ix_users_suspended_at ON users (suspended_at)",
]


def migrate():
    engine = create_engine(get_database_url())

    logger.info("Adding account-suspension columns to users...")
    with engine.begin() as conn:
        for stmt in ALTER_STATEMENTS:
            logger.info(stmt)
            conn.execute(text(stmt))

    logger.info("Migration for account suspension complete.")


if __name__ == "__main__":
    migrate()
