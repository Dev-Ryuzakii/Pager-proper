"""
Database Migration Script: Google Calendar two-way sync.

Adds the granted OAuth scope to existing links (so read-only links can be
told apart from write-capable ones and prompted to re-link) and the mapping
table that ties a Dilarion meeting/task to its Google Calendar event, so a
reschedule patches the same event instead of duplicating it.
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
        "ALTER TABLE google_calendar_links ADD COLUMN IF NOT EXISTS granted_scope TEXT",
        """
        CREATE TABLE IF NOT EXISTS google_calendar_event_links (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            source_type VARCHAR(20) NOT NULL,
            source_id INTEGER NOT NULL,
            google_event_id VARCHAR(1024) NOT NULL,
            calendar_id VARCHAR(255) DEFAULT 'primary',
            updated_at TIMESTAMP DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_google_calendar_event_links_user_id ON google_calendar_event_links (user_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_google_event_link_source ON google_calendar_event_links (user_id, source_type, source_id)",
    ]
    with engine.begin() as conn:
        for stmt in statements:
            logger.info(stmt.split("\n")[1].strip() if "\n" in stmt else stmt)
            conn.execute(text(stmt))

    logger.info("Migration for Google Calendar two-way sync complete.")


if __name__ == "__main__":
    migrate()
