"""
Participant meeting notes: speaker segments and the org auto-run switch.
Transcript text already lives on meeting_recordings. Idempotent.
"""

import logging

from sqlalchemy import create_engine, text

from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATEMENTS = [
    "ALTER TABLE meeting_recordings ADD COLUMN IF NOT EXISTS transcript_segments JSON",
    "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS auto_meeting_notes BOOLEAN DEFAULT FALSE",
]


def migrate():
    engine = create_engine(get_database_url())
    with engine.begin() as conn:
        for stmt in STATEMENTS:
            logger.info(stmt)
            conn.execute(text(stmt))
    logger.info("Meeting notes access migration complete.")


if __name__ == "__main__":
    migrate()
