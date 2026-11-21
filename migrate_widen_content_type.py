"""
Widen messages.content_type and media.content_type to VARCHAR(255).

Office MIME types are longer than the old limits, e.g. a .docx is
"application/vnd.openxmlformats-officedocument.wordprocessingml.document"
(71 characters), so sending a Word document failed with
"value too long for type character varying(50)". Widening a VARCHAR keeps
every existing row as it is. Safe to run more than once.
"""

import logging

from sqlalchemy import create_engine, text

from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATEMENTS = [
    "ALTER TABLE messages ALTER COLUMN content_type TYPE VARCHAR(255)",
    "ALTER TABLE media ALTER COLUMN content_type TYPE VARCHAR(255)",
]


def migrate():
    engine = create_engine(get_database_url())
    with engine.begin() as conn:
        for stmt in STATEMENTS:
            logger.info(stmt)
            conn.execute(text(stmt))
    logger.info("Content type widening migration complete.")


if __name__ == "__main__":
    migrate()
