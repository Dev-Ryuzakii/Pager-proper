"""One card per recording per user. Idempotent. Aborts if duplicate card hashes already exist."""

import logging
import sys

from sqlalchemy import create_engine, text

from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_messages_card_hash ON messages (message_hash) "
    "WHERE message_hash LIKE 'rec:%' OR message_hash LIKE 'notes:%'"
)


def migrate():
    engine = create_engine(get_database_url())
    with engine.begin() as conn:
        dupes = conn.execute(text(
            "SELECT message_hash, COUNT(*) FROM messages "
            "WHERE message_hash LIKE 'rec:%' OR message_hash LIKE 'notes:%' "
            "GROUP BY message_hash HAVING COUNT(*) > 1"
        )).fetchall()
        if dupes:
            logger.error("duplicate card hashes: %s", [row[0] for row in dupes])
            sys.exit(1)
        logger.info(INDEX)
        conn.execute(text(INDEX))
    logger.info("Card hash index migration complete.")


if __name__ == "__main__":
    migrate()
