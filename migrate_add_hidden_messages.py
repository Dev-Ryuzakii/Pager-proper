"""
Database Migration Script: per-user "delete for me" — hidden_messages table.
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
        """
        CREATE TABLE IF NOT EXISTS hidden_messages (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT now(),
            CONSTRAINT uq_hidden_message UNIQUE (user_id, message_id)
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_hidden_messages_user_id ON hidden_messages (user_id)",
        "CREATE INDEX IF NOT EXISTS ix_hidden_messages_message_id ON hidden_messages (message_id)",
    ]
    with engine.begin() as conn:
        for stmt in statements:
            logger.info(stmt.strip().splitlines()[0])
            conn.execute(text(stmt))

    logger.info("Migration for hidden messages complete.")


if __name__ == "__main__":
    migrate()
