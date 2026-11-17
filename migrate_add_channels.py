"""
Topic channels are groups with extra columns, plus a thread root on messages.
Idempotent. Does not rewrite existing group rows beyond the new defaults.
"""

import logging

from sqlalchemy import create_engine, text

from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATEMENTS = [
    "ALTER TABLE groups ADD COLUMN IF NOT EXISTS kind VARCHAR(20) DEFAULT 'group'",
    "ALTER TABLE groups ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'private'",
    "ALTER TABLE groups ADD COLUMN IF NOT EXISTS organization_id INTEGER",
    "ALTER TABLE groups ADD COLUMN IF NOT EXISTS topic VARCHAR(200)",
    "ALTER TABLE groups ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE",
    "ALTER TABLE groups ADD COLUMN IF NOT EXISTS posting_policy VARCHAR(20) DEFAULT 'everyone'",
    "ALTER TABLE groups ADD COLUMN IF NOT EXISTS slug VARCHAR(80)",
    "CREATE INDEX IF NOT EXISTS ix_groups_kind ON groups (kind)",
    "CREATE INDEX IF NOT EXISTS ix_groups_organization_id ON groups (organization_id)",
    "CREATE INDEX IF NOT EXISTS ix_groups_slug ON groups (slug)",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_channels_org_slug ON groups (organization_id, slug) WHERE kind = 'channel'",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS thread_root_id INTEGER",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS thread_reply_count INTEGER DEFAULT 0",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS thread_last_reply_at TIMESTAMP",
    "CREATE INDEX IF NOT EXISTS ix_messages_thread_root_id ON messages (thread_root_id)",
    """CREATE TABLE IF NOT EXISTS thread_follows (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        root_message_id INTEGER NOT NULL,
        created_at TIMESTAMP,
        CONSTRAINT uq_thread_follow UNIQUE (user_id, root_message_id)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_thread_follows_user_id ON thread_follows (user_id)",
    "CREATE INDEX IF NOT EXISTS ix_thread_follows_root_message_id ON thread_follows (root_message_id)",
]


def migrate():
    engine = create_engine(get_database_url())
    with engine.begin() as conn:
        for stmt in STATEMENTS:
            logger.info(stmt.splitlines()[0])
            conn.execute(text(stmt))
    logger.info("Channel migration complete.")


if __name__ == "__main__":
    migrate()
