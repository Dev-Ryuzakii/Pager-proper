"""
Create the multi-device tables and backfill each existing user's identity key as
their primary linked device, so senders can encrypt to it immediately and the
phone keeps working after it updates.
"""

import logging
import os
import sys
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database_config import get_database_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create the two new tables directly, WITHOUT database-level FOREIGN KEY
# constraints. A FK to users(id) would need a lock on the busy `users` table and
# hang behind the live backend's open transactions. SQLAlchemy relationships still
# work — they join on the model's declared keys, not on DB constraints.
CREATE_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS linked_devices (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        device_uuid VARCHAR(64) UNIQUE NOT NULL,
        platform VARCHAR(20) NOT NULL,
        device_name VARCHAR(120),
        public_key TEXT NOT NULL,
        session_token VARCHAR(512) UNIQUE,
        created_at TIMESTAMP DEFAULT NOW(),
        last_seen TIMESTAMP,
        revoked_at TIMESTAMP
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_linked_devices_user_id ON linked_devices (user_id)",
    "CREATE INDEX IF NOT EXISTS ix_linked_devices_device_uuid ON linked_devices (device_uuid)",
    "CREATE INDEX IF NOT EXISTS ix_linked_devices_session_token ON linked_devices (session_token)",
    """
    CREATE TABLE IF NOT EXISTS device_link_requests (
        id SERIAL PRIMARY KEY,
        nonce VARCHAR(64) UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        platform VARCHAR(20) NOT NULL,
        device_name VARCHAR(120),
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        approved_user_id INTEGER,
        device_uuid VARCHAR(64),
        session_token VARCHAR(512),
        consumed BOOLEAN DEFAULT FALSE
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_device_link_requests_nonce ON device_link_requests (nonce)",
]


def migrate():
    engine = create_engine(get_database_url())

    # A previously interrupted run can leave a transaction holding a catalog lock
    # on the half-created table, which blocks every retry. Clear those stuck
    # sessions first: idle-in-transaction, or anything still stuck creating our
    # tables, older than 30s. Active app connections (short transactions) are not
    # touched.
    logger.info("Clearing any stuck transactions from a previous run...")
    with engine.begin() as conn:
        killed = conn.execute(text("""
            SELECT pg_terminate_backend(pid), pid, state, left(query, 60) AS q
            FROM pg_stat_activity
            WHERE datname = current_database()
              AND pid <> pg_backend_pid()
              AND xact_start < now() - interval '30 seconds'
              AND (
                    state = 'idle in transaction'
                 OR (state = 'active' AND query ILIKE '%linked_devices%')
                 OR (state = 'active' AND query ILIKE '%device_link_requests%')
              )
        """)).fetchall()
        for row in killed:
            logger.info(f"  terminated pid {row.pid} ({row.state}): {row.q}")

    logger.info("Creating linked_devices / device_link_requests tables...")
    with engine.begin() as conn:
        # Fail fast instead of blocking forever if something holds a lock.
        conn.execute(text("SET lock_timeout = '10s'"))
        for stmt in CREATE_STATEMENTS:
            conn.execute(text(stmt))

    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        # Query only the columns we need, so the backfill doesn't depend on the
        # rest of the users schema being fully migrated.
        rows = db.execute(text("""
            SELECT id, public_key FROM users
            WHERE public_key IS NOT NULL AND public_key <> ''
        """)).fetchall()

        created = 0
        for user_id, public_key in rows:
            pub = (public_key or "").strip()
            if not pub:
                continue
            exists = db.execute(
                text("SELECT 1 FROM linked_devices WHERE user_id = :uid AND public_key = :pk LIMIT 1"),
                {"uid": user_id, "pk": pub},
            ).first()
            if exists:
                continue
            db.execute(text("""
                INSERT INTO linked_devices
                    (user_id, device_uuid, platform, device_name, public_key, created_at)
                VALUES (:uid, :uuid, 'legacy', 'Primary device', :pk, NOW())
            """), {"uid": user_id, "uuid": uuid.uuid4().hex, "pk": pub})
            created += 1

        db.commit()
        logger.info(f"✅ Backfilled {created} primary device(s).")
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Migration failed: {e}")
        return False
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(0 if migrate() else 1)
