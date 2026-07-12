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
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate():
    engine = create_engine(get_database_url())

    logger.info("Creating linked_devices / device_link_requests tables...")
    Base.metadata.create_all(bind=engine)

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
