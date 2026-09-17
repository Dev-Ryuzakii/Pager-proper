"""
Database Migration Script: per-user chat preferences (archive/mute/lock/
delete-for-me) — new chat_settings table only, Base.metadata.create_all()
picks it up.
"""

import logging
from sqlalchemy import create_engine
from database_config import get_database_url
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate():
    url = get_database_url()
    engine = create_engine(url)

    logger.info("Creating chat_settings (and any other new tables)...")
    Base.metadata.create_all(bind=engine)

    logger.info("Migration for chat settings complete.")


if __name__ == "__main__":
    migrate()
