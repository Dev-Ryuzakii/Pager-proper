import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALTER_STATEMENTS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS voice_identity_path VARCHAR(512)",
]

def migrate():
    url = get_database_url()
    engine = create_engine(url)

    logger.info("Creating any new tables...")
    Base.metadata.create_all(bind=engine)

    logger.info("Applying column additions for AI Voice Decoy feature...")
    with engine.begin() as conn:
        for stmt in ALTER_STATEMENTS:
            logger.info(stmt)
            conn.execute(text(stmt))

    logger.info("Migration for voice identity feature complete.")

if __name__ == "__main__":
    migrate()
