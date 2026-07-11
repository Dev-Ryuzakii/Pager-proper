import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALTER_STATEMENTS = [
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS wipe_mode VARCHAR(20) DEFAULT 'app_data'",
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS target_packages JSON",
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS batch_id VARCHAR(64)",
    "CREATE INDEX IF NOT EXISTS ix_device_wipe_commands_batch_id ON device_wipe_commands (batch_id)",
    "ALTER TABLE geofence_zones ADD COLUMN IF NOT EXISTS wipe_mode VARCHAR(20) DEFAULT 'duress_selective'",
]

def migrate():
    url = get_database_url()
    engine = create_engine(url)

    logger.info("Creating any new tables...")
    Base.metadata.create_all(bind=engine)

    logger.info("Applying column additions for duress wipe feature...")
    with engine.begin() as conn:
        for stmt in ALTER_STATEMENTS:
            logger.info(stmt)
            conn.execute(text(stmt))

    logger.info("Migration for duress wipe feature complete.")

if __name__ == "__main__":
    migrate()
