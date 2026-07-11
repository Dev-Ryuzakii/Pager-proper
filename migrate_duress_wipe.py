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
    # Approval-flow columns
    "ALTER TABLE device_wipe_commands ALTER COLUMN issued_by_admin_id DROP NOT NULL",
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS trigger_source VARCHAR(20) DEFAULT 'admin'",
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS requested_by_user_id INTEGER REFERENCES users(id)",
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS approved_by_admin_id INTEGER REFERENCES users(id)",
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP",
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS rejected_by_admin_id INTEGER REFERENCES users(id)",
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMP",
    "ALTER TABLE device_wipe_commands ADD COLUMN IF NOT EXISTS rejection_note TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS can_approve_duress_wipe BOOLEAN DEFAULT FALSE",
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
