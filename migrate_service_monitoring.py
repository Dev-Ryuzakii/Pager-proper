import logging
from sqlalchemy import create_engine, text
from database_config import get_database_url
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALTER_STATEMENTS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS monitored_services JSON",
    "CREATE INDEX IF NOT EXISTS ix_service_events_service ON service_events (service)",
    "CREATE INDEX IF NOT EXISTS ix_service_events_created_at ON service_events (created_at)",
    "ALTER TABLE monitoring_consents ADD COLUMN IF NOT EXISTS allow_app_policy_monitoring BOOLEAN DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS accessible_pages JSON",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS disappear_text_hours INTEGER",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS disappear_media_hours INTEGER",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS disappear_voice_hours INTEGER",
    "CREATE INDEX IF NOT EXISTS ix_policy_violation_screenshots_user_id ON policy_violation_screenshots (user_id)",
    "CREATE INDEX IF NOT EXISTS ix_policy_violation_screenshots_detected_at ON policy_violation_screenshots (detected_at)",
]

def migrate():
    url = get_database_url()
    engine = create_engine(url)

    logger.info("Creating service_events table (and any other new tables)...")
    Base.metadata.create_all(bind=engine)

    logger.info("Applying column/index additions for service monitoring...")
    with engine.begin() as conn:
        for stmt in ALTER_STATEMENTS:
            logger.info(stmt)
            conn.execute(text(stmt))

    logger.info("Migration for service monitoring complete.")

if __name__ == "__main__":
    migrate()
