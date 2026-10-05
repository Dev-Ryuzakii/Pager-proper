"""Organization attribution for service events, plus the uptime checker tables.

Idempotent: safe to run repeatedly, and safe to run before the new backend code
is deployed (the code needs these columns/tables to exist). Seeds the platform's
own endpoints as uptime targets the first time it runs, so the new page is not
empty on a fresh install.
"""
import logging
import os

from sqlalchemy import create_engine, text

from database_config import get_database_url
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALTER_STATEMENTS = [
    "ALTER TABLE service_events ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id)",
    "CREATE INDEX IF NOT EXISTS ix_service_events_organization_id ON service_events (organization_id)",
]

# (name, url) — only inserted when the table is still empty, so an admin who
# deletes one of these does not get it back on the next deploy.
SEED_TARGETS = [
    ("Dilarion API", os.getenv("UPTIME_SEED_API_URL", "https://apidilarion.eibstratoc.com/health")),
    ("Dilarion web", os.getenv("UPTIME_SEED_WEB_URL", "https://dilarion.xyz")),
    ("Dilarion admin console", os.getenv("UPTIME_SEED_ADMIN_URL", "https://admin.dilarion.xyz")),
]


def migrate():
    engine = create_engine(get_database_url())

    logger.info("Creating any missing tables (including the uptime checker's)...")
    Base.metadata.create_all(bind=engine)

    logger.info("Applying organization attribution to service_events...")
    with engine.begin() as conn:
        for stmt in ALTER_STATEMENTS:
            logger.info(stmt)
            conn.execute(text(stmt))

        existing = conn.execute(text("SELECT COUNT(*) FROM uptime_targets")).scalar()
        if not existing:
            logger.info("Seeding the platform's own endpoints as uptime targets...")
            for name, url in SEED_TARGETS:
                # created_at is set explicitly: it is NOT NULL and its default
                # is applied by the ORM's Python-side default, which raw SQL
                # here does not go through.
                conn.execute(
                    text(
                        "INSERT INTO uptime_targets "
                        "(name, url, method, expected_status, interval_seconds, timeout_ms, "
                        " is_active, last_status, created_at) "
                        "VALUES (:name, :url, 'GET', 200, 60, 10000, TRUE, 'unknown', NOW())"
                    ),
                    {"name": name, "url": url},
                )
        else:
            logger.info("uptime_targets already has %s row(s); not seeding", existing)

    logger.info("Migration for organization-scoped monitoring and uptime checking complete.")


if __name__ == "__main__":
    migrate()
