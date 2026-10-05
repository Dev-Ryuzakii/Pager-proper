"""The per-endpoint traffic rollup table behind the uptime page's Endpoints tab.

Idempotent: `create_all` adds `endpoint_metrics` when it is missing and leaves
it alone otherwise, so this is safe to run repeatedly and safe to run before or
after the backend deploy. The backend *does* need the table to exist — the
request middleware writes to it every 30 seconds — so run this first.

No seeding: the table fills itself from live traffic. A route with no rows has
simply not been called, and the page says so rather than inventing a number.
"""
import logging

from sqlalchemy import create_engine, inspect, text

from database_config import get_database_url
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Columns the page reads. Checked after create_all so a half-applied earlier
# attempt is caught here rather than as a 500 on the uptime page.
REQUIRED_COLUMNS = {
    "id", "route", "method", "bucket",
    "request_count", "success_count", "client_error_count", "server_error_count",
    "duration_sum_ms", "duration_max_ms",
    "lat_lt_10", "lat_lt_25", "lat_lt_50", "lat_lt_100", "lat_lt_250",
    "lat_lt_500", "lat_lt_1000", "lat_lt_2500", "lat_ge_2500",
}


def migrate():
    engine = create_engine(get_database_url())

    logger.info("Creating any missing tables (including endpoint_metrics)...")
    Base.metadata.create_all(bind=engine)

    with engine.begin() as conn:
        present = {c["name"] for c in inspect(engine).get_columns("endpoint_metrics")}
        missing = REQUIRED_COLUMNS - present
        if missing:
            raise RuntimeError(
                f"endpoint_metrics is missing {sorted(missing)} — "
                "drop the table and re-run this script"
            )

        rows = conn.execute(text("SELECT COUNT(*) FROM endpoint_metrics")).scalar()
        logger.info("endpoint_metrics is present with all %s columns; %s row(s) so far",
                    len(REQUIRED_COLUMNS), rows)

    logger.info("Migration for per-endpoint traffic metrics complete.")


if __name__ == "__main__":
    migrate()
