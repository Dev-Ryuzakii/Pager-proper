"""Persist the selected device for offline Field Ops commands."""

from sqlalchemy import create_engine, text

from database_config import get_database_url


def migrate():
    engine = create_engine(get_database_url())
    with engine.begin() as connection:
        connection.execute(text(
            "ALTER TABLE remote_commands ADD COLUMN IF NOT EXISTS target_device_id VARCHAR(128)"))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_remote_commands_target_device_id "
            "ON remote_commands (target_device_id)"))


if __name__ == "__main__":
    migrate()
