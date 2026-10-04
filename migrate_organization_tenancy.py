"""Add organization tenancy, invitations, and mandatory onboarding fields.

Run once before deploying the matching backend. Existing users remain
unassigned legacy accounts; newly provisioned users always belong to an org.
"""

import logging

from sqlalchemy import create_engine, text

from database_config import get_database_url
from database_models import Base


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


USER_COLUMNS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS department VARCHAR(120)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_role VARCHAR(20)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS invitation_token_hash VARCHAR(64)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS invitation_expires_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS invitation_accepted_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_invite_sent_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS sms_invite_sent_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS invitation_delivery_errors JSON",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS job_title VARCHAR(120)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS emergency_contact_name VARCHAR(255)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS emergency_contact_phone VARCHAR(20)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_invitation_token_hash ON users (invitation_token_hash)",
    "CREATE INDEX IF NOT EXISTS ix_users_organization_id ON users (organization_id)",
    "ALTER TABLE organization_access_requests ADD COLUMN IF NOT EXISTS requested_admin_username VARCHAR(50)",
    "ALTER TABLE organization_access_requests ADD COLUMN IF NOT EXISTS requested_admin_password_hash VARCHAR(255)",
    "UPDATE users SET organization_role = 'member' WHERE organization_id IS NOT NULL AND organization_role IS NULL AND is_admin = FALSE",
]


def migrate() -> None:
    engine = create_engine(get_database_url())
    # Creates organizations and organization_access_requests before the user
    # foreign-key column is added.
    Base.metadata.tables["organizations"].create(bind=engine, checkfirst=True)
    Base.metadata.tables["organization_access_requests"].create(bind=engine, checkfirst=True)
    with engine.begin() as connection:
        for statement in USER_COLUMNS:
            logger.info(statement)
            connection.execute(text(statement))
    logger.info("Organization tenancy migration complete")


if __name__ == "__main__":
    migrate()
