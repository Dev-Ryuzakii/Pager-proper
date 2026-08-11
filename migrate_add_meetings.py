#!/usr/bin/env python3
"""
Migration Script: Add meetings + meeting_participants tables

Scheduled meetings, independent of an active call. A meeting becomes a
standalone ConferenceSession (same call_id-omitted path instant meetings
already use) once someone joins — no parallel calling mechanism.
"""

import os
import sys
import logging
from database_config import db_config
from database_models import Meeting, MeetingParticipant

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_migration():
    print("🔧 Migrating meetings + meeting_participants tables")
    print("=" * 50)

    try:
        if not db_config.initialize_database():
            print("❌ Failed to initialize database connection")
            return False

        engine = db_config.engine
        if not engine:
            print("❌ Database engine not available")
            return False

        print("📋 Creating meetings table...")
        Meeting.__table__.create(engine, checkfirst=True)
        print("✅ meetings table created (or already existed)")

        print("📋 Creating meeting_participants table...")
        MeetingParticipant.__table__.create(engine, checkfirst=True)
        print("✅ meeting_participants table created (or already existed)")

        print("\n🎉 Migration completed successfully!")
        return True

    except Exception as e:
        logger.error(f"Migration error: {e}")
        print(f"❌ Migration failed: {e}")
        return False


if __name__ == "__main__":
    success = run_migration()
    sys.exit(0 if success else 1)
