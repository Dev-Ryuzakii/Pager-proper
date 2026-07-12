"""
Backfill migration: replace literal decoy placeholders with generated decoy text.

Older clients (and the previous server-side fallback) stored the literal strings
"[ENCRYPTED MESSAGE] Tap to decrypt" / "[ENCRYPTED GROUP MESSAGE] Tap to decrypt"
in messages.decoy_content. Those strings defeat the purpose of the decoy: they
advertise that an encrypted message exists. This rewrites every such row with a
natural-looking decoy from FakeTextGenerator.
"""

import os
import sys

from sqlalchemy import bindparam, text

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fake_text_generator import FakeTextGenerator

PLACEHOLDERS = [
    "[ENCRYPTED MESSAGE] Tap to decrypt",
    "[ENCRYPTED GROUP MESSAGE] Tap to decrypt",
]


def _get_session():
    try:
        from database_config import db_config
        if not db_config.initialize_database():
            raise RuntimeError("Failed to initialize database")
        return db_config.get_session()
    except ImportError:
        from sqlalchemy.orm import sessionmaker
        from database_models import engine
        return sessionmaker(autocommit=False, autoflush=False, bind=engine)()


def backfill_decoy_placeholders():
    db = None
    try:
        db = _get_session()

        rows = db.execute(
            text("""
                SELECT id, encrypted_content
                FROM messages
                WHERE decoy_content IN :placeholders
                   OR decoy_content IS NULL
                   OR decoy_content = ''
            """).bindparams(bindparam("placeholders", expanding=True)),
            {"placeholders": PLACEHOLDERS},
        ).fetchall()

        if not rows:
            print("✅ No placeholder decoys found — nothing to backfill.")
            return True

        for row in rows:
            decoy = FakeTextGenerator.generate_decoy_text_for_message(row[1] or "")
            db.execute(
                text("UPDATE messages SET decoy_content = :decoy WHERE id = :id"),
                {"decoy": decoy, "id": row[0]},
            )

        db.commit()
        print(f"✅ Backfilled decoy_content for {len(rows)} message(s).")
        return True

    except Exception as e:
        if db:
            db.rollback()
        print(f"❌ Backfill failed: {e}")
        return False
    finally:
        if db:
            db.close()


if __name__ == "__main__":
    sys.exit(0 if backfill_decoy_placeholders() else 1)
