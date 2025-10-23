"""
Migration script to add decoy_content column to messages table
"""

import os
import sys
from sqlalchemy import text

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def migrate_decoy_text():
    """Add decoy_content column to messages table"""
    db = None
    try:
        # Try to initialize database
        try:
            from database_config import db_config
            if not db_config.initialize_database():
                print("❌ Failed to initialize database")
                return False
                
            # Create session
            db = db_config.get_session()
        except ImportError:
            # Fallback to direct database connection
            from database_models import engine
            from sqlalchemy.orm import sessionmaker
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            db = SessionLocal()
        
        # Check if column already exists
        try:
            result = db.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'messages' AND column_name = 'decoy_content'
            """))
            
            if result.fetchone():
                print("✅ Column 'decoy_content' already exists in messages table")
                return True
        except Exception as e:
            print(f"⚠️  Could not check for column existence: {e}")
            # Continue with migration attempt
        
        # Add the decoy_content column
        try:
            db.execute(text("ALTER TABLE messages ADD COLUMN decoy_content TEXT"))
            db.commit()
            print("✅ Successfully added 'decoy_content' column to messages table")
            return True
        except Exception as e:
            print(f"❌ Error adding decoy_content column: {e}")
            # Try alternative approach for SQLite compatibility
            try:
                db.execute(text("ALTER TABLE messages ADD COLUMN decoy_content VARCHAR"))
                db.commit()
                print("✅ Successfully added 'decoy_content' column to messages table (VARCHAR version)")
                return True
            except Exception as e2:
                print(f"❌ Error adding decoy_content column (alternative approach): {e2}")
                return False
        
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        return False
    finally:
        if db:
            try:
                db.close()
            except:
                pass

def manual_migration_instructions():
    """Print manual migration instructions"""
    print("\n📝 Manual Migration Instructions:")
    print("=" * 50)
    print("If automatic migration fails, you can manually add the column:")
    print("\nFor PostgreSQL:")
    print("  ALTER TABLE messages ADD COLUMN decoy_content TEXT;")
    print("\nFor SQLite:")
    print("  ALTER TABLE messages ADD COLUMN decoy_content VARCHAR;")
    print("\nFor MySQL:")
    print("  ALTER TABLE messages ADD COLUMN decoy_content TEXT;")

if __name__ == "__main__":
    print("🔄 Migrating database to add decoy_content column...")
    success = migrate_decoy_text()
    if success:
        print("✅ Migration completed successfully!")
    else:
        print("❌ Migration failed!")
        manual_migration_instructions()
        sys.exit(1)