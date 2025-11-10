#!/usr/bin/env python3
"""
Database Migration Script: Add phone_number column to users table
This script adds phone_number field and makes it the primary identifier for users
"""

import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Database connection
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost:5432/secure_messaging"
)

def run_migration():
    """Run the database migration"""
    print("🔧 Starting database migration...")
    print(f"📊 Database: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else 'local'}")
    
    try:
        # Create engine
        engine = create_engine(DATABASE_URL, echo=True)
        
        with engine.connect() as conn:
            # Start transaction
            trans = conn.begin()
            
            try:
                # Step 1: Add phone_number column (nullable first)
                print("\n📌 Step 1: Adding phone_number column...")
                conn.execute(text("""
                    ALTER TABLE users 
                    ADD COLUMN IF NOT EXISTS phone_number VARCHAR(20);
                """))
                
                # Step 2: Update existing users with placeholder phone numbers
                print("\n📌 Step 2: Populating phone_number for existing users...")
                conn.execute(text("""
                    UPDATE users 
                    SET phone_number = '+1' || LPAD(id::text, 10, '0')
                    WHERE phone_number IS NULL;
                """))
                
                # Step 3: Make phone_number NOT NULL and UNIQUE
                print("\n📌 Step 3: Adding constraints to phone_number...")
                conn.execute(text("""
                    ALTER TABLE users 
                    ALTER COLUMN phone_number SET NOT NULL;
                """))
                
                conn.execute(text("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_number 
                    ON users(phone_number);
                """))
                
                # Step 4: Add index on phone_number
                print("\n📌 Step 4: Creating index on phone_number...")
                conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_users_phone_number_lookup 
                    ON users(phone_number) WHERE is_active = true;
                """))
                
                # Step 5: Drop email column if it exists (optional)
                print("\n📌 Step 5: Removing email column (if exists)...")
                conn.execute(text("""
                    ALTER TABLE users 
                    DROP COLUMN IF EXISTS email;
                """))
                
                # Commit transaction
                trans.commit()
                print("\n✅ Migration completed successfully!")
                print("\n📝 Summary:")
                print("   - Added phone_number column to users table")
                print("   - Populated existing users with placeholder phone numbers")
                print("   - Created unique constraint and indexes")
                print("   - Removed email column (phone number is now the only contact method)")
                print("\n⚠️  IMPORTANT: Please update user phone numbers manually or via admin interface")
                
            except Exception as e:
                trans.rollback()
                print(f"\n❌ Migration failed: {e}")
                print("   Transaction rolled back")
                raise
                
    except Exception as e:
        print(f"\n❌ Database connection failed: {e}")
        sys.exit(1)

def verify_migration():
    """Verify the migration was successful"""
    print("\n\n🔍 Verifying migration...")
    
    try:
        engine = create_engine(DATABASE_URL, echo=False)
        
        with engine.connect() as conn:
            # Check if column exists
            result = conn.execute(text("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'phone_number';
            """))
            
            column_info = result.fetchone()
            
            if column_info:
                print(f"✅ phone_number column exists:")
                print(f"   - Type: {column_info[1]}")
                print(f"   - Nullable: {column_info[2]}")
            else:
                print("❌ phone_number column not found!")
                return False
            
            # Check constraint
            result = conn.execute(text("""
                SELECT count(*) FROM users WHERE phone_number IS NULL;
            """))
            
            row = result.fetchone()
            null_count = row[0] if row else 0
            if null_count > 0:
                print(f"⚠️  Warning: {null_count} users have NULL phone_number")
            else:
                print("✅ All users have phone_number values")
            
            # Check users
            result = conn.execute(text("""
                SELECT id, username, phone_number FROM users LIMIT 5;
            """))
            
            print("\n📊 Sample users:")
            for row in result:
                print(f"   ID: {row[0]}, Username: {row[1]}, Phone: {row[2]}")
            
            return True
            
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False

if __name__ == "__main__":
    print("=" * 80)
    print("DATABASE MIGRATION: Add phone_number to users table")
    print("=" * 80)
    
    # Run migration
    run_migration()
    
    # Verify migration
    if verify_migration():
        print("\n" + "=" * 80)
        print("✅ MIGRATION SUCCESSFUL")
        print("=" * 80)
        print("\n📋 Next Steps:")
        print("   1. Update admin interface to manage user phone numbers")
        print("   2. Update mobile app to use phone number for login")
        print("   3. Update existing users with real phone numbers")
    else:
        print("\n⚠️  Migration completed but verification found issues")
        sys.exit(1)
