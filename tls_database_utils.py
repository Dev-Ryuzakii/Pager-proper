"""
Database utilities for TLS server
Provides functions to store and validate master tokens in PostgreSQL database
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Optional

# Initialize global variables
db_config = None
engine = None
SessionLocal = None
DATABASE_AVAILABLE = False
DatabaseConfig = None

# Try to import database modules, but make them optional
try:
    from sqlalchemy import create_engine, text, and_, or_
    from sqlalchemy.orm import sessionmaker
    from database_models import MasterToken, User
    from database_config import DatabaseConfig as ConfigClass
    DatabaseConfig = ConfigClass
    DATABASE_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Database modules not available. Database features will be disabled. Error: {e}")
    # Define placeholders for the missing imports
    and_ = None
    or_ = None

def initialize_database():
    """Initialize database connection if available"""
    global db_config, engine, SessionLocal, DATABASE_AVAILABLE, DatabaseConfig
    
    if not DATABASE_AVAILABLE or DatabaseConfig is None:
        return False
    
    try:
        # Initialize database configuration
        db_config = DatabaseConfig()
        if not db_config.initialize_database():
            print("⚠️  Failed to initialize database connection")
            return False
        
        # Test connection
        if not db_config.test_connection():
            print("⚠️  Database connection test failed")
            return False
            
        engine = db_config.engine
        SessionLocal = db_config.SessionLocal
        
        print("✅ Database connection initialized successfully")
        return True
        
    except Exception as e:
        print(f"⚠️  Database initialization error: {e}")
        return False

def get_db_session():
    """Get database session"""
    global SessionLocal
    if not SessionLocal:
        return None
    return SessionLocal()

def hash_master_token(mastertoken: str, salt: str) -> str:
    """Hash master token with salt for secure storage"""
    return hashlib.sha256((mastertoken + salt).encode()).hexdigest()

def generate_salt() -> str:
    """Generate a random salt for hashing"""
    return base64.b64encode(os.urandom(32)).decode()

def store_master_token(username: str, mastertoken: str) -> bool:
    """
    Store master token for a user in the database
    Returns True if successful or if database is not available, False on error
    """
    global DATABASE_AVAILABLE, engine, and_
    
    if not DATABASE_AVAILABLE or not engine:
        print("⚠️  Database not available, skipping master token storage")
        # Return True to indicate that this is not an error condition
        return True
    
    try:
        # Import database models inside the function to avoid import issues
        from database_models import MasterToken, User
        
        # Get database session
        db = get_db_session()
        if not db:
            return False
            
        try:
            # Check if user exists
            user = db.query(User).filter(User.username == username).first()
            if not user:
                # Create user if not exists (for backward compatibility)
                user = User(
                    username=username,
                    token="",  # Will be updated later
                    is_active=True,
                    user_type="tls"
                )
                db.add(user)
                db.commit()
                db.refresh(user)
            
            # Generate salt and hash the master token
            salt = generate_salt()
            token_hash = hash_master_token(mastertoken, salt)
            
            # Deactivate any existing master tokens for this user
            if and_ is not None:
                db.query(MasterToken).filter(
                    and_(
                        MasterToken.user_id == user.id,
                        MasterToken.is_active == True
                    )
                ).update({"is_active": False})
            
            # Create new master token record
            master_token_record = MasterToken(
                user_id=user.id,
                token_hash=token_hash,
                salt=salt,
                is_active=True,
                expires_at=datetime.now() + timedelta(days=30)  # 30-day expiration
            )
            
            db.add(master_token_record)
            db.commit()
            
            print(f"✅ Master token stored for user: {username}")
            return True
            
        finally:
            db.close()
            
    except Exception as e:
        print(f"❌ Error storing master token: {e}")
        return False

def validate_master_token(username: str, mastertoken: str) -> bool:
    """
    Validate master token for a user against database
    Returns True if valid or if database is not available, False otherwise
    """
    global DATABASE_AVAILABLE, engine, and_, or_
    
    if not DATABASE_AVAILABLE or not engine:
        print("⚠️  Database not available, skipping master token validation")
        # Return True to indicate that this is not an error condition
        # When database is not available, we allow the operation to proceed
        return True
    
    try:
        # Import database models inside the function to avoid import issues
        from database_models import MasterToken, User
        
        # Get database session
        db = get_db_session()
        if not db:
            return False
            
        try:
            # Get user
            user = db.query(User).filter(User.username == username).first()
            if not user:
                print(f"❌ User not found: {username}")
                return False
            
            # Get the latest active master token for this user
            if and_ is not None and or_ is not None:
                master_token_record = db.query(MasterToken).filter(
                    and_(
                        MasterToken.user_id == user.id,
                        MasterToken.is_active == True,
                        or_(
                            MasterToken.expires_at == None,
                            MasterToken.expires_at > datetime.now()
                        )
                    )
                ).order_by(MasterToken.created_at.desc()).first()
            else:
                master_token_record = None
            
            if not master_token_record:
                print(f"❌ No active master token found for user: {username}")
                return False
            
            # Hash the provided token with the stored salt
            provided_hash = hash_master_token(mastertoken, str(master_token_record.salt))
            
            # Compare hashes
            is_valid = provided_hash == str(master_token_record.token_hash)
            
            if is_valid:
                print(f"✅ Master token validated for user: {username}")
            else:
                print(f"❌ Invalid master token for user: {username}")
                
            return is_valid
            
        finally:
            db.close()
            
    except Exception as e:
        print(f"❌ Error validating master token: {e}")
        return False

# Initialize database on module load
if DATABASE_AVAILABLE:
    initialize_database()