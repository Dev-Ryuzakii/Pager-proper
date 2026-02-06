#!/usr/bin/env python3
"""
Script to create an admin user account
"""

import os
import sys
import logging
import bcrypt
from sqlalchemy.orm import Session
from database_config import db_config
from database_models import User, UserKey, UserSession, Message, Media, AuditLog, MasterToken

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def create_admin_user(username: str = "admin", password: str = "adminuser@123"):
    """Create an admin user account with default credentials"""
    print(f"🔧 Creating admin user: {username}")
    print("=" * 50)
    
    try:
        # Initialize database connection
        if not db_config.initialize_database():
            print("❌ Failed to initialize database connection")
            return False
        
        # Get database session
        session = db_config.get_session()
        if not session:
            print("❌ Failed to get database session")
            return False
        
        # Check if user already exists
        existing_user = session.query(User).filter(User.username == username).first()
        if existing_user:
            print(f"⚠️  User {username} already exists")
            # Check if user is already admin
            if existing_user.is_admin:
                print(f"✅ User {username} is already an admin")
                session.close()
                return True
            else:
                # Make existing user an admin
                existing_user.is_admin = True
                existing_user.password_hash = hash_password(password)
                existing_user.must_change_password = True  # Force password change on first login
                session.commit()
                print(f"✅ User {username} has been promoted to admin")
                session.close()
                return True
        
        # Create new admin user with a unique phone number
        # Generate admin phone number based on username to ensure uniqueness
        admin_phone = f"+1000{abs(hash(username)) % 1000000:06d}"
        
        admin_user = User(
            username=username,
            phone_number=admin_phone,  # Add required phone number
            password_hash=hash_password(password),
            is_active=True,
            is_verified=True,
            is_admin=True,
            user_type="mobile",
            must_change_password=True  # Force password change on first login
        )
        
        session.add(admin_user)
        session.commit()
        session.refresh(admin_user)
        
        print(f"✅ Admin user created successfully!")
        print(f"Username: {admin_user.username}")
        print(f"User ID: {admin_user.id}")
        print(f"Admin status: {admin_user.is_admin}")
        print(f"⚠️  NOTE: User must change password on first login")
        
        # Log the admin creation
        audit_log = AuditLog(
            user_id=admin_user.id,
            event_type="admin_user_created",
            event_description=f"Admin user {username} created",
            severity="info"
        )
        
        session.add(audit_log)
        session.commit()
        
        session.close()
        return True
        
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        print(f"❌ Failed to create admin user: {e}")
        return False

def list_admin_users():
    """List all admin users"""
    print("📋 Listing admin users")
    print("=" * 50)
    
    try:
        # Initialize database connection
        if not db_config.initialize_database():
            print("❌ Failed to initialize database connection")
            return False
        
        # Get database session
        session = db_config.get_session()
        if not session:
            print("❌ Failed to get database session")
            return False
        
        # Get all admin users
        admin_users = session.query(User).filter(User.is_admin == True).all()
        
        if not admin_users:
            print("No admin users found")
            session.close()
            return True
        
        print(f"Found {len(admin_users)} admin user(s):")
        for user in admin_users:
            print(f"  - {user.username} (ID: {user.id})")
        
        session.close()
        return True
        
    except Exception as e:
        logger.error(f"Error listing admin users: {e}")
        print(f"❌ Failed to list admin users: {e}")
        return False

def remove_admin_status(username: str):
    """Remove admin status from a user"""
    print(f"🔧 Removing admin status from user: {username}")
    print("=" * 50)
    
    try:
        # Initialize database connection
        if not db_config.initialize_database():
            print("❌ Failed to initialize database connection")
            return False
        
        # Get database session
        session = db_config.get_session()
        if not session:
            print("❌ Failed to get database session")
            return False
        
        # Find the user
        user = session.query(User).filter(User.username == username).first()
        if not user:
            print(f"❌ User {username} not found")
            session.close()
            return False
        
        if not user.is_admin:
            print(f"⚠️  User {username} is not an admin")
            session.close()
            return True
        
        # Remove admin status
        user.is_admin = False
        session.commit()
        
        print(f"✅ Admin status removed from user {username}")
        
        # Log the action
        audit_log = AuditLog(
            user_id=user.id,
            event_type="admin_status_removed",
            event_description=f"Admin status removed from user {username}",
            severity="info"
        )
        
        session.add(audit_log)
        session.commit()
        
        session.close()
        return True
        
    except Exception as e:
        logger.error(f"Error removing admin status: {e}")
        print(f"❌ Failed to remove admin status: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python create_admin_user.py create [username] [password]")
        print("  python create_admin_user.py list")
        print("  python create_admin_user.py remove <username>")
        print("\nNote: If no username/password provided for create, defaults to:")
        print("  Username: admin")
        print("  Password: adminuser@123")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "create":
        username = "admin"
        password = "adminuser@123"
        
        if len(sys.argv) >= 3:
            username = sys.argv[2]
        if len(sys.argv) >= 4:
            password = sys.argv[3]
            
        success = create_admin_user(username, password)
        sys.exit(0 if success else 1)
    
    elif command == "list":
        success = list_admin_users()
        sys.exit(0 if success else 1)
    
    elif command == "remove":
        if len(sys.argv) < 3:
            print("Usage: python create_admin_user.py remove <username>")
            sys.exit(1)
        
        username = sys.argv[2]
        success = remove_admin_status(username)
        sys.exit(0 if success else 1)
    
    else:
        print(f"Unknown command: {command}")
        print("Usage:")
        print("  python create_admin_user.py create [username] [password]")
        print("  python create_admin_user.py list")
        print("  python create_admin_user.py remove <username>")
        sys.exit(1)