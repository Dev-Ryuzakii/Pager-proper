#!/usr/bin/env python3
"""
Script to create an admin user account
"""

import os
import sys
import logging
from getpass import getpass

# Load .env before database config (try cwd and script directory)
def _load_env():
    for path in (".env", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
        if os.path.exists(path):
            with open(path, "r") as f:
                for line in f:
                    if "=" in line and not line.strip().startswith("#"):
                        key, value = line.strip().split("=", 1)
                        os.environ[key] = value.strip().strip("'\"")

_load_env()

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
            role = user.admin_role or "admin"
            email = user.email or "-"
            last_login = user.last_login or "never"
            print(
                f"  - ID: {user.id} | username: {user.username} | "
                f"email: {email} | role: {role} | active: {user.is_active} | "
                f"last login: {last_login}"
            )
        
        session.close()
        return True
        
    except Exception as e:
        logger.error(f"Error listing admin users: {e}")
        print(f"❌ Failed to list admin users: {e}")
        return False


def reset_admin_password(username: str, password: str, force_change: bool = True):
    """Reset a database-backed admin password and revoke existing sessions.

    The password is supplied by the interactive CLI instead of as a command
    argument so it is not exposed in shell history or the process list.
    """
    if len(password) < 12:
        print("❌ Password must contain at least 12 characters")
        return False

    session = None
    try:
        if not db_config.initialize_database():
            print("❌ Failed to initialize database connection")
            return False

        session = db_config.get_session()
        if not session:
            print("❌ Failed to get database session")
            return False

        user = session.query(User).filter(
            User.username == username,
            User.is_admin == True,
        ).first()
        if not user:
            print(f"❌ Admin user {username!r} not found")
            return False

        user.password_hash = hash_password(password)
        user.must_change_password = force_change

        invalidated = session.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.is_active == True,
        ).update(
            {
                "is_active": False,
                "logout_reason": "admin_password_reset",
            },
            synchronize_session=False,
        )

        session.add(AuditLog(
            user_id=user.id,
            event_type="admin_password_reset_vps",
            event_description=f"Password reset from management CLI for admin {user.username}",
            severity="warning",
        ))
        session.commit()

        print(f"✅ Password reset for admin {user.username}")
        print(f"🔒 Invalidated {invalidated} active session(s)")
        if force_change:
            print("⚠️  Admin must change this temporary password after login")
        return True
    except Exception as e:
        if session:
            session.rollback()
        logger.error(f"Error resetting admin password: {e}")
        print(f"❌ Failed to reset admin password: {e}")
        return False
    finally:
        if session:
            session.close()

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

def init_database():
    """Create database tables (users, user_sessions, etc.) if they don't exist."""
    print("🔧 Creating database tables...")
    try:
        if not db_config.initialize_database():
            print("❌ Failed to initialize database connection")
            return False
        from database_models import Base
        Base.metadata.create_all(bind=db_config.engine)
        print("✅ Database tables created successfully!")
        return True
    except Exception as e:
        print(f"❌ Failed to create tables: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python create_admin_user.py init              # Create DB tables first")
        print("  python create_admin_user.py create [username] [password]")
        print("  python create_admin_user.py list")
        print("  python create_admin_user.py reset-password <username> [--no-force-change]")
        print("  python create_admin_user.py remove <username>")
        print("\nNote: Run 'init' first if tables don't exist. If no username/password for create, defaults:")
        print("  Username: admin")
        print("  Password: adminuser@123")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "init":
        success = init_database()
        sys.exit(0 if success else 1)
    
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

    elif command == "reset-password":
        if len(sys.argv) < 3:
            print("Usage: python create_admin_user.py reset-password <username> [--no-force-change]")
            sys.exit(1)
        if any(arg not in {"--no-force-change"} for arg in sys.argv[3:]):
            print("Usage: python create_admin_user.py reset-password <username> [--no-force-change]")
            sys.exit(1)

        username = sys.argv[2]
        force_change = "--no-force-change" not in sys.argv[3:]
        password_label = "New temporary password" if force_change else "New password"
        password = getpass(f"{password_label}: ")
        confirmation = getpass(f"Confirm {password_label.lower()}: ")
        if password != confirmation:
            print("❌ Passwords do not match")
            sys.exit(1)

        success = reset_admin_password(username, password, force_change=force_change)
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
        print("  python create_admin_user.py reset-password <username> [--no-force-change]")
        print("  python create_admin_user.py remove <username>")
        sys.exit(1)
