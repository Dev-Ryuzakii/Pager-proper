"""
Migration Script: JSON Files to PostgreSQL
Transfers existing user data, messages, and keys from JSON files to PostgreSQL database
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, Any, List
import logging

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

from database_config import db_config, get_database_session
from database_models import User, Message, UserKey, UserSession, SystemConfig, AuditLog

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DataMigrator:
    """Class to handle migration from JSON files to PostgreSQL"""
    
    def __init__(self):
        self.session = None
        self.migration_stats = {
            'users_migrated': 0,
            'messages_migrated': 0,
            'keys_migrated': 0,
            'errors': []
        }
    
    def initialize_session(self):
        """Initialize database session"""
        try:
            db_config.initialize_database()
            self.session = db_config.get_session()
            logger.info("✅ Database session initialized")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to initialize database session: {e}")
            return False
    
    def migrate_users(self) -> bool:
        """Migrate users from JSON to PostgreSQL"""
        logger.info("👥 Migrating users from JSON to PostgreSQL...")
        
        try:
            # Load user data from JSON
            user_files = [
                'auth/user_keys/user_keys_secure.json',
                'auth/user_keys/user_keys.json'
            ]
            
            all_users = {}
            
            for file_path in user_files:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if 'users' in data:
                            all_users.update(data['users'])
                        else:
                            # Handle legacy format
                            all_users.update(data)
                    logger.info(f"✅ Loaded users from {file_path}")
            
            # Migrate each user
            for username, user_data in all_users.items():
                if username in ['last_updated', 'server_version']:
                    continue  # Skip metadata
                
                try:
                    # Check if user already exists
                    existing_user = self.session.query(User).filter(User.username == username).first()
                    if existing_user:
                        logger.info(f"⚠️  User '{username}' already exists, skipping...")
                        continue
                    
                    # Create new user
                    user = User(
                        username=username,
                        email=user_data.get('email'),  # May be None for TLS users
                        public_key=user_data.get('public_key', ''),
                        token=user_data.get('token'),
                        registered=datetime.fromtimestamp(user_data.get('registered', datetime.now().timestamp())),
                        last_login=datetime.fromtimestamp(user_data['last_login']) if user_data.get('last_login') else None,
                        registration_ip=user_data.get('registration_ip'),
                        device_id=user_data.get('device_id'),
                        push_token=user_data.get('push_token'),
                        device_info=user_data.get('device_info'),
                        is_active=True,
                        is_verified=True,
                        user_type="mobile" if user_data.get('email') or user_data.get('device_id') else "tls"
                    )
                    
                    self.session.add(user)
                    self.migration_stats['users_migrated'] += 1
                    logger.info(f"✅ Migrated user: {username}")
                    
                except Exception as e:
                    error_msg = f"Error migrating user {username}: {e}"
                    logger.error(f"❌ {error_msg}")
                    self.migration_stats['errors'].append(error_msg)
            
            self.session.commit()
            logger.info(f"✅ Users migration completed: {self.migration_stats['users_migrated']} users migrated")
            return True
            
        except Exception as e:
            logger.error(f"❌ Users migration failed: {e}")
            self.session.rollback()
            return False
    
    def migrate_offline_messages(self) -> bool:
        """Migrate offline messages from JSON to PostgreSQL"""
        logger.info("💬 Migrating offline messages from JSON to PostgreSQL...")
        
        try:
            offline_messages_file = 'auth/user_keys/offline_messages.json'
            
            if not os.path.exists(offline_messages_file):
                logger.info("ℹ️  No offline messages file found, skipping...")
                return True
            
            with open(offline_messages_file, 'r') as f:
                offline_messages = json.load(f)
            
            for recipient_username, messages in offline_messages.items():
                # Get recipient user
                recipient = self.session.query(User).filter(User.username == recipient_username).first()
                if not recipient:
                    logger.warning(f"⚠️  Recipient '{recipient_username}' not found, skipping messages")
                    continue
                
                for msg_data in messages:
                    try:
                        # Get sender user
                        sender_username = msg_data.get('sender', 'system')
                        sender = self.session.query(User).filter(User.username == sender_username).first()
                        
                        if not sender:
                            # Create a system user if sender not found
                            sender = User(
                                username='system',
                                email='system@localhost',
                                public_key='system_key',
                                is_active=True,
                                registered=datetime.now()
                            )
                            self.session.add(sender)
                            self.session.commit()
                        
                        # Create message
                        message = Message(
                            sender_id=sender.id,
                            recipient_id=recipient.id,
                            encrypted_content=msg_data.get('content', ''),
                            content_type=msg_data.get('type', 'text'),
                            timestamp=datetime.fromtimestamp(msg_data.get('timestamp', datetime.now().timestamp())),
                            is_offline=True,
                            delivered=False,
                            read=False
                        )
                        
                        self.session.add(message)
                        self.migration_stats['messages_migrated'] += 1
                        
                    except Exception as e:
                        error_msg = f"Error migrating message for {recipient_username}: {e}"
                        logger.error(f"❌ {error_msg}")
                        self.migration_stats['errors'].append(error_msg)
            
            self.session.commit()
            logger.info(f"✅ Offline messages migration completed: {self.migration_stats['messages_migrated']} messages migrated")
            return True
            
        except Exception as e:
            logger.error(f"❌ Offline messages migration failed: {e}")
            self.session.rollback()
            return False
    
    def migrate_user_keys(self) -> bool:
        """Migrate user keys from files to PostgreSQL"""
        logger.info("🔑 Migrating user keys from files to PostgreSQL...")
        
        try:
            key_directories = [
                ('auth/private_keys/', 'private_key'),
                ('auth/master_salts/', 'master_salt'),
                ('auth/cache/', 'public_key_cache')
            ]
            
            for directory, key_type in key_directories:
                if not os.path.exists(directory):
                    continue
                
                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)
                    
                    if os.path.isfile(file_path):
                        try:
                            # Extract username from filename
                            username = None
                            if '_private_key.pem' in filename:
                                username = filename.replace('_private_key.pem', '').replace('_user', '')
                            elif '_master_salt.dat' in filename:
                                username = filename.replace('_master_salt.dat', '')
                            elif '_public_keys_cache.json' in filename:
                                username = filename.replace('_public_keys_cache.json', '')
                            
                            if not username:
                                logger.warning(f"⚠️  Could not extract username from {filename}")
                                continue
                            
                            # Get user
                            user = self.session.query(User).filter(User.username == username).first()
                            if not user:
                                logger.warning(f"⚠️  User '{username}' not found for key {filename}")
                                continue
                            
                            # Read key data
                            with open(file_path, 'rb') as f:
                                key_data = f.read()
                            
                            # Check if key already exists
                            existing_key = self.session.query(UserKey).filter(
                                UserKey.user_id == user.id,
                                UserKey.key_name == filename
                            ).first()
                            
                            if existing_key:
                                logger.info(f"⚠️  Key '{filename}' already exists for user '{username}', skipping...")
                                continue
                            
                            # Create user key record
                            user_key = UserKey(
                                user_id=user.id,
                                key_type=key_type,
                                key_name=filename,
                                key_data=key_data,
                                is_active=True
                            )
                            
                            self.session.add(user_key)
                            self.migration_stats['keys_migrated'] += 1
                            logger.info(f"✅ Migrated key: {filename} for user {username}")
                            
                        except Exception as e:
                            error_msg = f"Error migrating key {filename}: {e}"
                            logger.error(f"❌ {error_msg}")
                            self.migration_stats['errors'].append(error_msg)
            
            self.session.commit()
            logger.info(f"✅ User keys migration completed: {self.migration_stats['keys_migrated']} keys migrated")
            return True
            
        except Exception as e:
            logger.error(f"❌ User keys migration failed: {e}")
            self.session.rollback()
            return False
    
    def create_system_config(self) -> bool:
        """Create system configuration entries"""
        logger.info("⚙️  Creating system configuration...")
        
        try:
            configs = [
                {
                    'config_key': 'migration_date',
                    'config_value': datetime.now().isoformat(),
                    'config_type': 'string',
                    'description': 'Date when migration from JSON to PostgreSQL was completed'
                },
                {
                    'config_key': 'database_version',
                    'config_value': '1.0',
                    'config_type': 'string',
                    'description': 'Database schema version'
                },
                {
                    'config_key': 'system_status',
                    'config_value': 'active',
                    'config_type': 'string',
                    'description': 'Current system status'
                }
            ]
            
            for config_data in configs:
                existing_config = self.session.query(SystemConfig).filter(
                    SystemConfig.config_key == config_data['config_key']
                ).first()
                
                if not existing_config:
                    config = SystemConfig(**config_data)
                    self.session.add(config)
            
            self.session.commit()
            logger.info("✅ System configuration created")
            return True
            
        except Exception as e:
            logger.error(f"❌ System configuration creation failed: {e}")
            self.session.rollback()
            return False
    
    def create_audit_log(self) -> bool:
        """Create audit log entry for migration"""
        try:
            audit_entry = AuditLog(
                event_type='data_migration',
                event_description='Migration from JSON files to PostgreSQL completed',
                severity='info',
                extra_data={
                    'users_migrated': self.migration_stats['users_migrated'],
                    'messages_migrated': self.migration_stats['messages_migrated'],
                    'keys_migrated': self.migration_stats['keys_migrated'],
                    'errors_count': len(self.migration_stats['errors'])
                }
            )
            
            self.session.add(audit_entry)
            self.session.commit()
            logger.info("✅ Audit log entry created")
            return True
            
        except Exception as e:
            logger.error(f"❌ Audit log creation failed: {e}")
            return False
    
    def run_migration(self) -> bool:
        """Run the complete migration process"""
        logger.info("🚀 Starting data migration from JSON to PostgreSQL...")
        
        if not self.initialize_session():
            return False
        
        try:
            # Run migrations
            success = True
            success &= self.migrate_users()
            success &= self.migrate_offline_messages()
            success &= self.migrate_user_keys()
            success &= self.create_system_config()
            success &= self.create_audit_log()
            
            # Print migration summary
            self.print_migration_summary()
            
            return success
            
        except Exception as e:
            logger.error(f"❌ Migration failed: {e}")
            return False
        finally:
            if self.session:
                self.session.close()
    
    def print_migration_summary(self):
        """Print migration summary"""
        print("\n" + "="*60)
        print("📊 MIGRATION SUMMARY")
        print("="*60)
        print(f"👥 Users migrated: {self.migration_stats['users_migrated']}")
        print(f"💬 Messages migrated: {self.migration_stats['messages_migrated']}")
        print(f"🔑 Keys migrated: {self.migration_stats['keys_migrated']}")
        print(f"❌ Errors: {len(self.migration_stats['errors'])}")
        
        if self.migration_stats['errors']:
            print("\n🚨 ERRORS:")
            for error in self.migration_stats['errors']:
                print(f"   - {error}")
        
        print("\n✅ Migration completed!")
        print("Your secure messaging system is now using PostgreSQL.")

def main():
    """Main migration function"""
    print("🔄 JSON to PostgreSQL Migration Tool")
    print("=" * 50)
    
    # Check if database is accessible
    if not db_config.test_connection():
        print("❌ Cannot connect to PostgreSQL database!")
        print("Please ensure PostgreSQL is running and configured correctly.")
        return False
    
    # Run migration
    migrator = DataMigrator()
    success = migrator.run_migration()
    
    if success:
        print("\n🎉 Migration completed successfully!")
        print("You can now start using PostgreSQL with your secure messaging system.")
        return True
    else:
        print("\n❌ Migration failed!")
        print("Please check the logs above for details.")
        return False

if __name__ == "__main__":
    sys.exit(0 if main() else 1)