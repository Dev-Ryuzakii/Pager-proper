"""
TLS Server PostgreSQL Integration
Allows the existing TLS server to work with PostgreSQL database
"""

import os
import json
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

from database_config import db_config
from database_models import User, Message, UserKey, UserSession, AuditLog

class TLSPostgreSQLService:
    """Service to integrate TLS server with PostgreSQL database"""
    
    def __init__(self):
        self.session = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database connection"""
        if not db_config.initialize_database():
            raise Exception("Failed to initialize PostgreSQL database")
        self.session = db_config.get_session()
    
    def register_tls_user(self, username: str, public_key: str, token: str, client_ip: str = None) -> bool:
        """Register a TLS user in PostgreSQL"""
        try:
            # Check if user already exists
            existing_user = self.session.query(User).filter(User.username == username).first()
            if existing_user:
                # Update existing user (in case they're re-registering)
                existing_user.public_key = public_key
                existing_user.token = token
                existing_user.last_login = datetime.now(timezone.utc)
                existing_user.registration_ip = client_ip or existing_user.registration_ip
                if existing_user.user_type == "mobile":
                    existing_user.user_type = "both"  # Can use both TLS and mobile
                self.session.commit()
                return True
            
            # Create new TLS user
            user = User(
                username=username,
                email=None,  # TLS users don't have email
                public_key=public_key,
                token=token,
                registration_ip=client_ip,
                device_id=None,
                push_token=None,
                device_info=None,
                is_active=True,
                is_verified=True,
                user_type="tls"
            )
            
            self.session.add(user)
            self.session.commit()
            
            # Log registration
            self._log_audit_event(user.id, "tls_registration", f"TLS user {username} registered", client_ip)
            
            return True
            
        except Exception as e:
            self.session.rollback()
            print(f"Error registering TLS user: {e}")
            return False
    
    def authenticate_tls_user(self, username: str, token: str, client_ip: str = None) -> Optional[User]:
        """Authenticate TLS user"""
        try:
            user = self.session.query(User).filter(
                User.username == username,
                User.token == token,
                User.is_active == True
            ).first()
            
            if user:
                # Update last login
                user.last_login = datetime.now(timezone.utc)
                self.session.commit()
                
                # Log login
                self._log_audit_event(user.id, "tls_login", f"TLS user {username} logged in", client_ip)
                
            return user
            
        except Exception as e:
            print(f"Error authenticating TLS user: {e}")
            return None
    
    def store_tls_message(self, sender_username: str, recipient_username: str, 
                         encrypted_payload: str, client_ip: str = None) -> bool:
        """Store TLS message in PostgreSQL"""
        try:
            # Get sender and recipient
            sender = self.session.query(User).filter(User.username == sender_username).first()
            recipient = self.session.query(User).filter(User.username == recipient_username).first()
            
            if not sender or not recipient:
                return False
            
            # Create message
            message = Message(
                sender_id=sender.id,
                recipient_id=recipient.id,
                encrypted_content=encrypted_payload,
                content_type="tls_encrypted",
                delivered=False,
                read=False,
                is_offline=True,
                encryption_algorithm="TLS-RSA+AES256-GCM"
            )
            
            self.session.add(message)
            self.session.commit()
            
            # Log message
            self._log_audit_event(
                sender.id, "tls_message_sent", 
                f"TLS message sent to {recipient_username}", 
                client_ip
            )
            
            return True
            
        except Exception as e:
            self.session.rollback()
            print(f"Error storing TLS message: {e}")
            return False
    
    def get_offline_messages(self, username: str) -> list:
        """Get offline messages for TLS user"""
        try:
            user = self.session.query(User).filter(User.username == username).first()
            if not user:
                return []
            
            messages = self.session.query(Message).filter(
                Message.recipient_id == user.id,
                Message.is_offline == True,
                Message.delivered == False
            ).order_by(Message.timestamp.asc()).all()
            
            result = []
            for msg in messages:
                sender = self.session.query(User).filter(User.id == msg.sender_id).first()
                result.append({
                    "type": "message",
                    "sender": sender.username if sender else "unknown",
                    "payload": msg.encrypted_content,
                    "timestamp": msg.timestamp.timestamp(),
                    "message_id": msg.id
                })
                
                # Mark as delivered
                msg.delivered = True
                msg.is_offline = False
            
            self.session.commit()
            return result
            
        except Exception as e:
            print(f"Error getting offline messages: {e}")
            return []
    
    def get_user_public_key(self, username: str) -> Optional[str]:
        """Get user's public key"""
        try:
            user = self.session.query(User).filter(
                User.username == username,
                User.is_active == True
            ).first()
            
            return user.public_key if user else None
            
        except Exception as e:
            print(f"Error getting public key: {e}")
            return None
    
    def get_user_list(self) -> Dict[str, list]:
        """Get list of registered and online users"""
        try:
            # Get all registered users
            all_users = self.session.query(User).filter(User.is_active == True).all()
            registered_users = [user.username for user in all_users]
            
            # Get online users (users with recent activity - within last 5 minutes)
            recent_time = datetime.now(timezone.utc).timestamp() - 300  # 5 minutes ago
            online_users = []
            
            # For TLS integration, we'd need to track online status differently
            # This is a simplified version - in practice, you'd track active connections
            
            return {
                "registered_users": registered_users,
                "online_users": online_users  # TLS server tracks this separately
            }
            
        except Exception as e:
            print(f"Error getting user list: {e}")
            return {"registered_users": [], "online_users": []}
    
    def update_user_activity(self, username: str, client_ip: str = None):
        """Update user's last activity"""
        try:
            user = self.session.query(User).filter(User.username == username).first()
            if user:
                user.last_login = datetime.now(timezone.utc)
                self.session.commit()
        except Exception as e:
            print(f"Error updating user activity: {e}")
    
    def _log_audit_event(self, user_id: Optional[int], event_type: str, description: str, 
                        ip_address: str = None, severity: str = "info"):
        """Log audit event"""
        try:
            audit_log = AuditLog(
                user_id=user_id,
                event_type=event_type,
                event_description=description,
                severity=severity,
                ip_address=ip_address
            )
            
            self.session.add(audit_log)
            self.session.commit()
            
        except Exception as e:
            print(f"Error logging audit event: {e}")
    
    def export_to_json_format(self) -> Dict[str, Any]:
        """Export users to JSON format for TLS server compatibility"""
        try:
            users = self.session.query(User).filter(User.is_active == True).all()
            
            user_data = {}
            for user in users:
                user_data[user.username] = {
                    "public_key": user.public_key,
                    "token": user.token,
                    "registered": user.registered.timestamp(),
                    "registration_ip": user.registration_ip,
                    "last_login": user.last_login.timestamp() if user.last_login else None
                }
            
            return {
                "users": user_data,
                "last_updated": time.time(),
                "server_version": "2.1-PostgreSQL"
            }
            
        except Exception as e:
            print(f"Error exporting to JSON format: {e}")
            return {"users": {}, "last_updated": time.time(), "server_version": "2.1-PostgreSQL"}
    
    def close(self):
        """Close database session"""
        if self.session:
            self.session.close()

# Global service instance
tls_pg_service = None

def get_tls_postgresql_service():
    """Get or create TLS PostgreSQL service instance"""
    global tls_pg_service
    if not tls_pg_service:
        tls_pg_service = TLSPostgreSQLService()
    return tls_pg_service

def test_tls_postgresql_integration():
    """Test the TLS PostgreSQL integration"""
    print("🧪 Testing TLS PostgreSQL Integration")
    print("=" * 40)
    
    try:
        service = get_tls_postgresql_service()
        
        # Test user registration
        print("1. Testing user registration...")
        success = service.register_tls_user("test_tls_user", "test_public_key", "test_token", "127.0.0.1")
        print(f"   Registration: {'✅ Success' if success else '❌ Failed'}")
        
        # Test authentication
        print("2. Testing authentication...")
        user = service.authenticate_tls_user("test_tls_user", "test_token", "127.0.0.1")
        print(f"   Authentication: {'✅ Success' if user else '❌ Failed'}")
        
        # Test user list
        print("3. Testing user list...")
        user_list = service.get_user_list()
        print(f"   User list: {len(user_list['registered_users'])} registered users")
        
        # Test JSON export
        print("4. Testing JSON export...")
        json_data = service.export_to_json_format()
        print(f"   JSON export: {len(json_data['users'])} users exported")
        
        print("\n🎉 TLS PostgreSQL integration test completed!")
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")

if __name__ == "__main__":
    test_tls_postgresql_integration()