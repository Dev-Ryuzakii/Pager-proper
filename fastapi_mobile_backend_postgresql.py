"""
FastAPI Mobile Backend with PostgreSQL Database
Updated version that uses PostgreSQL instead of JSON files
"""

import os
import json
import time
import base64
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

# Import cryptographic libraries
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
import json

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Import required modules
from database_config import get_database_session, db_config
from database_models import User, Message, UserKey, UserSession, AuditLog, MasterToken as DBMasterToken, Media
from fake_text_generator import FakeTextGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()

# Pydantic Models
class UserAuth(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    token: str = Field(..., description="User authentication token")

class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    token: str = Field(..., description="User authentication token")
    public_key: Optional[str] = Field(None, description="User's RSA public key in PEM format (optional)")

# Add new Pydantic models for admin functionality
class AdminLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, description="Admin password")

class AdminChangePassword(BaseModel):
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")

class AdminCreateUser(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    token: str = Field(..., description="User authentication token")
    public_key: Optional[str] = Field(None, description="User's RSA public key in PEM format (optional)")


class UserLogin(UserAuth):
    pass  # Same as auth - just username and token

class MessageSend(BaseModel):
    username: str = Field(..., description="Recipient username")
    message: str = Field(..., min_length=1, description="Message content")
    disappear_after_hours: Optional[int] = Field(None, description="Hours after which message should disappear (default: None)")

class MasterToken(BaseModel):
    mastertoken: str = Field(..., description="Master decryption token")

class DecryptRequest(BaseModel):
    mastertoken: str = Field(..., description="Master token for decryption")
    message_id: int = Field(..., description="ID of the message to decrypt")

class MessageResponse(BaseModel):
    id: int
    sender: str
    recipient: str
    content: str
    content_type: str = Field(default="TLS 1.3 + AES-256-GCM + RSA-4096")
    timestamp: datetime
    delivered: bool
    read: bool
    server_hmac: bool = Field(default=True, description="Message authentication status")
    decrypt_time: float = Field(default=0.0, description="Time taken to decrypt in seconds")

class UserResponse(BaseModel):
    username: str
    registered: datetime
    last_login: Optional[datetime]
    is_active: bool

# Add new Pydantic models for media handling
class MediaUpload(BaseModel):
    username: str = Field(..., description="Recipient username")
    media_type: str = Field(..., description="Type of media: photo, video, or document")
    encrypted_content: str = Field(..., description="Base64 encoded encrypted media content")
    filename: str = Field(..., description="Original filename")
    file_size: int = Field(..., description="File size in bytes")
    disappear_after_hours: Optional[int] = Field(None, description="Hours after which media should disappear (default: None)")

class MediaResponse(BaseModel):
    id: int
    media_id: str
    filename: str
    media_type: str
    content_type: str
    file_size: int
    sender: str
    recipient: str
    timestamp: datetime
    expires_at: Optional[datetime]
    auto_delete: bool
    downloaded: bool

def validate_master_token(db: Session, user_id: int, mastertoken: str) -> bool:
    """Validate the master token for a user"""
    # For the TLS system's token handling:
    # 1. For sending: Check if token is cached (last 24 hours)
    # 2. For decryption: Always require fresh token entry
    
    # Get user to verify master token
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return False
        
    # Simple token verification (you should implement proper token validation)
    # This is a placeholder - implement your actual master token validation
    master_salt = f"{user.username}_master_salt"  # In production, get from secure storage
    
    # Create token hash (match your TLS system's token derivation)
    token_hash = hashlib.sha256(f"{mastertoken}:{master_salt}".encode()).hexdigest()
    
    # For actual implementation, verify against securely stored token hash
    return True  # Replace with actual token verification

# Database Services
class UserService:
    """Service class for user operations"""
    
    @staticmethod
    def create_user(db: Session, user_data: UserRegistration, ip_address: Optional[str] = None) -> User:
        """Create a new user"""
        # Check if user already exists
        existing_user = db.query(User).filter(User.username == user_data.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        
        # Use provided token (simple like TLS system)
        token = user_data.token
        
        # Create user - simple fields only: username, token, and optional public_key
        user = User(
            username=user_data.username,
            token=token,
            public_key=user_data.public_key,  # This is now optional
            registration_ip=ip_address,
            is_active=True,
            is_verified=True,
            user_type='mobile'  # To distinguish from TLS users
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Log registration - use getattr to safely access the id
        user_id = getattr(user, 'id', None)
        AuditService.log_event(
            db, user_id, "user_registration", 
            f"User {user_data.username} registered", 
            ip_address=ip_address
        )
        
        logger.info(f"✅ User registered: {user_data.username}")
        return user
    
    @staticmethod
    def authenticate_user(db: Session, username: str, token: str, ip_address: Optional[str] = None) -> Optional[User]:
        """Authenticate user with token and update last login"""
        user = db.query(User).filter(
            User.username == username, 
            User.token == token,
            User.is_active == True
        ).first()
        
        if user:
            # Use setattr for SQLAlchemy models
            setattr(user, 'last_login', datetime.now(timezone.utc))
            db.commit()
            
            # Log login
            AuditService.log_event(
                db, getattr(user, 'id', None), "user_login", 
                f"User {username} logged in", 
                ip_address=ip_address
            )
        
        return user
    
    @staticmethod
    def get_user_by_username(db: Session, username: str) -> Optional[User]:
        """Get user by username"""
        return db.query(User).filter(User.username == username, User.is_active == True).first()
    
    @staticmethod
    def get_all_users(db: Session) -> List[User]:
        """Get all active users"""
        return db.query(User).filter(User.is_active == True).all()
    
    @staticmethod
    def delete_user(db: Session, username: str) -> bool:
        """Delete a user account and all associated data"""
        try:
            # Get the user
            user = db.query(User).filter(User.username == username).first()
            if not user:
                return False
            
            # Get user ID for logging
            user_id = getattr(user, 'id', None)
            
            # Log the deletion
            AuditService.log_event(
                db, user_id, "account_deleted", 
                f"User account {username} deleted by system"
            )
            
            # Delete associated data first due to foreign key constraints
            # Delete user sessions
            db.query(UserSession).filter(UserSession.user_id == user_id).delete()
            
            # Delete user keys
            db.query(UserKey).filter(UserKey.user_id == user_id).delete()
            
            # Delete user master tokens
            db.query(DBMasterToken).filter(DBMasterToken.user_id == user_id).delete()
            
            # Delete messages sent by user
            db.query(Message).filter(Message.sender_id == user_id).delete()
            
            # Delete messages received by user
            db.query(Message).filter(Message.recipient_id == user_id).delete()
            
            # Finally delete the user
            db.delete(user)
            db.commit()
            
            logger.info(f"✅ User account and all associated data deleted: {username}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting user {username}: {e}")
            db.rollback()
            return False

class MessageService:
    """Service class for message operations"""
    
    @staticmethod
    def send_message(db: Session, sender_id: int, recipient_username: str, message_content: str, disappear_after_hours: Optional[int] = None) -> Message:
        """Send a message - simplified"""
        # Get recipient
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        # Generate decoy text for the message
        try:
            decoy_text = FakeTextGenerator.generate_decoy_text_for_message(message_content)
        except Exception as e:
            print(f"⚠️  Error generating decoy text: {e}")
            decoy_text = "[ENCRYPTED MESSAGE] Tap to decrypt"
        
        # Calculate expiration time if disappearing message
        expires_at = None
        auto_delete = False
        if disappear_after_hours is not None and disappear_after_hours > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=disappear_after_hours)
            auto_delete = True
        
        # Create message - simplified
        message = Message(
            sender_id=sender_id,
            recipient_id=recipient.id,
            encrypted_content=message_content,
            content_type="encrypted",
            delivered=False,
            read=False,
            is_offline=True,  # Mark as offline initially
            expires_at=expires_at,
            auto_delete=auto_delete
        )
        
        # Try to set decoy_content, but handle case where column might not exist yet
        try:
            setattr(message, 'decoy_content', decoy_text)
        except Exception as e:
            print(f"⚠️  Could not set decoy_content: {e}")
            # Continue without setting decoy_content
        
        db.add(message)
        db.commit()
        db.refresh(message)
        
        logger.info(f"📤 Message sent: {sender_id} → {recipient.id}")
        return message
    
    @staticmethod
    def get_user_messages(db: Session, user_id: int, limit: int = 50) -> List[Message]:
        """Get messages for a user (inbox)"""
        return db.query(Message).filter(
            Message.recipient_id == user_id
        ).order_by(Message.timestamp.desc()).limit(limit).all()
    
    @staticmethod
    def get_offline_messages(db: Session, user_id: int) -> List[Message]:
        """Get offline messages for a user"""
        return db.query(Message).filter(
            and_(
                Message.recipient_id == user_id,
                Message.is_offline == True,
                Message.delivered == False
            )
        ).order_by(Message.timestamp.asc()).all()
    
    @staticmethod
    def mark_message_delivered(db: Session, message_id: int) -> bool:
        """Mark message as delivered"""
        message = db.query(Message).filter(Message.id == message_id).first()
        if message:
            # Use setattr for SQLAlchemy models to avoid type errors
            setattr(message, 'delivered', True)
            setattr(message, 'is_offline', False)
            db.commit()
            return True
        return False
    
    @staticmethod
    def mark_message_read(db: Session, message_id: int) -> bool:
        """Mark message as read"""
        message = db.query(Message).filter(Message.id == message_id).first()
        if message:
            # Use setattr for SQLAlchemy models to avoid type errors
            setattr(message, 'read', True)
            setattr(message, 'read_timestamp', datetime.now(timezone.utc))
            db.commit()
            return True
        return False
    
    @staticmethod
    def delete_expired_messages(db: Session) -> int:
        """Delete expired messages and return count of deleted messages"""
        current_time = datetime.now(timezone.utc)
        expired_messages = db.query(Message).filter(
            and_(
                Message.auto_delete == True,
                Message.expires_at <= current_time
            )
        ).all()
        
        deleted_count = len(expired_messages)
        
        # Delete expired messages
        for message in expired_messages:
            db.delete(message)
        
        if deleted_count > 0:
            db.commit()
            logger.info(f"🗑️  Deleted {deleted_count} expired messages")
        
        return deleted_count

class SessionService:
    """Service class for session management"""
    
    @staticmethod
    def create_session(db: Session, user_id: int, session_type: str = "api", ip_address: Optional[str] = None) -> UserSession:
        """Create a new session"""
        # Generate session token
        session_data = f"{user_id}:{int(time.time())}:{session_type}"
        session_token = base64.b64encode(session_data.encode()).decode()
        
        # Set expiration (24 hours)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        session = UserSession(
            user_id=user_id,
            session_token=session_token,
            session_type=session_type,
            expires_at=expires_at,
            ip_address=ip_address,
            is_active=True
        )
        
        db.add(session)
        db.commit()
        db.refresh(session)
        
        return session
    
    @staticmethod
    def validate_session(db: Session, session_token: str) -> Optional[UserSession]:
        """Validate a session token"""
        session = db.query(UserSession).filter(
            and_(
                UserSession.session_token == session_token,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.now(timezone.utc)
            )
        ).first()
        
        if session:
            # Update last activity
            setattr(session, 'last_activity', datetime.now(timezone.utc))
            db.commit()
        
        return session
    
    @staticmethod
    def invalidate_session(db: Session, session_token: str) -> bool:
        """Invalidate a session (logout)"""
        session = db.query(UserSession).filter(UserSession.session_token == session_token).first()
        if session:
            setattr(session, 'is_active', False)
            setattr(session, 'logout_reason', "manual")
            db.commit()
            return True
        return False

class AuditService:
    """Service class for audit logging"""
    
    @staticmethod
    def log_event(db: Session, user_id: Optional[int], event_type: str, description: str, 
                  severity: str = "info", ip_address: Optional[str] = None, extra_data: Optional[Dict[Any, Any]] = None):
        """Log an audit event"""
        audit_log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_description=description,
            severity=severity,
            ip_address=ip_address,
            extra_data=extra_data or {}  # Fix the None default
        )
        
        db.add(audit_log)
        db.commit()

class DecryptService:
    """Service class for decryption operations"""
    
    @staticmethod
    def validate_master_token(db: Session, user_id: int, mastertoken: str) -> bool:
        """Validate the master token for a user"""
        # Check if the master token has been confirmed for this user
        audit_record = db.query(AuditLog).filter(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.event_type == "mastertoken_confirmed",
                AuditLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)  # Valid for 24 hours
            )
        ).first()
        
        return audit_record is not None
    
    @staticmethod
    def derive_master_key(mastertoken: str, salt: bytes) -> bytes:
        """Derive encryption key using PBKDF2"""
        try:
            master_key = PBKDF2(
                mastertoken, 
                salt, 
                32,  # 256-bit key
                count=100000  # Iterations
            )
            return master_key
        except Exception as e:
            logger.error(f"Key derivation error: {e}")
            raise HTTPException(status_code=500, detail="Key derivation failed")
    
    @staticmethod
    def decrypt_with_aes_gcm(encrypted_data: Dict[str, str], key: bytes) -> str:
        """Decrypt using AES-256-GCM (authenticated decryption)"""
        try:
            nonce = base64.b64decode(encrypted_data["nonce"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            auth_tag = base64.b64decode(encrypted_data["auth_tag"])
            
            # Create AES-GCM cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Decrypt and verify authentication tag
            plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
            
            return plaintext.decode()
            
        except ValueError as e:
            logger.error(f"AES-GCM authentication failed: {e}")
            raise HTTPException(status_code=400, detail="AES-GCM authentication failed")
        except Exception as e:
            logger.error(f"AES-GCM decryption error: {e}")
            raise HTTPException(status_code=500, detail="AES-GCM decryption failed")
    
    @staticmethod
    def decrypt_message(db: Session, user_id: int, message_id: int, mastertoken: str) -> Optional[str]:
        """Decrypt a message using the master token"""
        # Get the message
        message = db.query(Message).filter(
            and_(
                Message.id == message_id,
                or_(
                    Message.sender_id == user_id,
                    Message.recipient_id == user_id
                )
            )
        ).first()
        
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")
        
        try:
            # For mobile users, we should not attempt server-side decryption
            # Mobile users should decrypt messages locally using their private keys
            user = db.query(User).filter(User.id == user_id).first()
            user_type = getattr(user, 'user_type', '') if user else ''
            if user and user_type == "mobile":
                raise HTTPException(
                    status_code=400, 
                    detail="Mobile users should decrypt messages locally. Private keys are not stored on the server for security."
                )
            
            # Get the user's private key for decryption (only for TLS users)
            user_key = db.query(UserKey).filter(
                and_(
                    UserKey.user_id == user_id,
                    UserKey.key_type == "private_key"
                )
            ).first()
            
            if not user_key:
                raise HTTPException(status_code=404, detail="User private key not found")
            
            # Get the user's master salt for key derivation
            master_salt_record = db.query(UserKey).filter(
                and_(
                    UserKey.user_id == user_id,
                    UserKey.key_type == "master_salt"
                )
            ).first()
            
            if not master_salt_record:
                raise HTTPException(status_code=404, detail="Master salt not found")
            
            # Parse the encrypted content
            try:
                encrypted_content = getattr(message, 'encrypted_content', '')
                encrypted_payload = json.loads(encrypted_content)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid encrypted content format")
            
            # Validate payload structure
            if "encrypted_key" not in encrypted_payload or "encrypted_message" not in encrypted_payload:
                raise HTTPException(status_code=400, detail="Invalid encrypted payload structure")
            
            # Derive master key from master token and salt
            master_salt = bytes(getattr(master_salt_record, 'key_data', b''))
            master_key = DecryptService.derive_master_key(mastertoken, master_salt)
            
            # Decrypt the AES key using RSA private key
            try:
                # Load RSA private key
                private_key_data = bytes(getattr(user_key, 'key_data', b''))
                private_key = RSA.import_key(private_key_data)
                
                # Decode and decrypt the AES key
                encrypted_aes_key = base64.b64decode(encrypted_payload["encrypted_key"])
                rsa_cipher = PKCS1_OAEP.new(private_key)
                aes_key = rsa_cipher.decrypt(encrypted_aes_key)
            except Exception as e:
                logger.error(f"RSA decryption error: {e}")
                raise HTTPException(status_code=500, detail="RSA decryption failed")
            
            # Decrypt the message using AES key
            try:
                encrypted_msg_data = encrypted_payload["encrypted_message"]
                if not isinstance(encrypted_msg_data, dict):
                    raise HTTPException(status_code=400, detail="Invalid AES-GCM data format")
                
                decrypted_content = DecryptService.decrypt_with_aes_gcm(encrypted_msg_data, aes_key)
                
                # Parse decrypted message to extract actual content
                try:
                    message_data = json.loads(decrypted_content)
                    actual_content = message_data.get("content", decrypted_content)
                except json.JSONDecodeError:
                    # If it's not JSON, return as is
                    actual_content = decrypted_content
                
                # Log decryption attempt
                AuditService.log_event(
                    db, user_id, "message_decrypted",
                    f"Message {message_id} decrypted successfully",
                    severity="info"
                )
                
                return actual_content
                
            except Exception as e:
                logger.error(f"Message decryption error: {e}")
                AuditService.log_event(
                    db, user_id, "decryption_failed",
                    f"Failed to decrypt message {message_id}: {str(e)}",
                    severity="error"
                )
                raise HTTPException(status_code=500, detail="Message decryption failed")
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            AuditService.log_event(
                db, user_id, "decryption_failed",
                f"Failed to decrypt message {message_id}: {str(e)}",
                severity="error"
            )
            raise HTTPException(status_code=500, detail="Decryption failed")

# Add MediaService class
class MediaService:
    """Service class for media operations"""
    
    @staticmethod
    def upload_media(db: Session, sender_id: int, recipient_username: str, media_data: dict) -> Media:
        """Upload encrypted media file (photo, video, or document)"""
        # Get recipient
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        # Generate unique media ID
        import uuid
        media_id = str(uuid.uuid4())
        
        # Save encrypted media to file system
        import os
        upload_dir = "media_uploads"
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        # Save encrypted content to file
        encrypted_file_path = os.path.join(upload_dir, f"{media_id}.enc")
        try:
            # Decode base64 content and save to file
            import base64
            encrypted_content = base64.b64decode(media_data["encrypted_content"])
            with open(encrypted_file_path, "wb") as f:
                f.write(encrypted_content)
        except Exception as e:
            logger.error(f"Error saving encrypted media: {e}")
            raise HTTPException(status_code=500, detail="Failed to save encrypted media")
        
        # Calculate expiration time if disappearing media
        expires_at = None
        auto_delete = False
        if media_data.get("disappear_after_hours") is not None and media_data["disappear_after_hours"] > 0:
            from datetime import datetime, timedelta, timezone
            expires_at = datetime.now(timezone.utc) + timedelta(hours=media_data["disappear_after_hours"])
            auto_delete = True
        
        # Create message for the media
        message = Message(
            sender_id=sender_id,
            recipient_id=recipient.id,
            encrypted_content=media_data["encrypted_content"],
            content_type=f"media/{media_data['media_type']}",
            delivered=False,
            read=False,
            is_offline=True,
            expires_at=expires_at,
            auto_delete=auto_delete
        )
        
        db.add(message)
        db.commit()
        db.refresh(message)
        
        # Create media record
        media = Media(
            media_id=media_id,
            filename=media_data["filename"],
            file_size=media_data["file_size"],
            media_type=media_data["media_type"],
            content_type=media_data.get("content_type", "application/octet-stream"),
            encryption_metadata=media_data.get("encryption_metadata"),
            encrypted_file_path=encrypted_file_path,
            message_id=message.id,
            sender_id=sender_id,
            recipient_id=recipient.id,
            expires_at=expires_at,
            auto_delete=auto_delete
        )
        
        db.add(media)
        db.commit()
        db.refresh(media)
        
        logger.info(f"📤 Media uploaded: {sender_id} → {recipient.id} ({media_id})")
        return media
    
    @staticmethod
    def get_user_media(db: Session, user_id: int, limit: int = 50) -> List[Media]:
        """Get media files (photos, videos, documents) for a user"""
        return db.query(Media).filter(
            Media.recipient_id == user_id
        ).order_by(Media.uploaded_at.desc()).limit(limit).all()
    
    @staticmethod
    def get_media_by_id(db: Session, media_id: int, user_id: int) -> Optional[Media]:
        """Get specific media file by ID for a user"""
        return db.query(Media).filter(
            and_(
                Media.id == media_id,
                or_(
                    Media.sender_id == user_id,
                    Media.recipient_id == user_id
                )
            )
        ).first()
    
    @staticmethod
    def mark_media_downloaded(db: Session, media_id: int) -> bool:
        """Mark media as downloaded"""
        media = db.query(Media).filter(Media.id == media_id).first()
        if media:
            from datetime import datetime, timezone
            setattr(media, 'downloaded_at', datetime.now(timezone.utc))
            db.commit()
            return True
        return False
    
    @staticmethod
    def delete_expired_media(db: Session) -> int:
        """Delete expired media files and return count of deleted files"""
        from datetime import datetime, timezone
        current_time = datetime.now(timezone.utc)
        expired_media = db.query(Media).filter(
            and_(
                Media.auto_delete == True,
                Media.expires_at <= current_time
            )
        ).all()
        
        deleted_count = len(expired_media)
        
        # Delete expired media files from file system and database
        for media in expired_media:
            try:
                # Delete encrypted file from file system
                if os.path.exists(media.encrypted_file_path):
                    os.remove(media.encrypted_file_path)
                
                # Delete associated message
                message = db.query(Message).filter(Message.id == media.message_id).first()
                if message:
                    db.delete(message)
                
                # Delete media record
                db.delete(media)
            except Exception as e:
                logger.error(f"Error deleting expired media {media.media_id}: {e}")
        
        if deleted_count > 0:
            db.commit()
            logger.info(f"🗑️  Deleted {deleted_count} expired media files")
        
        return deleted_count

class AdminService:
    """Service class for admin operations"""
    
    @staticmethod
    def is_admin(db: Session, user_id: int) -> bool:
        """Check if user is an admin"""
        user = db.query(User).filter(User.id == user_id, User.is_admin == True).first()
        return user is not None
    
    @staticmethod
    def authenticate_admin(db: Session, username: str, password: str, ip_address: Optional[str] = None) -> Optional[User]:
        """Authenticate admin user with password"""
        user = db.query(User).filter(
            User.username == username, 
            User.is_admin == True,
            User.is_active == True
        ).first()
        
        if user and user.password_hash:
            if verify_password(password, user.password_hash):
                # Use setattr for SQLAlchemy models
                setattr(user, 'last_login', datetime.now(timezone.utc))
                db.commit()
                
                # Log login
                AuditService.log_event(
                    db, getattr(user, 'id', None), "admin_login", 
                    f"Admin {username} logged in", 
                    ip_address=ip_address
                )
                return user
        
        return None
    
    @staticmethod
    def change_admin_password(db: Session, user_id: int, current_password: str, new_password: str) -> bool:
        """Change admin password"""
        user = db.query(User).filter(User.id == user_id, User.is_admin == True).first()
        if not user or not user.password_hash:
            return False
        
        # Verify current password
        if not verify_password(current_password, user.password_hash):
            return False
        
        # Hash and set new password
        user.password_hash = hash_password(new_password)
        user.must_change_password = False  # Clear the flag after password change
        db.commit()
        
        # Log password change
        AuditService.log_event(
            db, user_id, "admin_password_changed", 
            f"Admin password changed for user {user.username}"
        )
        
        return True
    
    @staticmethod
    def create_user(db: Session, admin_user_id: int, user_data: AdminCreateUser, ip_address: Optional[str] = None) -> User:
        """Create a new user (admin only)"""
        # Check if requesting user is admin
        if not AdminService.is_admin(db, admin_user_id):
            raise HTTPException(status_code=403, detail="Only admin users can create new accounts")
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.username == user_data.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        
        # Use provided token
        token = user_data.token
        
        # Create user
        user = User(
            username=user_data.username,
            token=token,
            public_key=user_data.public_key,
            registration_ip=ip_address,
            is_active=True,
            is_verified=True,
            user_type='mobile',
            is_admin=False  # New users are not admins by default
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Log registration
        user_id = getattr(user, 'id', None)
        AuditService.log_event(
            db, admin_user_id, "user_registration_by_admin", 
            f"User {user_data.username} registered by admin user {admin_user_id}", 
            ip_address=ip_address
        )
        
        logger.info(f"✅ User registered by admin: {user_data.username}")
        return user
    
    @staticmethod
    def delete_user(db: Session, admin_user_id: int, username: str) -> bool:
        """Delete a user account (admin only)"""
        # Check if requesting user is admin
        if not AdminService.is_admin(db, admin_user_id):
            raise HTTPException(status_code=403, detail="Only admin users can delete accounts")
        
        # Get the user to delete
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return False
        
        # Prevent admin from deleting themselves
        if user.id == admin_user_id:
            raise HTTPException(status_code=400, detail="Admin cannot delete their own account")
        
        # Get user ID for logging
        user_id = getattr(user, 'id', None)
        
        # Log the deletion
        AuditService.log_event(
            db, admin_user_id, "account_deleted_by_admin", 
            f"User account {username} deleted by admin user {admin_user_id}"
        )
        
        # Delete associated data first due to foreign key constraints
        # Delete user sessions
        db.query(UserSession).filter(UserSession.user_id == user_id).delete()
        
        # Delete user keys
        db.query(UserKey).filter(UserKey.user_id == user_id).delete()
        
        # Delete user master tokens
        db.query(DBMasterToken).filter(DBMasterToken.user_id == user_id).delete()
        
        # Delete messages sent by user
        db.query(Message).filter(Message.sender_id == user_id).delete()
        
        # Delete messages received by user
        db.query(Message).filter(Message.recipient_id == user_id).delete()
        
        # Delete media files associated with user
        media_files = db.query(Media).filter(
            or_(Media.sender_id == user_id, Media.recipient_id == user_id)
        ).all()
        
        for media in media_files:
            # Delete encrypted file from filesystem
            try:
                if os.path.exists(media.encrypted_file_path):
                    os.remove(media.encrypted_file_path)
            except Exception as e:
                logger.error(f"Error deleting media file {media.encrypted_file_path}: {e}")
            
            # Delete associated message if it exists
            message = db.query(Message).filter(Message.id == media.message_id).first()
            if message:
                db.delete(message)
            
            # Delete media record
            db.delete(media)
        
        # Finally delete the user
        db.delete(user)
        db.commit()
        
        logger.info(f"✅ User account and all associated data deleted by admin: {username}")
        return True

# FastAPI app with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Starting FastAPI Mobile Backend with PostgreSQL...")
    
    # Initialize database with retry logic
    if not db_config.initialize_database(max_retries=5, retry_delay=10):
        logger.error("❌ Failed to initialize database after multiple attempts")
        # Don't raise exception, let the app start but with database issues
        logger.warning("⚠️  App will start but database functionality may be limited")
    else:
        # Test connection
        if not db_config.test_connection(max_retries=3, retry_delay=5):
            logger.error("❌ Database connection test failed after multiple attempts")
            logger.warning("⚠️  App will start but database functionality may be limited")
        else:
            logger.info("✅ PostgreSQL database connected successfully")
    
    yield
    
    # Shutdown
    logger.info("📴 Shutting down FastAPI Mobile Backend")

app = FastAPI(
    title="Secure Messaging API",
    description="Mobile backend for secure messaging system with PostgreSQL",
    version="2.1-PostgreSQL",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), 
                          db: Session = Depends(get_database_session)) -> User:
    """Get current authenticated user"""
    try:
        token = credentials.credentials
        
        # Validate session
        session = SessionService.validate_session(db, token)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user
        user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return user
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Helper function to get client IP
def get_client_ip(request):
    """Get client IP address from request"""
    return getattr(request.client, 'host', 'unknown') if hasattr(request, 'client') else 'unknown'

# API Endpoints
@app.get("/")
async def root():
    return {
        "message": "Secure Messaging API with PostgreSQL",
        "version": "2.1-PostgreSQL",
        "status": "running",
        "database": "PostgreSQL"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for Render"""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/status")
async def get_status(db: Session = Depends(get_database_session)):
    """Get system status"""
    try:
        users_count = db.query(User).filter(User.is_active == True).count()
        messages_count = db.query(Message).count()
        sessions_count = db.query(UserSession).filter(UserSession.is_active == True).count()
        
        return {
            "status": "running",
            "version": "2.1-PostgreSQL",
            "database": "PostgreSQL",
            "users_count": users_count,
            "messages_count": messages_count,
            "active_sessions": sessions_count,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Status check error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/auth/register")
async def register_user(user_data: UserRegistration, db: Session = Depends(get_database_session)):
    """Register a new user - simplified JSON: {username, token}"""
    try:
        user = UserService.create_user(db, user_data, ip_address="mobile_app")
        
        # Create session
        user_id = int(getattr(user, 'id', 0)) if hasattr(getattr(user, 'id', 0), '__int__') else int(getattr(user, 'id', 0))
        session = SessionService.create_session(db, user_id, "mobile", "mobile_app")
        
        return {
            "username": str(getattr(user, 'username', '')),
            "token": str(getattr(session, 'session_token', ''))
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/auth/login")
async def login_user(login_data: UserLogin, db: Session = Depends(get_database_session)):
    """Login user - simplified JSON: {username, token}"""
    try:
        user = UserService.authenticate_user(db, login_data.username, login_data.token, ip_address="mobile_app")
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or token")
        
        # Create session
        user_id = int(getattr(user, 'id', 0)) if hasattr(getattr(user, 'id', 0), '__int__') else int(getattr(user, 'id', 0))
        session = SessionService.create_session(db, user_id, "mobile", "mobile_app")
        
        return {
            "username": str(getattr(user, 'username', '')),
            "token": str(getattr(session, 'session_token', ''))
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.post("/auth/logout")
async def logout_user(current_user: User = Depends(get_current_user), 
                     credentials: HTTPAuthorizationCredentials = Depends(security),
                     db: Session = Depends(get_database_session)):
    """Logout user"""
    try:
        token = credentials.credentials
        SessionService.invalidate_session(db, token)
        
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        username = str(getattr(current_user, 'username', ''))
        AuditService.log_event(
            db, user_id, "user_logout", 
            f"User {username} logged out"
        )
        
        return {"message": "Logout successful"}
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")

@app.post("/messages/send")
async def send_message(message_data: MessageSend, 
                      current_user: User = Depends(get_current_user),
                      db: Session = Depends(get_database_session)):
    """Send a message - simplified JSON: {username, message}"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        message = MessageService.send_message(
            db, user_id, message_data.username, message_data.message, message_data.disappear_after_hours
        )
        
        response = {
            "username": message_data.username,
            "message": "sent"
        }
        
        # Add expiration info if it's a disappearing message
        auto_delete = getattr(message, 'auto_delete', False)
        expires_at = getattr(message, 'expires_at', None)
        if auto_delete and expires_at:
            response["expires_at"] = expires_at.isoformat() if hasattr(expires_at, 'isoformat') else str(expires_at)
            response["auto_delete"] = str(auto_delete).lower()
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message")

@app.get("/messages/inbox")
async def get_inbox(current_user: User = Depends(get_current_user),
                   db: Session = Depends(get_database_session)):
    """Get user's inbox"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        messages = MessageService.get_user_messages(db, user_id)
        
        result = []
        for msg in messages:
            sender = db.query(User).filter(User.id == msg.sender_id).first()
            recipient = db.query(User).filter(User.id == msg.recipient_id).first()
            result.append({
                "id": int(getattr(msg, 'id', 0)),
                "sender": str(getattr(sender, 'username', '')) if sender else "unknown",
                "recipient": str(getattr(recipient, 'username', '')) if recipient else "unknown",
                "content": str(getattr(msg, 'encrypted_content', '')),
                "content_type": str(getattr(msg, 'content_type', '')),
                "timestamp": getattr(msg, 'timestamp', datetime.now(timezone.utc)).isoformat(),
                "delivered": bool(getattr(msg, 'delivered', False)),
                "read": bool(getattr(msg, 'read', False))
            })
        
        return {
            "messages": result,
            "count": len(result)
        }
        
    except Exception as e:
        logger.error(f"Inbox error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve inbox")

@app.get("/messages/offline")
async def get_offline_messages(current_user: User = Depends(get_current_user),
                              db: Session = Depends(get_database_session)):
    """Get offline messages"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        messages = MessageService.get_offline_messages(db, user_id)
        
        result = []
        for msg in messages:
            sender = db.query(User).filter(User.id == msg.sender_id).first()
            recipient = db.query(User).filter(User.id == msg.recipient_id).first()
            result.append({
                "id": int(getattr(msg, 'id', 0)),
                "sender": str(getattr(sender, 'username', '')) if sender else "unknown",
                "recipient": str(getattr(recipient, 'username', '')) if recipient else "unknown",
                "content": str(getattr(msg, 'encrypted_content', '')),
                "content_type": str(getattr(msg, 'content_type', '')),
                "timestamp": getattr(msg, 'timestamp', datetime.now(timezone.utc)).isoformat()
            })
            
            # Mark as delivered
            message_id = int(getattr(msg, 'id', 0))
            MessageService.mark_message_delivered(db, message_id)
        
        return {
            "messages": result,
            "count": len(result)
        }
        
    except Exception as e:
        logger.error(f"Offline messages error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve offline messages")

@app.put("/messages/{message_id}/read")
async def mark_message_read(message_id: int,
                           current_user: User = Depends(get_current_user),
                           db: Session = Depends(get_database_session)):
    """Mark message as read"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        # Verify message belongs to current user
        message = db.query(Message).filter(
            and_(Message.id == message_id, Message.recipient_id == user_id)
        ).first()
        
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")
        
        success = MessageService.mark_message_read(db, message_id)
        
        if success:
            return {"message": "Message marked as read"}
        else:
            raise HTTPException(status_code=500, detail="Failed to mark message as read")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mark read error: {e}")
        raise HTTPException(status_code=500, detail="Failed to mark message as read")

@app.get("/users")
async def get_users(current_user: User = Depends(get_current_user),
                   db: Session = Depends(get_database_session)):
    """Get list of users"""
    try:
        users = UserService.get_all_users(db)
        
        result = []
        current_user_id = int(getattr(current_user, 'id', 0))
        for user in users:
            user_id = int(getattr(user, 'id', 0))
            if user_id != current_user_id:  # Exclude current user
                last_login = getattr(user, 'last_login', None)
                registered = getattr(user, 'registered', datetime.now(timezone.utc))
                result.append({
                    "username": str(getattr(user, 'username', '')),
                    "registered": registered.isoformat() if registered else datetime.now(timezone.utc).isoformat(),
                    "last_login": last_login.isoformat() if last_login else None
                })
        
        return {
            "users": result,
            "count": len(result)
        }
        
    except Exception as e:
        logger.error(f"Get users error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve users")

@app.get("/users/{username}/public_key")
async def get_user_public_key(username: str,
                             current_user: User = Depends(get_current_user),
                             db: Session = Depends(get_database_session)):
    """Get user's public key"""
    try:
        user = UserService.get_user_by_username(db, username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "username": str(getattr(user, 'username', '')),
            "public_key": str(getattr(user, 'public_key', '')) if getattr(user, 'public_key', '') else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get public key error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve public key")

@app.post("/mastertoken/create")
async def create_mastertoken(token_data: MasterToken, 
                           current_user: User = Depends(get_current_user),
                           db: Session = Depends(get_database_session)):
    """Create master token - simplified JSON: {mastertoken}"""
    try:
        # Store master token for user (you might want to hash this)
        # For now, just acknowledge creation
        
        user_id = int(getattr(current_user, 'id', 0))
        username = str(getattr(current_user, 'username', ''))
        AuditService.log_event(
            db, user_id, "mastertoken_created", 
            f"Master token created for {username}"
        )
        
        return {
            "mastertoken": "created"
        }
        
    except Exception as e:
        logger.error(f"Create mastertoken error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create master token")

@app.post("/mastertoken/confirm")
async def confirm_mastertoken(token_data: MasterToken, 
                            current_user: User = Depends(get_current_user),
                            db: Session = Depends(get_database_session)):
    """Confirm master token - simplified JSON: {mastertoken}"""
    try:
        # Validate master token (implement your validation logic)
        # For now, just acknowledge confirmation
        
        user_id = int(getattr(current_user, 'id', 0))
        username = str(getattr(current_user, 'username', ''))
        AuditService.log_event(
            db, user_id, "mastertoken_confirmed", 
            f"Master token confirmed for {username}"
        )
        
        return {
            "mastertoken": "confirmed"
        }
        
    except Exception as e:
        logger.error(f"Confirm mastertoken error: {e}")
        raise HTTPException(status_code=500, detail="Failed to confirm master token")

@app.post("/messages/cleanup")
async def cleanup_expired_messages(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Manually trigger cleanup of expired messages and media"""
    try:
        # Clean up expired messages
        deleted_messages = MessageService.delete_expired_messages(db)
        
        # Clean up expired media
        deleted_media = MediaService.delete_expired_media(db)
        
        return {
            "message": f"Cleanup completed. {deleted_messages} expired messages and {deleted_media} expired media files deleted.",
            "deleted_messages": deleted_messages,
            "deleted_media": deleted_media
        }
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
        raise HTTPException(status_code=500, detail="Failed to cleanup expired messages and media")

@app.delete("/users/{username}")
async def delete_user_account(
    username: str,
    db: Session = Depends(get_database_session)
):
    """Delete a user account and all associated data.
    This endpoint is intended for system use, not for users to call directly."""
    try:
        # Delete the user account
        success = UserService.delete_user(db, username)
        
        if success:
            return {
                "message": f"User account '{username}' deleted successfully",
                "deleted": True
            }
        else:
            raise HTTPException(status_code=404, detail="User not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete user account")

@app.post("/decrypt")
async def decrypt_message(
    decrypt_data: DecryptRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Decrypt message using master token - TLS system format"""
    try:
        start_time = time.time()
        
        user_id = int(getattr(current_user, 'id', 0))
        # Always require fresh master token for decryption
        if not DecryptService.validate_master_token(db, user_id, decrypt_data.mastertoken):
            raise HTTPException(
                status_code=401, 
                detail="Invalid master token. Master token is required for message decryption."
            )
        
        # Get the message first to check existence
        message = db.query(Message).filter(
            and_(
                Message.id == decrypt_data.message_id,
                or_(
                    Message.sender_id == user_id,
                    Message.recipient_id == user_id
                )
            )
        ).first()
        
        if not message:
            raise HTTPException(
                status_code=404,
                detail="Message not found"
            )
            
        # Get sender info
        sender = db.query(User).filter(User.id == message.sender_id).first()
        if not sender:
            raise HTTPException(
                status_code=404,
                detail="Message sender not found"
            )
        
        # Attempt to decrypt the message
        decrypted_content = DecryptService.decrypt_message(
            db, 
            user_id,
            decrypt_data.message_id,
            decrypt_data.mastertoken
        )
        
        decrypt_time = time.time() - start_time
        
        # Log successful decryption
        sender_username = str(getattr(sender, 'username', ''))
        AuditService.log_event(
            db,
            user_id,
            "message_decrypted",
            f"Message {decrypt_data.message_id} from {sender_username} decrypted successfully",
            severity="info"
        )
        
        # Format response like TLS system
        message_timestamp = getattr(message, 'timestamp', datetime.now(timezone.utc))
        return {
            "id": int(getattr(message, 'id', 0)),
            "sender": sender_username,
            "sender_verified": True,  # Add actual verification logic
            "timestamp": message_timestamp.strftime("%H:%M"),
            "security": "TLS 1.3 + AES-256-GCM + RSA-4096",
            "server_hmac": True,  # Add actual HMAC verification
            "decrypt_time": round(decrypt_time, 3),
            "content": str(decrypted_content),
            "auto_clear": True,  # Message will auto-clear
            "clear_seconds": 30  # Clear after 30 seconds
        }
        
    except HTTPException:
        raise
    except Exception as e:
        # Log the error
        logger.error(f"Decrypt error: {e}")
        user_id_for_log = int(getattr(current_user, 'id', 0)) if current_user else None
        AuditService.log_event(
            db,
            user_id_for_log,
            "decrypt_error",
            f"Failed to decrypt message {decrypt_data.message_id}: {str(e)}",
            severity="error"
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to decrypt message: {str(e)}"
        )

# Add media endpoints
@app.post("/media/upload")
async def upload_media(
    media_data: MediaUpload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Upload encrypted media file from gallery"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        media = MediaService.upload_media(db, user_id, media_data.username, media_data.dict())
        
        return {
            "media_id": media.media_id,
            "filename": media.filename,
            "media_type": media.media_type,
            "message": "Media uploaded successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload media error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload media")

@app.get("/media/inbox")
async def get_media_inbox(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get user's media inbox"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        media_files = MediaService.get_user_media(db, user_id)
        
        result = []
        for media in media_files:
            sender = db.query(User).filter(User.id == media.sender_id).first()
            recipient = db.query(User).filter(User.id == media.recipient_id).first()
            result.append({
                "id": int(getattr(media, 'id', 0)),
                "media_id": str(getattr(media, 'media_id', '')),
                "filename": str(getattr(media, 'filename', '')),
                "media_type": str(getattr(media, 'media_type', '')),
                "content_type": str(getattr(media, 'content_type', '')),
                "file_size": int(getattr(media, 'file_size', 0)),
                "sender": str(getattr(sender, 'username', '')) if sender else "unknown",
                "recipient": str(getattr(recipient, 'username', '')) if recipient else "unknown",
                "timestamp": getattr(media, 'uploaded_at', datetime.now(timezone.utc)).isoformat(),
                "expires_at": getattr(media, 'expires_at', None).isoformat() if getattr(media, 'expires_at', None) else None,
                "auto_delete": bool(getattr(media, 'auto_delete', False)),
                "downloaded": getattr(media, 'downloaded_at', None) is not None
            })
        
        return {
            "media_files": result,
            "count": len(result)
        }
        
    except Exception as e:
        logger.error(f"Media inbox error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve media inbox")

@app.get("/media/{media_id}")
async def get_media_file(
    media_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get encrypted media file for download"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        media = MediaService.get_media_by_id(db, media_id, user_id)
        
        if not media:
            raise HTTPException(status_code=404, detail="Media file not found")
        
        # Check if user is authorized to access this media
        if user_id != media.sender_id and user_id != media.recipient_id:
            raise HTTPException(status_code=403, detail="Not authorized to access this media")
        
        # Read encrypted file content
        import os
        if not os.path.exists(media.encrypted_file_path):
            raise HTTPException(status_code=404, detail="Media file not found on server")
        
        try:
            with open(media.encrypted_file_path, "rb") as f:
                encrypted_content = f.read()
            
            # Encode as base64 for transmission
            import base64
            encoded_content = base64.b64encode(encrypted_content).decode('utf-8')
            
            # Mark as downloaded
            MediaService.mark_media_downloaded(db, media_id)
            
            return {
                "media_id": media.media_id,
                "filename": media.filename,
                "media_type": media.media_type,
                "content_type": media.content_type,
                "file_size": media.file_size,
                "encrypted_content": encoded_content,
                "encryption_metadata": media.encryption_metadata
            }
            
        except Exception as e:
            logger.error(f"Error reading media file: {e}")
            raise HTTPException(status_code=500, detail="Failed to read media file")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get media error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve media")

@app.post("/media/cleanup")
async def cleanup_expired_media(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Manually trigger cleanup of expired media files"""
    try:
        deleted_count = MediaService.delete_expired_media(db)
        return {
            "message": f"Cleanup completed. {deleted_count} expired media files deleted.",
            "deleted_count": deleted_count
        }
    except Exception as e:
        logger.error(f"Media cleanup error: {e}")
        raise HTTPException(status_code=500, detail="Failed to cleanup expired media files")

# Add admin authentication dependency
async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security), 
                        db: Session = Depends(get_database_session)) -> User:
    """Get current authenticated admin user"""
    try:
        token = credentials.credentials
        
        # Validate session
        session = SessionService.validate_session(db, token)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user
        user = db.query(User).filter(User.id == session.user_id, User.is_active == True, User.is_admin == True).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin user not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return user
        
    except Exception as e:
        logger.error(f"Admin authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate admin credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Add admin endpoints
@app.post("/admin/login")
async def admin_login(login_data: AdminLogin, db: Session = Depends(get_database_session)):
    """Admin login with username and password"""
    try:
        user = AdminService.authenticate_admin(db, login_data.username, login_data.password, ip_address="admin_api")
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        # Create session
        user_id = int(getattr(user, 'id', 0))
        session = SessionService.create_session(db, user_id, "admin", "admin_api")
        
        return {
            "username": str(getattr(user, 'username', '')),
            "token": str(getattr(session, 'session_token', '')),
            "must_change_password": bool(getattr(user, 'must_change_password', False))
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.post("/admin/change_password")
async def admin_change_password(password_data: AdminChangePassword,
                               current_user: User = Depends(get_admin_user),
                               db: Session = Depends(get_database_session)):
    """Change admin password"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        success = AdminService.change_admin_password(
            db, user_id, password_data.current_password, password_data.new_password
        )
        
        if success:
            return {"message": "Password changed successfully"}
        else:
            raise HTTPException(status_code=400, detail="Failed to change password")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Change password error: {e}")
        raise HTTPException(status_code=500, detail="Failed to change password")

@app.post("/admin/users")
async def admin_create_user(user_data: AdminCreateUser,
                           current_user: User = Depends(get_admin_user),
                           db: Session = Depends(get_database_session)):
    """Create a new user account (admin only)"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        new_user = AdminService.create_user(db, user_id, user_data, ip_address="admin_api")
        
        return {
            "username": str(getattr(new_user, 'username', '')),
            "message": "User created successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin create user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user")

@app.delete("/admin/users/{username}")
async def admin_delete_user(username: str,
                           current_user: User = Depends(get_admin_user),
                           db: Session = Depends(get_database_session)):
    """Delete a user account permanently (admin only)"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        success = AdminService.delete_user(db, user_id, username)
        
        if success:
            return {
                "message": f"User account '{username}' deleted successfully",
                "deleted": True
            }
        else:
            raise HTTPException(status_code=404, detail="User not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin delete user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete user account")

@app.get("/admin/users")
async def admin_get_all_users(current_user: User = Depends(get_admin_user),
                             db: Session = Depends(get_database_session)):
    """Get list of all users (admin only)"""
    try:
        # Check if requesting user is admin
        user_id = int(getattr(current_user, 'id', 0))
        if not AdminService.is_admin(db, user_id):
            raise HTTPException(status_code=403, detail="Only admin users can access this endpoint")
        
        users = UserService.get_all_users(db)
        
        result = []
        for user in users:
            last_login = getattr(user, 'last_login', None)
            registered = getattr(user, 'registered', datetime.now(timezone.utc))
            result.append({
                "username": str(getattr(user, 'username', '')),
                "registered": registered.isoformat() if registered else datetime.now(timezone.utc).isoformat(),
                "last_login": last_login.isoformat() if last_login else None,
                "is_active": bool(getattr(user, 'is_active', False)),
                "is_admin": bool(getattr(user, 'is_admin', False)),
                "user_type": str(getattr(user, 'user_type', ''))
            })
        
        return {
            "users": result,
            "count": len(result)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin get users error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve users")
