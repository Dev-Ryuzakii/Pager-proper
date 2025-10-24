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

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks, UploadFile, File, Form
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
import hmac
import gc
import json

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

from database_config import get_database_session, db_config
from database_models import User, Message, UserKey, UserSession, AuditLog

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

class UserLogin(UserAuth):
    pass  # Same as auth - just username and token

class MessageSend(BaseModel):
    username: str = Field(..., description="Recipient username")
    message: str = Field(..., min_length=1, description="Message content")

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
            # Check if user has master salt
            master_salt_record = db.query(UserKey).filter(
                and_(
                    UserKey.user_id == user.id,
                    UserKey.key_type == "master_salt"
                )
            ).first()
            
            if not master_salt_record:
                # Read master salt from file
                salt_path = f"/Users/macbook/Pager-proper/auth/master_salts/{username}_master_salt.dat"
                try:
                    with open(salt_path, 'rb') as f:
                        salt_data = f.read()
                        
                    # Store master salt in database
                    master_salt = UserKey(
                        user_id=user.id,
                        key_type="master_salt",
                        key_data=salt_data,
                        is_active=True
                    )
                    db.add(master_salt)
                    logger.info(f"✅ Initialized master salt for user {username}")
                except Exception as e:
                    logger.error(f"❌ Failed to initialize master salt for {username}: {e}")
            
            # Check if user has private key
            private_key_record = db.query(UserKey).filter(
                and_(
                    UserKey.user_id == user.id,
                    UserKey.key_type == "private_key"
                )
            ).first()
            
            if not private_key_record:
                # Read private key from file
                key_path = f"/Users/macbook/Pager-proper/auth/private_keys/{username}_user_private_key.pem"
                try:
                    with open(key_path, 'r') as f:
                        key_data = f.read()
                        
                    # Store private key in database
                    private_key = UserKey(
                        user_id=user.id,
                        key_type="private_key",
                        key_data=key_data,
                        is_active=True
                    )
                    db.add(private_key)
                    logger.info(f"✅ Initialized private key for user {username}")
                except Exception as e:
                    logger.error(f"❌ Failed to initialize private key for {username}: {e}")
            
            user.last_login = datetime.now(timezone.utc)
            db.commit()
            
            # Log login
            AuditService.log_event(
                db, getattr(user, 'id', None), "user_login", 
                f"User {username} logged in", 
                ip_address=ip_address,
                extra_data=json.dumps({
                    "has_master_salt": master_salt_record is not None,
                    "has_private_key": private_key_record is not None
                })
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

class MessageService:
    """Service class for message operations"""
    
    @staticmethod
    def send_message(db: Session, sender_id: int, recipient_username: str, message_content: str) -> Message:
        """Send a message with proper encryption"""
        # Get recipient
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
            
        try:
            # Generate random AES key
            aes_key = os.urandom(32)  # 256-bit key
            
            # Get recipient's public key from the cache directory
            public_key_path = f"/Users/macbook/Pager-proper/auth/cache/{recipient_username}_public_keys_cache.json"
            try:
                with open(public_key_path, 'r') as f:
                    public_keys_data = json.load(f)
                    if not public_keys_data or "public_key" not in public_keys_data:
                        raise ValueError("Invalid public key cache format")
                    recipient_public_key = RSA.import_key(public_keys_data["public_key"])
            except FileNotFoundError:
                logger.error(f"Public key not found for {recipient_username}")
                raise HTTPException(status_code=500, detail="Recipient public key not found")
                
            # Create PKCS1_OAEP cipher for RSA encryption
            from Crypto.Hash import SHA256
            rsa_cipher = PKCS1_OAEP.new(
                recipient_public_key,
                hashAlgo=SHA256,
                mgfunc=lambda x, y: PKCS1_OAEP.MGF1(x, y, SHA256)
            )
            
            # Encrypt the AES key with recipient's public key
            encrypted_aes_key = rsa_cipher.encrypt(aes_key)
            
            # Prepare message content
            message_data = {
                "content": message_content,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sender": recipient_username
            }
            
            # Convert to JSON and encode
            message_json = json.dumps(message_data).encode()
            
            # Create AES-GCM cipher
            nonce = os.urandom(12)  # 96-bit nonce for GCM
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            
            # Encrypt the message
            ciphertext, tag = cipher.encrypt_and_digest(message_json)
            
            # Create encrypted message package
            encrypted_payload = {
                "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
                "encrypted_message": {
                    "nonce": base64.b64encode(nonce).decode(),
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "auth_tag": base64.b64encode(tag).decode()
                }
            }
            
            # Create message record
            message = Message(
                sender_id=sender_id,
                recipient_id=recipient.id,
                encrypted_content=json.dumps(encrypted_payload),
                content_type="encrypted",
                delivered=False,
                read=False,
                is_offline=True  # Mark as offline initially
            )
            
            db.add(message)
            db.commit()
            db.refresh(message)
            
            logger.info(f"📤 Encrypted message sent: {sender_id} → {recipient.id}")
            return message
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Message encryption error: {e}")
            raise HTTPException(status_code=500, detail="Failed to encrypt and send message")
    
    @staticmethod
    def send_image(db: Session, sender_id: int, recipient_username: str, image_data_b64: str, filename: str) -> Message:
        """Send an image with proper encryption"""
        # Get recipient
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
            
        try:
            # Generate random AES key
            aes_key = os.urandom(32)  # 256-bit key
            
            # Get recipient's public key from the cache directory
            public_key_path = f"/Users/macbook/Pager-proper/auth/cache/{recipient_username}_public_keys_cache.json"
            try:
                with open(public_key_path, 'r') as f:
                    public_keys_data = json.load(f)
                    if not public_keys_data or "public_key" not in public_keys_data:
                        raise ValueError("Invalid public key cache format")
                    recipient_public_key = RSA.import_key(public_keys_data["public_key"])
            except FileNotFoundError:
                logger.error(f"Public key not found for {recipient_username}")
                raise HTTPException(status_code=500, detail="Recipient public key not found")
                
            # Create PKCS1_OAEP cipher for RSA encryption
            from Crypto.Hash import SHA256
            rsa_cipher = PKCS1_OAEP.new(
                recipient_public_key,
                hashAlgo=SHA256,
                mgfunc=lambda x, y: PKCS1_OAEP.MGF1(x, y, SHA256)
            )
            
            # Encrypt the AES key with recipient's public key
            encrypted_aes_key = rsa_cipher.encrypt(aes_key)
            
            # Prepare message content
            message_data = {
                "content": image_data_b64,
                "filename": filename,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sender": recipient_username,
                "content_type": "image"
            }
            
            # Convert to JSON and encode
            message_json = json.dumps(message_data).encode()
            
            # Create AES-GCM cipher
            nonce = os.urandom(12)  # 96-bit nonce for GCM
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            
            # Encrypt the message
            ciphertext, tag = cipher.encrypt_and_digest(message_json)
            
            # Create encrypted message package
            encrypted_payload = {
                "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
                "encrypted_message": {
                    "nonce": base64.b64encode(nonce).decode(),
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "auth_tag": base64.b64encode(tag).decode()
                }
            }
            
            # Create message record
            message = Message(
                sender_id=sender_id,
                recipient_id=recipient.id,
                encrypted_content=json.dumps(encrypted_payload),
                content_type="encrypted",
                delivered=False,
                read=False,
                is_offline=True  # Mark as offline initially
            )
            
            db.add(message)
            db.commit()
            db.refresh(message)
            
            logger.info(f"📤 Encrypted image sent: {sender_id} → {recipient.id}")
            return message
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Message encryption error: {e}")
            raise HTTPException(status_code=500, detail="Failed to encrypt and send image")
    
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
        """Invalidate a session"""
        session = db.query(UserSession).filter(UserSession.session_token == session_token).first()
        if session:
            # Use setattr for SQLAlchemy models to avoid type errors
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

class SecureMemory:
    """Utility class for secure memory handling"""
    
    @staticmethod
    def secure_clear(data):
        """Securely clear sensitive data from memory"""
        if data is None:
            return
        
        try:
            if isinstance(data, str):
                # Convert to bytearray for mutable clearing
                data_bytes = bytearray(data.encode())
                # Overwrite with random data multiple times
                for _ in range(3):
                    for i in range(len(data_bytes)):
                        data_bytes[i] = os.urandom(1)[0]
                data_bytes.clear()
            elif isinstance(data, bytearray):
                # Overwrite with random data
                for _ in range(3):
                    for i in range(len(data)):
                        data[i] = os.urandom(1)[0]
                data.clear()
            elif isinstance(data, bytes):
                # Let GC handle immutable bytes
                pass
        except Exception:
            pass
        
        # Force garbage collection
        gc.collect()

class DecryptService:
    """Service class for decryption operations with memory security"""
    
    @staticmethod
    def validate_master_token(db: Session, user_id: int, mastertoken: str) -> bool:
        """Validate the master token for a user using TLS-like approach"""
        try:
            # Get username first
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return False
                
            # Read master salt directly from file (TLS approach)
            salt_path = f"/Users/macbook/Pager-proper/auth/master_salts/{user.username}_master_salt.dat"
            try:
                with open(salt_path, 'rb') as f:
                    master_salt = f.read()
            except FileNotFoundError:
                logger.error(f"Master salt file not found for {user.username}")
                return False
                
            # Get stored master token hash from audit log
            audit_record = db.query(AuditLog).filter(
                and_(
                    AuditLog.user_id == user_id,
                    AuditLog.event_type == "mastertoken_confirmed",
                    AuditLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)  # Valid for 24 hours
                )
            ).order_by(AuditLog.timestamp.desc()).first()
            
            if not audit_record or not audit_record.extra_data:
                logger.error(f"No valid master token confirmation found for user {user_id}")
                return False
                
            # Get the stored hash from extra_data
            try:
                stored_data = json.loads(audit_record.extra_data)
                stored_hash = stored_data.get("token_hash")
                if not stored_hash:
                    logger.error("No token hash found in audit record")
                    return False
            except (json.JSONDecodeError, KeyError) as e:
                logger.error(f"Failed to parse stored token data: {e}")
                return False
            
            # Convert read master salt to bytes if needed
            if isinstance(master_salt, str):
                master_salt = master_salt.encode()
            elif not isinstance(master_salt, bytes):
                master_salt = bytes(master_salt)
            
            # Hash the provided master token with the salt
            current_hash = hashlib.sha256(
                f"{mastertoken}:{master_salt.decode()}".encode()
            ).hexdigest()
            
            # Verify the hash matches
            if not hmac.compare_digest(stored_hash, current_hash):
                logger.warning(f"Master token validation failed for user {user_id}")
                return False
                
            logger.info(f"Master token validated successfully for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Master token validation error: {e}")
            return False
    
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
        """Decrypt a message using TLS-like approach with secure memory handling"""
        start_time = time.time()
        
        # Get user info for paths
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get message
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
            # TLS-like approach: Load private key from file
            key_path = f"/Users/macbook/Pager-proper/auth/private_keys/{user.username}_user_private_key.pem"
            try:
                with open(key_path, 'rb') as f:
                    private_key_data = f.read()
                private_key = RSA.import_key(private_key_data)
                # Clear sensitive data
                SecureMemory.secure_clear(private_key_data)
            except FileNotFoundError:
                raise HTTPException(status_code=404, detail="User private key file not found")
            
            # Get the user's master salt for key derivation
            master_salt_record = db.query(UserKey).filter(
                and_(
                    UserKey.user_id == user_id,
                    UserKey.key_type == "master_salt"
                )
            ).first()
            
            if not master_salt_record:
                raise HTTPException(status_code=404, detail="Master salt not found")
            
            # Parse encrypted content
            try:
                encrypted_content = getattr(message, 'encrypted_content', '')
                encrypted_payload = json.loads(encrypted_content)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid encrypted content format")
            
            # Validate payload structure
            if "encrypted_key" not in encrypted_payload or "encrypted_message" not in encrypted_payload:
                raise HTTPException(status_code=400, detail="Invalid encrypted payload structure")
                
            # TLS-like approach: Read master salt from file
            salt_path = f"/Users/macbook/Pager-proper/auth/master_salts/{user.username}_master_salt.dat"
            try:
                with open(salt_path, 'rb') as f:
                    master_salt = f.read()
            except FileNotFoundError:
                raise HTTPException(status_code=404, detail="Master salt file not found")
                
            # Derive master key using PBKDF2 (like TLS system)
            master_key = PBKDF2(
                mastertoken,
                master_salt,
                32,  # 256-bit key
                count=200000  # Increased iterations for better security
            )
            
            try:
                # Create PKCS1_OAEP cipher for RSA decryption
                from Crypto.Hash import SHA256
                rsa_cipher = PKCS1_OAEP.new(
                    private_key,
                    hashAlgo=SHA256,
                    mgfunc=lambda x, y: PKCS1_OAEP.MGF1(x, y, SHA256)
                )

                # Decrypt the AES key
                encrypted_aes_key = base64.b64decode(encrypted_payload["encrypted_key"])
                aes_key = rsa_cipher.decrypt(encrypted_aes_key)
                
                # Decrypt the message using AES-GCM
                encrypted_msg_data = encrypted_payload["encrypted_message"]
                if not isinstance(encrypted_msg_data, dict):
                    raise ValueError("Invalid AES-GCM data format")
                    
                # Decrypt using AES-256-GCM with authentication
                decrypted_content = DecryptService.decrypt_with_aes_gcm(encrypted_msg_data, aes_key)
                
                # Clear sensitive keys from memory
                SecureMemory.secure_clear(aes_key)
                SecureMemory.secure_clear(master_key)
                
                return decrypted_content
                
            except ValueError as e:
                logger.error(f"Decryption validation error: {e}")
                raise HTTPException(status_code=400, detail="Message authentication failed")
            except Exception as e:
                logger.error(f"Decryption error: {e}")
                raise HTTPException(status_code=500, detail="Decryption failed")
                
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Message decryption error: {e}")
            raise HTTPException(status_code=500, detail="Decryption failed")


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency to get the current authenticated user"""
    session_token = credentials.credentials
    try:
        user_session = SessionService.validate_session(db_config(), session_token)
        if not user_session:
            raise HTTPException(status_code=401, detail="Invalid session token")
        user = UserService.get_user_by_username(db_config(), user_session.user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
        
    except Exception as e:
        logger.error(f"Session validation error: {e}")
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.post("/users/register")
async def register_user(
    user_data: UserRegistration,
    db: Session = Depends(get_database_session),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Register a new user"""
    try:
        user = UserService.create_user(db, user_data, "127.0.0.1")
        background_tasks.add_task(AuditService.log_event, db, user.id, "user_registration", f"User {user_data.username} registered", ip_address="127.0.0.1")
        return {"username": user.username, "registered": user.registration_time}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User registration error: {e}")
        raise HTTPException(status_code=500, detail="Server error")

@app.post("/users/login")
async def login_user(
    user_data: UserLogin,
    db: Session = Depends(get_database_session),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Authenticate user and create a session"""
    try:
        user = UserService.authenticate_user(db, user_data.username, user_data.token, "127.0.0.1")
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        session = SessionService.create_session(db, user.id, session_type="api", ip_address="127.0.0.1")
        background_tasks.add_task(AuditService.log_event, db, user.id, "user_login", f"User {user_data.username} logged in", ip_address="127.0.0.1")
        return {"session_token": session.session_token, "expires_at": session.expires_at}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User login error: {e}")
        raise HTTPException(status_code=500, detail="Server error")

@app.post("/messages/send")
async def send_message(
    message_data: MessageSend,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Send an encrypted message"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        message = MessageService.send_message(db, user_id, message_data.username, message_data.message)
        return {"username": message_data.username, "message": "Message sent successfully", "message_id": message.id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message")

@app.post("/messages/send/image/snap")
async def send_snap_image(
    recipient_username: str = Form(...),
    image: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Send a snapped image directly (multipart form data)"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        
        # Validate file type (must be JPG)
        if not image.filename.lower().endswith(('.jpg', '.jpeg')):
            raise HTTPException(status_code=400, detail="Only JPG images are supported")
        
        # Read image data
        image_data = await image.read()
        
        # Check image size (limit to 10MB)
        if len(image_data) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=413, detail="Image size exceeds 10MB limit")
        
        # Encode image data as Base64 for storage
        image_data_b64 = base64.b64encode(image_data).decode('utf-8')
        
        # Send the image message
        message = MessageService.send_image(
            db, user_id, recipient_username, image_data_b64, image.filename
        )
        
        return {
            "username": recipient_username,
            "message": "Snapped image sent successfully",
            "message_id": message.id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send snap image error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send snapped image")

@app.get("/messages/inbox")
async def get_messages(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session),
    limit: int = 50
):
    """Get messages for the current user (inbox)"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        messages = MessageService.get_user_messages(db, user_id, limit)
        message_responses = []
        for message in messages:
            message_responses.append(
                MessageResponse(
                    id=message.id,
                    sender=message.sender.username,
                    recipient=message.recipient.username,
                    content=message.content,
                    content_type=message.content_type,
                    timestamp=message.timestamp,
                    delivered=message.delivered,
                    read=message.read,
                    server_hmac=message.server_hmac,
                    decrypt_time=message.decrypt_time
                )
            )
        return message_responses
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get messages error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch messages")

@app.get("/messages/offline")
async def get_offline_messages(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session),
):
    """Get offline messages for the current user"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        messages = MessageService.get_offline_messages(db, user_id)
        message_responses = []
        for message in messages:
            message_responses.append(
                MessageResponse(
                    id=message.id,
                    sender=message.sender.username,
                    recipient=message.recipient.username,
                    content=message.content,
                    content_type=message.content_type,
                    timestamp=message.timestamp,
                    delivered=message.delivered,
                    read=message.read,
                    server_hmac=message.server_hmac,
                    decrypt_time=message.decrypt_time
                )
            )
        return message_responses
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get offline messages error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch offline messages")

@app.post("/messages/decrypt")
async def decrypt_message(
    decrypt_data: DecryptRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session),
):
    """Decrypt a message using the master token"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        decrypted_content = DecryptService.decrypt_message(db, user_id, decrypt_data.message_id, decrypt_data.mastertoken)
        return {"message_id": decrypt_data.message_id, "content": decrypted_content}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Decrypt message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to decrypt message")

@app.post("/messages/delivered")
async def mark_message_delivered(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session),
):
    """Mark a message as delivered"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        success = MessageService.mark_message_delivered(db, message_id)
        if success:
            return {"message_id": message_id, "status": "delivered"}
        else:
            raise HTTPException(status_code=404, detail="Message not found")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mark message delivered error: {e}")
        raise HTTPException(status_code=500, detail="Failed to mark message as delivered")

@app.post("/messages/read")
async def mark_message_read(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session),
):
    """Mark a message as read"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        success = MessageService.mark_message_read(db, message_id)
        if success:
            return {"message_id": message_id, "status": "read"}
        else:
            raise HTTPException(status_code=404, detail="Message not found")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mark message read error: {e}")
        raise HTTPException(status_code=500, detail="Failed to mark message as read")

@app.post("/sessions/invalidate")
async def invalidate_session(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_database_session),
):
    """Invalidate an active session"""
    try:
        session_token = credentials.credentials
        success = SessionService.invalidate_session(db, session_token)
        if success:
            return {"status": "session invalidated"}
        else:
            raise HTTPException(status_code=404, detail="Session not found")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Invalidate session error: {e}")
        raise HTTPException(status_code=500, detail="Failed to invalidate session")

@app.get("/users/info")
async def user_info(
    current_user: User = Depends(get_current_user)
):
    """Get information about the current user"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        return {
            "username": current_user.username,
            "registered": current_user.registration_time,
            "last_login": current_user.last_login,
            "is_active": current_user.is_active
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User info error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch user info")

if __name__ == "__main__":
    uvicorn.run(
        "fastapi_mobile_backend_postgresql:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )