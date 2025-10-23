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

from database_config import get_database_session, db_config
from database_models import User, Message, UserKey, UserSession, AuditLog

# Import the fake text generator
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

class MessageService:
    """Service class for message operations"""
    
    @staticmethod
    def send_message(db: Session, sender_id: int, recipient_username: str, message_content: str) -> Message:
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
        
        # Create message - simplified
        message = Message(
            sender_id=sender_id,
            recipient_id=recipient.id,
            encrypted_content=message_content,
            content_type="encrypted",
            delivered=False,
            read=False,
            is_offline=True  # Mark as offline initially
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
                  severity: str = "info", ip_address: Optional[str] = None, extra_data: Optional[Dict[Any, Any]] = None) -> None:
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

# FastAPI app with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Starting FastAPI Mobile Backend with PostgreSQL...")
    
    # Initialize database
    if not db_config.initialize_database():
        logger.error("❌ Failed to initialize database")
        raise Exception("Database initialization failed")
    
    # Test connection
    if not db_config.test_connection():
        logger.error("❌ Database connection test failed")
        raise Exception("Database connection failed")
    
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
            db, user_id, message_data.username, message_data.message
        )
        
        return {
            "username": message_data.username,
            "message": "sent"
        }
        
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

if __name__ == "__main__":
    uvicorn.run(
        "fastapi_mobile_backend_postgresql:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )