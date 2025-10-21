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
class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    public_key: str = Field(..., min_length=100)
    safetoken: str = Field(..., description="User authentication token")

class UserLogin(BaseModel):
    username: str
    safetoken: str

class MessageSend(BaseModel):
    recipient: str
    content: str = Field(..., min_length=1)
    content_type: str = "text"

class MessageResponse(BaseModel):
    id: int
    sender: str
    recipient: str
    content: str
    content_type: str
    timestamp: datetime
    delivered: bool
    read: bool

class UserResponse(BaseModel):
    username: str
    registered: datetime
    last_login: Optional[datetime]
    is_active: bool

# Database Services
class UserService:
    """Service class for user operations"""
    
    @staticmethod
    def create_user(db: Session, user_data: UserRegistration, ip_address: str = None) -> User:
        """Create a new user"""
        # Check if user already exists
        existing_user = db.query(User).filter(User.username == user_data.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        
        # Use provided safetoken (like TLS system)
        token = user_data.safetoken
        
        # Create user - TLS compatible fields only
        user = User(
            username=user_data.username,
            public_key=user_data.public_key,
            token=token,
            registration_ip=ip_address,
            is_active=True,
            is_verified=True,
            user_type='mobile'  # To distinguish from TLS users
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Log registration
        AuditService.log_event(
            db, user.id, "user_registration", 
            f"User {user_data.username} registered", 
            ip_address=ip_address
        )
        
        logger.info(f"✅ User registered: {user_data.username}")
        return user
    
    @staticmethod
    def authenticate_user(db: Session, username: str, safetoken: str, ip_address: str = None) -> Optional[User]:
        """Authenticate user with safetoken and update last login"""
        user = db.query(User).filter(
            User.username == username, 
            User.token == safetoken,
            User.is_active == True
        ).first()
        
        if user:
            user.last_login = datetime.now(timezone.utc)
            db.commit()
            
            # Log login
            AuditService.log_event(
                db, user.id, "user_login", 
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
    def send_message(db: Session, sender_id: int, recipient_username: str, content: str, content_type: str = "text") -> Message:
        """Send a message"""
        # Get recipient
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        # Create message
        message = Message(
            sender_id=sender_id,
            recipient_id=recipient.id,
            encrypted_content=content,
            content_type=content_type,
            delivered=False,
            read=False,
            is_offline=True  # Mark as offline initially
        )
        
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
            message.delivered = True
            message.is_offline = False
            db.commit()
            return True
        return False
    
    @staticmethod
    def mark_message_read(db: Session, message_id: int) -> bool:
        """Mark message as read"""
        message = db.query(Message).filter(Message.id == message_id).first()
        if message:
            message.read = True
            message.read_timestamp = datetime.now(timezone.utc)
            db.commit()
            return True
        return False

class SessionService:
    """Service class for session management"""
    
    @staticmethod
    def create_session(db: Session, user_id: int, session_type: str = "api", ip_address: str = None) -> UserSession:
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
            session.last_activity = datetime.now(timezone.utc)
            db.commit()
        
        return session
    
    @staticmethod
    def invalidate_session(db: Session, session_token: str) -> bool:
        """Invalidate a session"""
        session = db.query(UserSession).filter(UserSession.session_token == session_token).first()
        if session:
            session.is_active = False
            session.logout_reason = "manual"
            db.commit()
            return True
        return False

class AuditService:
    """Service class for audit logging"""
    
    @staticmethod
    def log_event(db: Session, user_id: Optional[int], event_type: str, description: str, 
                  severity: str = "info", ip_address: str = None, extra_data: Dict = None):
        """Log an audit event"""
        audit_log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_description=description,
            severity=severity,
            ip_address=ip_address,
            extra_data=extra_data
        )
        
        db.add(audit_log)
        db.commit()

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
    """Register a new user"""
    try:
        user = UserService.create_user(db, user_data, ip_address="mobile_app")
        
        # Create session
        session = SessionService.create_session(db, user.id, "mobile", "mobile_app")
        
        return {
            "message": "User registered successfully",
            "user": {
                "username": user.username,
                "registered": user.registered.isoformat()
            },
            "token": session.session_token
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/auth/login")
async def login_user(login_data: UserLogin, db: Session = Depends(get_database_session)):
    """Login user"""
    try:
        user = UserService.authenticate_user(db, login_data.username, login_data.safetoken, ip_address="mobile_app")
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or safetoken")
        
        # Create session
        session = SessionService.create_session(db, user.id, "mobile", "mobile_app")
        
        return {
            "message": "Login successful",
            "user": {
                "username": user.username,
                "last_login": user.last_login.isoformat() if user.last_login else None
            },
            "token": session.session_token
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
        
        AuditService.log_event(
            db, current_user.id, "user_logout", 
            f"User {current_user.username} logged out"
        )
        
        return {"message": "Logout successful"}
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")

@app.post("/messages/send")
async def send_message(message_data: MessageSend, 
                      current_user: User = Depends(get_current_user),
                      db: Session = Depends(get_database_session)):
    """Send a message"""
    try:
        message = MessageService.send_message(
            db, current_user.id, message_data.recipient, 
            message_data.content, message_data.content_type
        )
        
        return {
            "message": "Message sent successfully",
            "message_id": message.id,
            "timestamp": message.timestamp.isoformat()
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
        messages = MessageService.get_user_messages(db, current_user.id)
        
        result = []
        for msg in messages:
            sender = db.query(User).filter(User.id == msg.sender_id).first()
            result.append({
                "id": msg.id,
                "sender": sender.username if sender else "unknown",
                "content": msg.encrypted_content,
                "content_type": msg.content_type,
                "timestamp": msg.timestamp.isoformat(),
                "delivered": msg.delivered,
                "read": msg.read
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
        messages = MessageService.get_offline_messages(db, current_user.id)
        
        result = []
        for msg in messages:
            sender = db.query(User).filter(User.id == msg.sender_id).first()
            result.append({
                "id": msg.id,
                "sender": sender.username if sender else "unknown",
                "content": msg.encrypted_content,
                "content_type": msg.content_type,
                "timestamp": msg.timestamp.isoformat()
            })
            
            # Mark as delivered
            MessageService.mark_message_delivered(db, msg.id)
        
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
        # Verify message belongs to current user
        message = db.query(Message).filter(
            and_(Message.id == message_id, Message.recipient_id == current_user.id)
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
        for user in users:
            if user.id != current_user.id:  # Exclude current user
                result.append({
                    "username": user.username,
                    "registered": user.registered.isoformat(),
                    "last_login": user.last_login.isoformat() if user.last_login else None
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
            "username": user.username,
            "public_key": user.public_key
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get public key error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve public key")

if __name__ == "__main__":
    uvicorn.run(
        "fastapi_mobile_backend_postgresql:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )