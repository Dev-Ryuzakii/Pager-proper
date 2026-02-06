"""
PostgreSQL Database Models for Secure Messaging System
Using SQLAlchemy ORM for data modeling and relationships
"""

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, LargeBinary, ForeignKey, Float, JSON
from sqlalchemy.orm import DeclarativeBase, sessionmaker, relationship
from sqlalchemy.sql import func
from datetime import datetime
import os

class Base(DeclarativeBase):
    pass

class User(Base):
    """User account table with authentication and profile data"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)  # Kept for backward compatibility
    phone_number = Column(String(20), unique=True, index=True, nullable=False)  # Primary identifier
    public_key = Column(Text, nullable=True)  # Make this optional - RSA public key in PEM format
    password_hash = Column(String(255), nullable=True)  # Optional password hash
    must_change_password = Column(Boolean, default=False)  # Flag to force password change on first login
    
    # Authentication tokens
    token = Column(String(255), unique=True, index=True, nullable=True)  # TLS safetoken or API token
    session_token = Column(String(255), nullable=True)
    
    # Registration and login tracking
    registered = Column(DateTime, default=func.now())
    last_login = Column(DateTime, nullable=True)
    registration_ip = Column(String(45), nullable=True)  # IPv4/IPv6 support
    
    # Mobile app specific fields (optional for TLS compatibility)
    device_id = Column(String(255), nullable=True)
    push_token = Column(String(512), nullable=True)
    device_info = Column(JSON, nullable=True)  # Store device metadata as JSON
    
    # Account status and type
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    user_type = Column(String(20), default="tls")  # "tls", "mobile", "both"
    is_admin = Column(Boolean, default=False)  # Admin account flag
    
    # Relationships
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")
    user_keys = relationship("UserKey", back_populates="user")
    sessions = relationship("UserSession", back_populates="user")
    master_tokens = relationship("MasterToken", back_populates="user")  # Add this line
    
    def __repr__(self):
        return f"<User(phone='{self.phone_number}', username='{self.username}', type='{self.user_type}', admin={self.is_admin})>"

class Message(Base):
    """Message table for storing encrypted messages between users"""
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Message content (encrypted)
    encrypted_content = Column(Text, nullable=False)
    content_type = Column(String(50), default="text")  # text, file, image, etc.
    
    # Add decoy text field
    decoy_content = Column(Text, nullable=True)  # Fake text shown as placeholder
    
    # Message metadata
    timestamp = Column(DateTime, default=func.now())
    delivered = Column(Boolean, default=False)
    read = Column(Boolean, default=False)
    read_timestamp = Column(DateTime, nullable=True)
    
    # Disappearing messages
    expires_at = Column(DateTime, nullable=True)  # When the message should be deleted
    auto_delete = Column(Boolean, default=False)  # Whether the message should auto-delete
    
    # Message encryption info
    encryption_algorithm = Column(String(50), default="RSA+AES256-GCM")
    message_hash = Column(String(64), nullable=True)  # SHA-256 hash for integrity
    
    # Offline message handling
    is_offline = Column(Boolean, default=False)
    delivery_attempts = Column(Integer, default=0)
    max_delivery_attempts = Column(Integer, default=10)
    
    # Relationships
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")
    media_files = relationship("Media", back_populates="message")  # Add this line
    
    def __repr__(self):
        return f"<Message(sender={self.sender_id}, recipient={self.recipient_id}, timestamp={self.timestamp})>"

class UserKey(Base):
    """User encryption keys and master salts storage"""
    __tablename__ = "user_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Key types and data
    key_type = Column(String(50), nullable=False)  # private_key, master_salt, public_key_cache
    key_name = Column(String(100), nullable=False)  # filename or identifier
    key_data = Column(LargeBinary, nullable=False)  # Binary key data
    
    # Key metadata
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    key_algorithm = Column(String(50), default="RSA-4096")
    
    # Relationships
    user = relationship("User", back_populates="user_keys")
    
    def __repr__(self):
        return f"<UserKey(user_id={self.user_id}, key_type='{self.key_type}', key_name='{self.key_name}')>"

class UserSession(Base):
    """User session management for JWT tokens and TLS connections"""
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Session data
    session_token = Column(String(512), unique=True, nullable=False)
    session_type = Column(String(20), default="api")  # api, tls, mobile
    
    # Session timing
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=func.now())
    
    # Connection info
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    
    # Session status
    is_active = Column(Boolean, default=True)
    logout_reason = Column(String(100), nullable=True)  # expired, manual, forced
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<UserSession(user_id={self.user_id}, session_type='{self.session_type}', active={self.is_active})>"

class SystemConfig(Base):
    """System configuration and metadata storage"""
    __tablename__ = "system_config"
    
    id = Column(Integer, primary_key=True, index=True)
    config_key = Column(String(100), unique=True, nullable=False)
    config_value = Column(Text, nullable=False)
    config_type = Column(String(20), default="string")  # string, json, int, float, bool
    
    # Metadata
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    description = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<SystemConfig(key='{self.config_key}', value='{self.config_value[:50]}...')>"

class AuditLog(Base):
    """Audit log for security and debugging purposes"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Event details
    event_type = Column(String(50), nullable=False)  # login, message_send, key_generation, etc.
    event_description = Column(Text, nullable=False)
    severity = Column(String(20), default="info")  # debug, info, warning, error, critical
    
    # Event metadata
    timestamp = Column(DateTime, default=func.now())
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    session_id = Column(String(512), nullable=True)
    
    # Additional data
    extra_data = Column(JSON, nullable=True)  # Store additional event data as JSON
    
    def __repr__(self):
        return f"<AuditLog(event_type='{self.event_type}', severity='{self.severity}', timestamp={self.timestamp})>"

class MasterToken(Base):
    """Master token storage for user authentication"""
    __tablename__ = "master_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Token data (hashed for security)
    token_hash = Column(String(255), nullable=False)  # Hashed master token
    salt = Column(String(255), nullable=False)  # Salt used for hashing
    
    # Token metadata
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="master_tokens")
    
    def __repr__(self):
        return f"<MasterToken(user_id={self.user_id}, created_at={self.created_at})>"

class Media(Base):
    """Media files storage for encrypted photos, videos and documents"""
    __tablename__ = "media"
    
    id = Column(Integer, primary_key=True, index=True)
    media_id = Column(String(255), unique=True, nullable=False)  # UUID for the media
    filename = Column(String(255), nullable=False)  # Original filename
    file_size = Column(Integer, nullable=False)  # Size in bytes
    media_type = Column(String(50), nullable=False)  # photo, video, document
    content_type = Column(String(100), nullable=False)  # MIME type
    
    # Encryption metadata
    encryption_metadata = Column(JSON, nullable=True)  # Encryption details
    encrypted_file_path = Column(String(512), nullable=False)  # Path to encrypted file
    
    # Message relationship
    message_id = Column(Integer, ForeignKey("messages.id"), nullable=False)
    message = relationship("Message", back_populates="media_files")
    
    # Ownership
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Disappearing media
    expires_at = Column(DateTime, nullable=True)  # When the media should be deleted
    auto_delete = Column(Boolean, default=False)  # Whether the media should auto-delete
    
    # Timestamps
    uploaded_at = Column(DateTime, default=func.now())
    downloaded_at = Column(DateTime, nullable=True)
    
    # Relationships
    sender = relationship("User", foreign_keys=[sender_id])
    recipient = relationship("User", foreign_keys=[recipient_id])
    
    def __repr__(self):
        return f"<Media(media_id='{self.media_id}', filename='{self.filename}', type='{self.media_type}')>"

# Add relationship to Message model
Message.media_files = relationship("Media", back_populates="message")

# Database connection configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://user:password@localhost:5432/secure_messaging"
)

# Create engine and session factory
engine = create_engine(DATABASE_URL, echo=False)  # Set echo=True for SQL debugging
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_tables():
    """Create all database tables"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully!")

def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

if __name__ == "__main__":
    # Create tables when run directly
    create_tables()