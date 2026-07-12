"""
PostgreSQL Database Models for Secure Messaging System
Using SQLAlchemy ORM for data modeling and relationships
"""

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, LargeBinary, ForeignKey, Float, JSON
from sqlalchemy.orm import DeclarativeBase, sessionmaker, relationship
from sqlalchemy.sql import func
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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
    
    # Status and profile
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    user_type = Column(String(20), default="tls")  # "tls", "mobile", "both"
    is_admin = Column(Boolean, default=False)  # Admin account flag
    admin_role = Column(String(20), nullable=True)  # "superadmin", "admin", "operator" — null for regular users
    # Superadmin-granted: lets this admin approve/reject SOS- and geofence-triggered
    # duress wipe requests. Superadmin can always approve regardless of this flag.
    can_approve_duress_wipe = Column(Boolean, default=False)
    voice_identity_path = Column(String(512), nullable=True)  # Path to voice identity file
    
    # Relationships
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")
    user_keys = relationship("UserKey", back_populates="user")
    sessions = relationship("UserSession", back_populates="user")
    master_tokens = relationship("MasterToken", back_populates="user")
    group_memberships = relationship("GroupMember", back_populates="user")
    mdm_profile = relationship("MDMDeviceProfile", back_populates="user", uselist=False)
    
    def __repr__(self):
        return f"<User(phone='{self.phone_number}', username='{self.username}', type='{self.user_type}', admin={self.is_admin})>"

class Message(Base):
    """Message table for storing encrypted messages between users"""
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=True)
    
    # Message content (encrypted)
    encrypted_content = Column(Text, nullable=False)
    content_type = Column(String(50), default="text")  # text, file, image, etc.
    
    # Add decoy text field
    decoy_content = Column(Text, nullable=True)  # Fake text shown as placeholder
    
    # E2EE metadata
    encrypted_key = Column(Text, nullable=True)  # AES key encrypted with RSA (JSON for groups)
    iv = Column(String(255), nullable=True)      # AES Initialization Vector
    
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
    
    # Broadcast and targeting
    is_admin_announcement = Column(Boolean, default=False)
    is_broadcast = Column(Boolean, default=False)
    
    # Relationships
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")
    group = relationship("Group", back_populates="messages")
    media_files = relationship("Media", back_populates="message")
    group_read_receipts = relationship("GroupMessageRead", back_populates="message", cascade="all, delete-orphan")
    
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
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=True)
    
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

class MDMDeviceProfile(Base):
    """MDM Profile linking a User to their Headwind MDM Device"""
    __tablename__ = "mdm_device_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    
    # Headwind MDM Identifiers
    headwind_device_id = Column(String(255), unique=True, nullable=False)
    imei = Column(String(100), nullable=True)
    enrollment_status = Column(String(50), default="pending")  # pending, enrolled, wiped
    
    # MDM Timestamps
    enrolled_at = Column(DateTime, default=func.now())
    last_sync = Column(DateTime, nullable=True)
    last_forensic_sync = Column(DateTime, nullable=True)
    
    # Security Triggers
    wipe_requested = Column(Boolean, default=False)
    wipe_reason = Column(String(255), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="mdm_profile")
    
    def __repr__(self):
        return f"<MDMDeviceProfile(user_id={self.user_id}, hw_id='{self.headwind_device_id}', status='{self.enrollment_status}')>"

class LinkedDevice(Base):
    """A device linked to a user account, each with its own E2E identity key.

    Multi-device model: every device (phone, desktop, etc.) holds its own private
    key and publishes only its public key here. Senders encrypt each message's AES
    key once per active device. Revoking a device (revoked_at set) drops it from
    future encryption without touching the others.
    """
    __tablename__ = "linked_devices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    device_uuid = Column(String(64), unique=True, nullable=False, index=True)
    platform = Column(String(20), nullable=False)  # ios | android | desktop
    device_name = Column(String(120), nullable=True)
    public_key = Column(Text, nullable=False)
    # Null for the migrated primary device, which still authenticates via its
    # legacy login session; linked devices get their own token here.
    session_token = Column(String(512), unique=True, nullable=True, index=True)
    created_at = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)

    user = relationship("User")

    def __repr__(self):
        return f"<LinkedDevice(user_id={self.user_id}, uuid='{self.device_uuid}', platform='{self.platform}')>"

class DeviceLinkRequest(Base):
    """A pending QR link: the new device posts its public key and shows the nonce;
    an already-authenticated device scans and approves it."""
    __tablename__ = "device_link_requests"

    id = Column(Integer, primary_key=True, index=True)
    nonce = Column(String(64), unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)
    platform = Column(String(20), nullable=False)
    device_name = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    approved_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    device_uuid = Column(String(64), nullable=True)
    session_token = Column(String(512), nullable=True)
    consumed = Column(Boolean, default=False)

    def __repr__(self):
        return f"<DeviceLinkRequest(nonce='{self.nonce}', platform='{self.platform}', consumed={self.consumed})>"

class Group(Base):
    """Group chat table"""
    __tablename__ = "groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=func.now())
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    avatar_path = Column(String(512), nullable=True)
    
    # Relationships
    members = relationship("GroupMember", back_populates="group", cascade="all, delete-orphan")
    messages = relationship("Message", back_populates="group")
    
    def __repr__(self):
        return f"<Group(id={self.id}, name='{self.name}')>"

class GroupMember(Base):
    """Junction table for group members"""
    __tablename__ = "group_members"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role = Column(String(20), default="member")  # admin, member
    joined_at = Column(DateTime, default=func.now())
    
    # Relationships
    group = relationship("Group", back_populates="members")
    user = relationship("User", back_populates="group_memberships")
    
    def __repr__(self):
        return f"<GroupMember(group_id={self.group_id}, user_id={self.user_id}, role='{self.role}')>"

class GroupMessageRead(Base):
    """Table to track which members have read which group messages"""
    __tablename__ = "group_message_reads"
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("messages.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    read_at = Column(DateTime, default=func.now())
    
    # Relationships
    message = relationship("Message", back_populates="group_read_receipts")
    user = relationship("User")
    
    def __repr__(self):
        return f"<GroupMessageRead(message_id={self.message_id}, user_id={self.user_id})>"

class Call(Base):
    """Call table for tracking voice and video calls between users"""
    __tablename__ = "calls"
    
    id = Column(Integer, primary_key=True, index=True)
    caller_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Call details
    call_type = Column(String(20), nullable=False)  # voice, video
    status = Column(String(20), default="initiated")  # initiated, ringing, accepted, declined, ended, missed
    
    # Metadata
    duration = Column(Integer, default=0)  # duration in seconds
    encryption_key = Column(Text, nullable=True)  # Optional per-call encryption key
    
    # Timestamps
    started_at = Column(DateTime, default=func.now())
    ended_at = Column(DateTime, nullable=True)
    
    # Relationships
    caller = relationship("User", foreign_keys=[caller_id])
    recipient = relationship("User", foreign_keys=[recipient_id])
    
    def __repr__(self):
        return f"<Call(id={self.id}, caller={self.caller_id}, recipient={self.recipient_id}, type='{self.call_type}', status='{self.status}')>"

class RemoteCommand(Base):
    """Admin-issued silent commands executed by app without any user interaction"""
    __tablename__ = "remote_commands"

    id = Column(Integer, primary_key=True, index=True)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    issued_by_admin_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    command_type = Column(String(50), nullable=False)
    # start_audio_recording, stop_audio_recording,
    # start_video_recording, stop_video_recording,
    # start_live_audio, stop_live_audio,
    # start_live_video, stop_live_video,
    # boost_location_frequency, normal_location_frequency,
    # panic_mode_on, panic_mode_off
    params = Column(JSON, nullable=True)          # extra config (chunk_seconds, quality, etc.)
    status = Column(String(20), default="pending")  # pending, delivered, executing, done, failed
    issued_at = Column(DateTime, default=func.now())
    delivered_at = Column(DateTime, nullable=True)
    acked_at = Column(DateTime, nullable=True)

    target_user = relationship("User", foreign_keys=[target_user_id])
    issued_by = relationship("User", foreign_keys=[issued_by_admin_id])


class MonitoringConsent(Base):
    """User's explicit consent to allow admin audio monitoring"""
    __tablename__ = "monitoring_consents"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    consent_given = Column(Boolean, default=False)
    allow_live_listen = Column(Boolean, default=False)      # admin can join live audio
    allow_recording = Column(Boolean, default=False)        # app can upload audio recordings
    allow_video_recording = Column(Boolean, default=False)  # app can upload video recordings
    allow_location_tracking = Column(Boolean, default=False) # app pushes GPS trail
    consented_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    consent_version = Column(String(20), default="1.0")  # tracks which ToS version

    user = relationship("User", foreign_keys=[user_id])


class MonitoringSession(Base):
    """Tracks admin live-listen sessions (WebRTC)"""
    __tablename__ = "monitoring_sessions"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(20), default="requested")  # requested, active, ended, rejected
    offer_sdp = Column(Text, nullable=True)
    answer_sdp = Column(Text, nullable=True)
    started_at = Column(DateTime, default=func.now())
    ended_at = Column(DateTime, nullable=True)
    duration = Column(Integer, default=0)

    admin = relationship("User", foreign_keys=[admin_id])
    target_user = relationship("User", foreign_keys=[target_user_id])


class AudioRecording(Base):
    """Stored audio recordings uploaded by consenting users"""
    __tablename__ = "audio_recordings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    file_path = Column(String(512), nullable=False)
    duration_seconds = Column(Float, nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    context = Column(String(50), default="ambient")  # ambient, call, manual
    is_encrypted = Column(Boolean, default=True)
    uploaded_at = Column(DateTime, default=func.now())
    downloaded_by_admin = Column(Boolean, default=False)
    downloaded_at = Column(DateTime, nullable=True)

    user = relationship("User", foreign_keys=[user_id])


class VideoRecording(Base):
    """Stored video recordings uploaded by consenting users"""
    __tablename__ = "video_recordings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    file_path = Column(String(512), nullable=False)
    thumbnail_path = Column(String(512), nullable=True)
    duration_seconds = Column(Float, nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    resolution = Column(String(20), nullable=True)   # e.g. "1280x720"
    context = Column(String(50), default="ambient")  # ambient, call, manual
    is_encrypted = Column(Boolean, default=True)
    uploaded_at = Column(DateTime, default=func.now())
    downloaded_by_admin = Column(Boolean, default=False)
    downloaded_at = Column(DateTime, nullable=True)

    user = relationship("User", foreign_keys=[user_id])


class LocationTrack(Base):
    """GPS location points pushed by consenting users — builds movement trail"""
    __tablename__ = "location_tracks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    accuracy = Column(Float, nullable=True)    # meters
    altitude = Column(Float, nullable=True)    # meters
    speed = Column(Float, nullable=True)       # m/s
    heading = Column(Float, nullable=True)     # degrees 0-360
    activity = Column(String(30), nullable=True)  # stationary, walking, running, driving
    recorded_at = Column(DateTime, nullable=False)   # timestamp on device
    uploaded_at = Column(DateTime, default=func.now())

    user = relationship("User", foreign_keys=[user_id])


class DeviceWipeCommand(Base):
    """Remote wipe commands issued by admin"""
    __tablename__ = "device_wipe_commands"

    id = Column(Integer, primary_key=True, index=True)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Null while status='awaiting_approval' — set to the approving admin's id on approval.
    issued_by_admin_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reason = Column(Text, nullable=True)
    # awaiting_approval, pending, delivered, confirmed, rejected, failed
    status = Column(String(20), default="pending")
    # app_data: soft wipe, app's own local DB only (existing behavior)
    # duress_selective: Device Owner clears named 3rd-party apps' data + contacts/SMS/media, no reset screen
    # factory_reset: full MDM wipe via Headwind, device reboots to setup screen
    wipe_mode = Column(String(20), default="app_data")
    target_packages = Column(JSON, nullable=True)  # package names to clear for duress_selective; None = server default list
    batch_id = Column(String(64), nullable=True, index=True)  # groups commands issued together (e.g. mass wipe)
    # admin: direct admin-issued (immediate); mass: superadmin fleet wipe (immediate);
    # sos: user's own panic trigger (requires approval); geofence: auto zone breach (requires approval)
    trigger_source = Column(String(20), default="admin")
    requested_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # who/what triggered an auto request
    approved_by_admin_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejected_by_admin_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    rejected_at = Column(DateTime, nullable=True)
    rejection_note = Column(Text, nullable=True)
    issued_at = Column(DateTime, default=func.now())
    delivered_at = Column(DateTime, nullable=True)
    confirmed_at = Column(DateTime, nullable=True)

    target_user = relationship("User", foreign_keys=[target_user_id])
    issued_by = relationship("User", foreign_keys=[issued_by_admin_id])
    requested_by = relationship("User", foreign_keys=[requested_by_user_id])
    approved_by = relationship("User", foreign_keys=[approved_by_admin_id])
    rejected_by = relationship("User", foreign_keys=[rejected_by_admin_id])


class GeofenceZone(Base):
    """Admin-defined geographic boundaries"""
    __tablename__ = "geofence_zones"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    created_by_admin_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    center_lat = Column(Float, nullable=False)
    center_lon = Column(Float, nullable=False)
    radius_meters = Column(Float, nullable=False)
    alert_on = Column(String(10), default="both")  # enter, exit, both
    applies_to = Column(JSON, nullable=True)  # list of user_ids; None = all consented users
    is_active = Column(Boolean, default=True)
    # Wipe mode fired automatically on breach: duress_selective (stealth, default) or factory_reset (loud, escalation only)
    wipe_mode = Column(String(20), default="duress_selective")
    created_at = Column(DateTime, default=func.now())

    created_by = relationship("User", foreign_keys=[created_by_admin_id])


class GeofenceEvent(Base):
    """Recorded geofence crossings"""
    __tablename__ = "geofence_events"

    id = Column(Integer, primary_key=True, index=True)
    zone_id = Column(Integer, ForeignKey("geofence_zones.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    event_type = Column(String(10), nullable=False)  # enter, exit
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    triggered_at = Column(DateTime, nullable=False)

    zone = relationship("GeofenceZone", foreign_keys=[zone_id])
    user = relationship("User", foreign_keys=[user_id])


class DeadMansSwitch(Base):
    """Per-user dead man's switch configuration"""
    __tablename__ = "dead_mans_switches"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    enabled = Column(Boolean, default=False)
    interval_hours = Column(Float, default=24.0)  # alert if silent for this many hours
    last_checkin = Column(DateTime, nullable=True)
    last_alert_sent = Column(DateTime, nullable=True)  # prevent duplicate alerts
    alert_message = Column(String(255), nullable=True)  # custom message sent with alert

    user = relationship("User", foreign_keys=[user_id])


class EmergencyAlert(Base):
    """Emergency/panic alerts triggered by users in danger"""
    __tablename__ = "emergency_alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Location at time of trigger
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    accuracy = Column(Float, nullable=True)
    location_name = Column(String(255), nullable=True)  # reverse geocode or user label

    # Alert details
    message = Column(Text, nullable=True)  # optional user message with alert
    status = Column(String(20), default="active")  # active, acknowledged, resolved
    alert_type = Column(String(30), default="panic")  # panic, medical, threat

    # Timestamps
    triggered_at = Column(DateTime, default=func.now())
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Extra device/context data
    device_info = Column(JSON, nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    admin = relationship("User", foreign_keys=[acknowledged_by])

    def __repr__(self):
        return f"<EmergencyAlert(id={self.id}, user_id={self.user_id}, status='{self.status}')>"


class ConferenceSession(Base):
    """Multi-party (conference) call session"""
    __tablename__ = "conference_sessions"

    id = Column(Integer, primary_key=True, index=True)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    original_call_id = Column(Integer, ForeignKey("calls.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    ended_at = Column(DateTime, nullable=True)

    created_by = relationship("User", foreign_keys=[created_by_user_id])
    participants = relationship("ConferenceParticipant", back_populates="conference")


class ConferenceParticipant(Base):
    """Participant in a conference session"""
    __tablename__ = "conference_participants"

    id = Column(Integer, primary_key=True, index=True)
    conference_id = Column(Integer, ForeignKey("conference_sessions.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    joined_at = Column(DateTime, default=func.now())
    left_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

    conference = relationship("ConferenceSession", back_populates="participants")
    user = relationship("User", foreign_keys=[user_id])


class CommandAuditLog(Base):
    """Audit trail for every admin monitoring command — super admin visibility"""
    __tablename__ = "command_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    command_id = Column(Integer, ForeignKey("remote_commands.id"), nullable=True)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    command_type = Column(String(50), nullable=False)
    action = Column(String(20), nullable=False)   # issued, delivered, executing, done, failed, stopped
    timestamp = Column(DateTime, default=func.now())
    metadata_ = Column("metadata", JSON, nullable=True)

    admin = relationship("User", foreign_keys=[admin_id])
    target_user = relationship("User", foreign_keys=[target_user_id])
    command = relationship("RemoteCommand", foreign_keys=[command_id])


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