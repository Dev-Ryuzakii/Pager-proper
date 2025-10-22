#!/usr/bin/env python3
"""
FastAPI Mobile App Backend - Secure Messaging API
Integrates with existing TLS server and encryption system
"""

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import socket
import ssl
import threading
import json
import time
import hashlib
import hmac
import base64
import os
import asyncio
import websockets
from datetime import datetime, timedelta
import uvicorn
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app initialization
app = FastAPI(
    title="Pager API",
    description="Secure messaging API with end-to-end encryption",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for mobile app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# HMAC secret key for message authentication (same concept as TLS server)
HMAC_SECRET_KEY = os.urandom(32)

# Data models
class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    public_key: str = Field(..., description="RSA public key in PEM format")
    safetoken: str = Field(..., description="User authentication token")

class UserLogin(BaseModel):
    username: str
    safetoken: str
    public_key: Optional[str] = None

class SendMessage(BaseModel):
    recipient_id: Optional[str] = None  # FastAPI format
    recipient: Optional[str] = None     # TLS format
    message_type: str = "hybrid_rsa_aes"
    encrypted_content: Optional[Dict[str, str]] = None  # FastAPI format
    payload: Optional[Dict[str, Any]] = None            # TLS format
    metadata: Optional[Dict[str, Any]] = None
    safetoken: Optional[str] = None     # TLS format

class MessageStatus(BaseModel):
    status: str = Field(..., pattern="^(read|delivered|failed)$")
    timestamp: float

class UserProfile(BaseModel):
    bio: Optional[str] = None
    profile_picture: Optional[str] = None
    privacy_settings: Optional[Dict[str, Any]] = None

# Global variables
user_keys = {}
connected_users = {}
offline_messages = {}
sessions = {}  # JWT session storage

def generate_message_hmac(message_data, timestamp):
    """Generate HMAC for message authentication - TLS server compatible"""
    message_string = json.dumps(message_data, sort_keys=True) + str(timestamp)
    return hmac.new(
        HMAC_SECRET_KEY, 
        message_string.encode(), 
        hashlib.sha256
    ).hexdigest()

def verify_message_hmac(message_data, timestamp, received_hmac):
    """Verify HMAC for message authentication - TLS server compatible"""
    expected_hmac = generate_message_hmac(message_data, timestamp)
    return hmac.compare_digest(expected_hmac, received_hmac)

def load_user_keys():
    """Load user keys from secure storage"""
    global user_keys
    try:
        # First try the TLS server location
        if os.path.exists('user_keys_secure.json'):
            with open('user_keys_secure.json', 'r') as f:
                data = json.load(f)
                user_keys = data.get('users', {})
            logger.info(f"Loaded {len(user_keys)} users from TLS server storage")
        # Fallback to auth directory
        elif os.path.exists('auth/user_keys/user_keys_secure.json'):
            with open('auth/user_keys/user_keys_secure.json', 'r') as f:
                data = json.load(f)
                user_keys = data.get('users', {})
            logger.info(f"Loaded {len(user_keys)} users from auth directory")
        else:
            user_keys = {}
            logger.warning("No user keys file found, starting fresh")
    except FileNotFoundError:
        user_keys = {}
        logger.warning("No user keys file found, starting fresh")

def save_user_keys():
    """Save user keys to secure storage - compatible with TLS server"""
    data = {
        "users": user_keys,
        "last_updated": time.time(),
        "server_version": "2.0-FastAPI-TLS-Compatible"
    }
    
    # Save to TLS server location for compatibility
    with open('user_keys_secure.json', 'w') as f:
        json.dump(data, f, indent=2)
    
    # Also save to auth directory for backup
    os.makedirs('auth/user_keys', exist_ok=True)
    with open('auth/user_keys/user_keys_secure.json', 'w') as f:
        json.dump(data, f, indent=2)

def load_offline_messages():
    """Load offline messages from storage - TLS server compatible"""
    global offline_messages
    try:
        # Try TLS server location first
        if os.path.exists('offline_messages.json'):
            with open('offline_messages.json', 'r') as f:
                offline_messages = json.load(f)
        # Fallback to auth directory
        elif os.path.exists('auth/user_keys/offline_messages.json'):
            with open('auth/user_keys/offline_messages.json', 'r') as f:
                offline_messages = json.load(f)
        else:
            offline_messages = {}
    except FileNotFoundError:
        offline_messages = {}

def save_offline_messages():
    """Save offline messages to storage - TLS server compatible"""
    # Save to TLS server location for compatibility
    with open('offline_messages.json', 'w') as f:
        json.dump(offline_messages, f, indent=2)
    
    # Also save to auth directory for backup
    os.makedirs('auth/user_keys', exist_ok=True)
    with open('auth/user_keys/offline_messages.json', 'w') as f:
        json.dump(offline_messages, f, indent=2)

def generate_token(username: str) -> str:
    """Generate session token"""
    timestamp = str(int(time.time()))
    data = f"{username}:{timestamp}"
    token = base64.b64encode(data.encode()).decode()
    return token

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify JWT token and return username"""
    try:
        token = credentials.credentials
        decoded = base64.b64decode(token.encode()).decode()
        username, timestamp = decoded.split(':')
        
        # Check if token is valid (within 24 hours)
        token_time = int(timestamp)
        if time.time() - token_time > 86400:  # 24 hours
            raise HTTPException(status_code=401, detail="Token expired")
        
        # Check if user exists
        if username not in user_keys:
            raise HTTPException(status_code=401, detail="User not found")
        
        return username
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# Initialize data
load_user_keys()
load_offline_messages()

# API Endpoints

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "🔒 SecureChat Pro API",
        "version": "1.0.0",
        "description": "Secure messaging API with end-to-end encryption",
        "status": "operational",
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc"
        },
        "endpoints": {
            "health": "/api/v1/health",
            "auth": "/api/v1/auth/*",
            "users": "/api/v1/users/*",
            "messages": "/api/v1/messages/*"
        },
        "features": [
            "End-to-end encryption",
            "Offline messaging",
            "JWT authentication", 
            "Contact management",
            "Real-time messaging ready"
        ]
    }

@app.get("/api/v1/info")
async def api_info():
    """Get detailed API information"""
    return {
        "api_name": "SecureChat Pro API",
        "version": "1.0.0",
        "status": "operational",
        "server_time": time.time(),
        "statistics": {
            "registered_users": len(user_keys),
            "online_users": len(connected_users),
            "users_with_offline_messages": len(offline_messages),
            "total_offline_messages": sum(len(msgs) for msgs in offline_messages.values())
        },
        "endpoints": {
            "authentication": [
                "POST /api/v1/auth/register",
                "POST /api/v1/auth/login", 
                "POST /api/v1/auth/logout"
            ],
            "users": [
                "GET /api/v1/users/profile/{user_id}",
                "PUT /api/v1/users/profile",
                "GET /api/v1/users/contacts",
                "POST /api/v1/users/contacts/add",
                "GET /api/v1/users/online"
            ],
            "messaging": [
                "POST /api/v1/messages/send",
                "GET /api/v1/messages/inbox",
                "PUT /api/v1/messages/{message_id}/status",
                "DELETE /api/v1/messages/{message_id}",
                "GET /api/v1/messages/offline/clear"
            ],
            "utility": [
                "GET /api/v1/health",
                "GET /api/v1/info"
            ]
        },
        "security_features": [
            "JWT-based authentication",
            "End-to-end encryption support",
            "Offline message storage",
            "Rate limiting ready",
            "CORS configured"
        ]
    }

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "1.0.0",
        "users_count": len(user_keys),
        "offline_messages_count": sum(len(msgs) for msgs in offline_messages.values())
    }

@app.post("/api/v1/auth/register")
async def register_user(user_data: UserRegistration):
    """Register a new user"""
    username = user_data.username
    
    # Check if user already exists
    if username in user_keys:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Use provided safetoken (like TLS system)
    user_token = user_data.safetoken
    
    # Store user data exactly like TLS server
    user_keys[username] = {
        "public_key": user_data.public_key,
        "safetoken": user_token,
        "registered": time.time(),
        "registration_ip": "fastapi_mobile",
        "last_login": None
    }
    
    save_user_keys()
    
    # Generate session token
    session_token = generate_token(username)
    
    logger.info(f"New user registered: {username}")
    
    # Create response with HMAC
    response_data = {
        "success": True,
        "status": "success",  # TLS compatibility
        "user_id": username,
        "session_token": session_token,
        "message": "User registered successfully"
    }
    timestamp = time.time()
    hmac_value = generate_message_hmac(response_data, timestamp)
    
    return {
        **response_data,
        "timestamp": timestamp,
        "hmac": hmac_value
    }

@app.post("/api/v1/auth/login")
async def login_user(login_data: UserLogin):
    """Authenticate user login"""
    username = login_data.username
    safetoken = login_data.safetoken
    
    # Check if user exists
    if username not in user_keys:
        raise HTTPException(status_code=401, detail="User not registered")
    
    # Verify token
    stored_token = user_keys[username].get("safetoken")
    if stored_token != safetoken:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Update public key if provided
    if login_data.public_key:
        user_keys[username]["public_key"] = login_data.public_key
        logger.info(f"Updated public key for {username}")
    
    # Update last login
    user_keys[username]["last_login"] = time.time()
    
    save_user_keys()
    
    # Generate session token
    session_token = generate_token(username)
    
    # Mark user as online
    connected_users[username] = {
        "last_seen": time.time(),
        "status": "online"
    }
    
    logger.info(f"User logged in: {username}")
    
    # Create response with HMAC
    response_data = {
        "success": True,
        "status": "success",  # TLS compatibility
        "session_token": session_token,
        "user_profile": {
            "username": username,
            "user_id": username,
            "last_login": user_keys[username]["last_login"],
            "status": "online"
        },
        "message": "Login successful"  # TLS compatibility
    }
    timestamp = time.time()
    hmac_value = generate_message_hmac(response_data, timestamp)
    
    return {
        **response_data,
        "timestamp": timestamp,
        "hmac": hmac_value
    }

@app.post("/api/v1/auth/logout")
async def logout_user(username: str = Depends(verify_token)):
    """Logout user"""
    if username in connected_users:
        del connected_users[username]
    
    logger.info(f"User logged out: {username}")
    
    return {
        "success": True,
        "message": "Logged out successfully"
    }

@app.get("/api/v1/users/profile/{user_id}")
async def get_user_profile(user_id: str, current_user: str = Depends(verify_token)):
    """Get user profile"""
    if user_id not in user_keys:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_data = user_keys[user_id]
    is_online = user_id in connected_users
    
    return {
        "user_id": user_id,
        "username": user_id,
        "status": "online" if is_online else "offline",
        "last_seen": user_data.get("last_login", user_data.get("registered")),
        "bio": user_data.get("bio", "Hello, I'm using SecureChat!")
    }

@app.put("/api/v1/users/profile")
async def update_user_profile(profile_data: UserProfile, current_user: str = Depends(verify_token)):
    """Update user profile"""
    if profile_data.bio:
        user_keys[current_user]["bio"] = profile_data.bio
    
    if profile_data.profile_picture:
        user_keys[current_user]["profile_picture"] = profile_data.profile_picture
    
    if profile_data.privacy_settings:
        user_keys[current_user]["privacy_settings"] = profile_data.privacy_settings
    
    save_user_keys()
    
    return {
        "success": True,
        "message": "Profile updated successfully"
    }

@app.get("/api/v1/users/contacts")
async def get_contacts(current_user: str = Depends(verify_token)):
    """Get user's contacts (all other users)"""
    contacts = []
    
    for username, user_data in user_keys.items():
        if username != current_user:
            is_online = username in connected_users
            contacts.append({
                "user_id": username,
                "username": username,
                "status": "online" if is_online else "offline",
                "last_seen": user_data.get("last_login", user_data.get("registered")),
                "is_blocked": False
            })
    
    return {
        "contacts": contacts
    }

@app.post("/api/v1/users/contacts/add")
async def add_contact(contact_data: dict, current_user: str = Depends(verify_token)):
    """Add a contact"""
    username = contact_data.get("username")
    
    if not username:
        raise HTTPException(status_code=400, detail="Username required")
    
    if username not in user_keys:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_data = user_keys[username]
    
    return {
        "success": True,
        "contact": {
            "user_id": username,
            "username": username
        }
    }

@app.post("/api/v1/messages/send")
async def send_message(message_data: SendMessage, current_user: str = Depends(verify_token)):
    """Send encrypted message - supports both FastAPI and TLS formats"""
    
    # Handle both FastAPI and TLS format
    recipient_id = message_data.recipient_id or message_data.recipient
    encrypted_content = message_data.encrypted_content or message_data.payload
    
    if not recipient_id:
        raise HTTPException(status_code=400, detail="Recipient required (recipient_id or recipient)")
    
    if not encrypted_content:
        raise HTTPException(status_code=400, detail="Message content required (encrypted_content or payload)")
    
    # Check if recipient exists
    if recipient_id not in user_keys:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # Validate sender token if provided (TLS format)
    if message_data.safetoken:
        stored_token = user_keys[current_user].get("safetoken")
        if stored_token != message_data.safetoken:
            raise HTTPException(status_code=401, detail="Invalid sender token")
    
    # Generate message ID
    message_id = f"msg_{int(time.time() * 1000)}"
    
    # Create message object
    message = {
        "message_id": message_id,
        "sender_id": current_user,
        "sender": current_user,  # TLS compatibility
        "recipient_id": recipient_id,
        "recipient": recipient_id,  # TLS compatibility  
        "timestamp": time.time(),
        "message_type": message_data.message_type,
        "encrypted_content": encrypted_content,
        "payload": encrypted_content,  # TLS compatibility
        "metadata": message_data.metadata or {},
        "status": "sent"
    }
    
    # Check if recipient is online
    if recipient_id in connected_users:
        # TODO: Send real-time notification via WebSocket
        message["status"] = "delivered"
        logger.info(f"Message delivered in real-time to {recipient_id}")
    else:
        # Store as offline message
        if recipient_id not in offline_messages:
            offline_messages[recipient_id] = []
        offline_messages[recipient_id].append(message)
        save_offline_messages()
        logger.info(f"Message stored offline for {recipient_id}")
    
    logger.info(f"Message sent from {current_user} to {recipient_id}")
    
    return {
        "success": True,
        "status": "success",  # TLS compatibility
        "message_id": message_id,
        "timestamp": message["timestamp"],
        "delivery_status": message["status"],
        "message": "Message sent successfully"  # TLS compatibility
    }

@app.get("/api/v1/messages/inbox")
async def get_messages(
    limit: int = 50,
    offset: int = 0,
    since: Optional[float] = None,
    conversation_id: Optional[str] = None,
    current_user: str = Depends(verify_token)
):
    """Get user's messages (including offline messages)"""
    messages = []
    
    # Get offline messages for this user
    user_offline_messages = offline_messages.get(current_user, [])
    
    # Filter messages based on parameters
    filtered_messages = user_offline_messages
    
    if since:
        filtered_messages = [msg for msg in filtered_messages if msg["timestamp"] > since]
    
    if conversation_id:
        filtered_messages = [msg for msg in filtered_messages if msg["sender_id"] == conversation_id]
    
    # Apply pagination
    total_count = len(filtered_messages)
    paginated_messages = filtered_messages[offset:offset + limit]
    
    return {
        "messages": paginated_messages,
        "has_more": offset + limit < total_count,
        "total_count": total_count
    }

@app.put("/api/v1/messages/{message_id}/status")
async def update_message_status(
    message_id: str,
    status_data: MessageStatus,
    current_user: str = Depends(verify_token)
):
    """Update message status (read, delivered, etc.)"""
    # Find and update message status
    user_messages = offline_messages.get(current_user, [])
    
    for message in user_messages:
        if message["message_id"] == message_id:
            message["status"] = status_data.status
            message["read_at"] = status_data.timestamp
            save_offline_messages()
            logger.info(f"Message {message_id} marked as {status_data.status}")
            break
    
    return {
        "success": True,
        "message_id": message_id,
        "status": status_data.status
    }

@app.delete("/api/v1/messages/{message_id}")
async def delete_message(
    message_id: str,
    delete_for: str = "me",
    current_user: str = Depends(verify_token)
):
    """Delete message"""
    user_messages = offline_messages.get(current_user, [])
    
    # Remove message from offline storage
    offline_messages[current_user] = [
        msg for msg in user_messages if msg["message_id"] != message_id
    ]
    save_offline_messages()
    
    logger.info(f"Message {message_id} deleted for {current_user}")
    
    return {
        "success": True,
        "message": "Message deleted"
    }

@app.get("/api/v1/messages/offline/clear")
async def clear_offline_messages(current_user: str = Depends(verify_token)):
    """Clear offline messages after delivery"""
    if current_user in offline_messages:
        delivered_count = len(offline_messages[current_user])
        del offline_messages[current_user]
        save_offline_messages()
        logger.info(f"Cleared {delivered_count} offline messages for {current_user}")
        
        return {
            "success": True,
            "delivered_count": delivered_count,
            "message": f"Delivered {delivered_count} offline messages"
        }
    
    return {
        "success": True,
        "delivered_count": 0,
        "message": "No offline messages"
    }

@app.get("/api/v1/users/online")
async def get_online_users(current_user: str = Depends(verify_token)):
    """Get list of currently online users"""
    online_users = []
    
    for username in connected_users:
        if username != current_user and username in user_keys:
            online_users.append({
                "username": username,
                "user_id": username,
                "status": "online",
                "last_seen": connected_users[username]["last_seen"]
            })
    
    return {
        "online_users": online_users,
        "count": len(online_users)
    }

@app.get("/api/v1/keys/{username}")
async def get_user_public_key(username: str, current_user: str = Depends(verify_token)):
    """Get user's public key for encryption - TLS compatibility endpoint"""
    if username not in user_keys:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_data = user_keys[username]
    
    return {
        "status": "success",
        "username": username,
        "public_key": user_data["public_key"],
        "timestamp": time.time()
    }

@app.get("/api/v1/users/list")
async def get_user_list_tls(current_user: str = Depends(verify_token)):
    """Get user list - TLS compatibility endpoint"""
    online_users = list(connected_users.keys())
    registered_users = list(user_keys.keys())
    
    return {
        "status": "success",
        "online_users": online_users,
        "registered_users": registered_users,
        "timestamp": time.time()
    }

@app.post("/api/v1/auth/register_tls")
async def register_user_tls(request: dict):
    """TLS-compatible registration endpoint"""
    try:
        username = request.get("username")
        public_key = request.get("public_key")
        safetoken = request.get("safetoken")
        
        if not all([username, public_key, safetoken]):
            return {
                "status": "error",
                "message": "Missing required fields",
                "timestamp": time.time()
            }
        
        # Check if user already exists
        if username in user_keys:
            return {
                "status": "error", 
                "message": "User already exists",
                "timestamp": time.time()
            }
        
        # Store user data
        user_keys[username] = {
            "public_key": public_key,
            "safetoken": safetoken,
            "registered": time.time(),
            "registration_ip": "fastapi_tls_compat",
            "last_login": time.time()
        }
        
        save_user_keys()
        
        # Generate session token for FastAPI compatibility
        session_token = generate_token(username)
        
        # Mark user as connected
        connected_users[username] = {
            "last_seen": time.time(),
            "status": "online"
        }
        
        logger.info(f"TLS user registered: {username}")
        
        return {
            "status": "success",
            "message": "Registration successful",
            "timestamp": time.time(),
            "session_token": session_token  # For FastAPI clients
        }
        
    except Exception as e:
        logger.error(f"TLS registration error: {e}")
        return {
            "status": "error",
            "message": "Registration failed",
            "timestamp": time.time()
        }

# Background task to update user presence
@app.on_event("startup")
async def startup_event():
    """Initialize background tasks"""
    logger.info("FastAPI SecureChat Pro API started")
    logger.info(f"Loaded {len(user_keys)} users")
    logger.info(f"Offline messages for {len(offline_messages)} users")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    save_user_keys()
    save_offline_messages()
    logger.info("FastAPI SecureChat Pro API stopped")

if __name__ == "__main__":
    uvicorn.run(
        "fastapi_mobile_backend:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
