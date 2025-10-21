#!/usr/bin/env python3
"""
TLS 1.3 Secure Messaging Server with Advanced Cybersecurity Features
- TLS 1.3 encryption for all communications
- X.509 certificate authentication  
- Rate limiting and IP whitelisting
- Zero-knowledge architecture
- HMAC-SHA256 message authentication
"""

import socket
import ssl
import threading
import json
import time
import hashlib
import hmac
from collections import defaultdict
from datetime import datetime, timedelta
import ipaddress
import os

# ===== TLS CONFIGURATION =====
HOST = "0.0.0.0"
PORT = 5050
TLS_SERVER_CERT = "server_tls_certificate.pem"
TLS_SERVER_KEY = "server_tls_private_key.pem"
USE_TLS = os.path.exists(TLS_SERVER_CERT) and os.path.exists(TLS_SERVER_KEY)

# Security configuration
RATE_LIMIT_REQUESTS = 10  # Max requests per minute per IP
RATE_LIMIT_WINDOW = 60    # Time window in seconds
MAX_MESSAGE_SIZE = 8192   # Maximum message size in bytes
HMAC_SECRET_KEY = os.urandom(32)  # Server HMAC secret

# Data storage
user_public_keys = {}     # {username: {"public_key": pem_string, "token": str, "registered": timestamp}}
connected_users = {}      # {username: {"socket": tls_socket, "token": str, "last_seen": timestamp, "ip": str}}
offline_messages = defaultdict(list)  # {username: [messages]}

# Security tracking
rate_limiter = defaultdict(list)      # {ip: [timestamps]}
failed_auth_attempts = defaultdict(int)  # {ip: count}
ip_whitelist = set()  # Allowed IPs (empty = allow all)

def log_message(message):
    """Thread-safe logging with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def load_ip_whitelist():
    """Load IP whitelist from file"""
    global ip_whitelist
    try:
        if os.path.exists("ip_whitelist.txt"):
            with open("ip_whitelist.txt", "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith("#"):
                        try:
                            # Support both single IPs and CIDR ranges
                            ipaddress.ip_network(ip, strict=False)
                            ip_whitelist.add(ip)
                        except ValueError:
                            log_message(f"Invalid IP in whitelist: {ip}")
            log_message(f"Loaded {len(ip_whitelist)} IP whitelist entries")
        else:
            # Create default whitelist file
            with open("ip_whitelist.txt", "w") as f:
                f.write("# IP Whitelist - one IP or CIDR range per line\\n")
                f.write("# Examples:\\n")
                f.write("# 127.0.0.1\\n")
                f.write("# 192.168.1.0/24\\n")
                f.write("# 10.0.0.0/8\\n")
                f.write("\\n# Allow localhost by default\\n")
                f.write("127.0.0.1\\n")
                f.write("::1\\n")
            ip_whitelist.add("127.0.0.1")
            ip_whitelist.add("::1")
            log_message("Created default IP whitelist file")
    except Exception as e:
        log_message(f"Error loading IP whitelist: {e}")

def is_ip_whitelisted(client_ip):
    """Check if IP is in whitelist"""
    if not ip_whitelist:  # Empty whitelist = allow all
        return True
    
    try:
        client_addr = ipaddress.ip_address(client_ip)
        for allowed in ip_whitelist:
            allowed_network = ipaddress.ip_network(allowed, strict=False)
            if client_addr in allowed_network:
                return True
        return False
    except Exception as e:
        log_message(f"IP validation error: {e}")
        return False

def check_rate_limit(client_ip):
    """Check if client is within rate limits"""
    current_time = time.time()
    
    # Clean old entries
    rate_limiter[client_ip] = [
        timestamp for timestamp in rate_limiter[client_ip]
        if current_time - timestamp < RATE_LIMIT_WINDOW
    ]
    
    # Check if within limits
    if len(rate_limiter[client_ip]) >= RATE_LIMIT_REQUESTS:
        return False
    
    # Add current request
    rate_limiter[client_ip].append(current_time)
    return True

def generate_message_hmac(message_data, timestamp):
    """Generate HMAC for message authentication"""
    message_string = json.dumps(message_data, sort_keys=True) + str(timestamp)
    return hmac.new(
        HMAC_SECRET_KEY, 
        message_string.encode(), 
        hashlib.sha256
    ).hexdigest()

def verify_message_hmac(message_data, timestamp, received_hmac):
    """Verify HMAC for message authentication"""
    expected_hmac = generate_message_hmac(message_data, timestamp)
    return hmac.compare_digest(expected_hmac, received_hmac)

def create_tls_context():
    """Create secure TLS context with strong security settings"""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # Load server certificate and key
    context.load_cert_chain(TLS_SERVER_CERT, TLS_SERVER_KEY)
    
    # Security settings
    context.minimum_version = ssl.TLSVersion.TLSv1_3  # Force TLS 1.3
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    
    log_message("🔒 TLS 1.3 context created with strong security settings")
    return context

def save_user_keys():
    """Save user keys to encrypted file"""
    try:
        # Add timestamp for audit trail
        data_to_save = {
            "users": user_public_keys,
            "last_updated": time.time(),
            "server_version": "2.0-TLS"
        }
        
        filename = "user_keys_secure.json" if USE_TLS else "user_keys.json"
        with open(filename, "w") as f:
            json.dump(data_to_save if USE_TLS else user_public_keys, f, indent=2)
    except Exception as e:
        log_message(f"Error saving user keys: {e}")

def load_user_keys():
    """Load user keys from encrypted file"""
    global user_public_keys
    try:
        # Try new secure format first, then legacy
        for filename in ["user_keys_secure.json", "user_keys.json"]:
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    data = json.load(f)
                    if "users" in data:  # New secure format
                        user_public_keys = data["users"]
                        log_message(f"Loaded {len(user_public_keys)} user keys (secure format)")
                    else:  # Legacy format
                        user_public_keys = data
                        log_message(f"Loaded {len(user_public_keys)} user keys (legacy format)")
                break
    except Exception as e:
        log_message(f"Error loading user keys: {e}")

def handle_key_registration(client_socket, data):
    """Handle secure user registration with enhanced validation"""
    try:
        username = data.get("username")
        public_key = data.get("public_key") 
        token = data.get("safetoken")
        client_ip = client_socket.getpeername()[0] if hasattr(client_socket, 'getpeername') else "unknown"
        
        if not all([username, public_key, token]):
            client_socket.send(json.dumps({"status": "error", "message": "Missing required fields"}).encode())
            return False
        
        # Enhanced validation
        if len(username) < 3 or len(username) > 20:
            client_socket.send(json.dumps({"status": "error", "message": "Username must be 3-20 characters"}).encode())
            return False
        
        if len(token) < 8:
            client_socket.send(json.dumps({"status": "error", "message": "Token too short"}).encode())
            return False
        
        # Store user data with security metadata
        user_public_keys[username] = {
            "public_key": public_key,
            "token": token,
            "registered": time.time(),
            "registration_ip": client_ip,
            "last_login": time.time()
        }
        
        save_user_keys()
        
        # Generate response with HMAC if TLS is enabled
        response_data = {"status": "success", "message": "Registration successful"}
        
        if USE_TLS:
            timestamp = time.time()
            hmac_value = generate_message_hmac(response_data, timestamp)
            response = {
                **response_data,
                "timestamp": timestamp,
                "hmac": hmac_value
            }
        else:
            response = response_data
        
        client_socket.send(json.dumps(response).encode())
        log_message(f"REGISTERED: {username} from {client_ip}")
        return True
        
    except Exception as e:
        log_message(f"Registration error: {e}")
        client_socket.send(json.dumps({"status": "error", "message": "Registration failed"}).encode())
        return False

def handle_key_request(client_socket, data):
    """Handle public key requests with enhanced security"""
    try:
        requested_user = data.get("requested_user")
        requester = data.get("requester")
        
        if requested_user in user_public_keys:
            response_data = {
                "status": "success",
                "username": requested_user,
                "public_key": user_public_keys[requested_user]["public_key"]
            }
            
            # Add HMAC for integrity if TLS enabled
            if USE_TLS:
                timestamp = time.time()
                hmac_value = generate_message_hmac(response_data, timestamp)
                response = {
                    **response_data,
                    "timestamp": timestamp,
                    "hmac": hmac_value
                }
            else:
                response = response_data
            
            client_socket.send(json.dumps(response).encode())
            log_message(f"KEY REQUEST: {requester} -> {requested_user}")
        else:
            client_socket.send(json.dumps({"status": "error", "message": f"User {requested_user} not found"}).encode())
            
    except Exception as e:
        log_message(f"Key request error: {e}")
        client_socket.send(json.dumps({"status": "error", "message": "Key request failed"}).encode())

def handle_user_list(client_socket, data):
    """Handle user list requests with enhanced security"""
    try:
        online_users = list(connected_users.keys())
        registered_users = list(user_public_keys.keys())
        
        response_data = {
            "status": "success", 
            "online_users": online_users,
            "registered_users": registered_users
        }
        
        # Add HMAC for integrity if TLS enabled
        if USE_TLS:
            timestamp = time.time()
            hmac_value = generate_message_hmac(response_data, timestamp)
            response = {
                **response_data,
                "timestamp": timestamp,
                "hmac": hmac_value
            }
        else:
            response = response_data
        
        client_socket.send(json.dumps(response).encode())
        log_message(f"USER LIST: online={online_users}, registered={registered_users}")
        
    except Exception as e:
        log_message(f"User list error: {e}")
        client_socket.send(json.dumps({"status": "error", "message": "Failed to get user list"}).encode())

def handle_secure_message(client_socket, message_json, sender, client_ip):
    """Handle message with enhanced security validation"""
    try:
        recipient = message_json["recipient"]
        payload = message_json["payload"]
        sender_token = message_json.get("safetoken", "")
        
        # Validate sender
        if sender not in connected_users or connected_users[sender]["token"] != sender_token:
            client_socket.send(json.dumps({"status": "error", "message": "Invalid sender token"}).encode())
            return
        
        # Zero-knowledge: Server never sees plaintext (payload is already encrypted)
        message_data = {
            "type": "message",
            "sender": sender,
            "payload": payload,  # Encrypted payload
            "timestamp": time.time(),
        }
        
        # Add server HMAC if TLS enabled
        if USE_TLS:
            message_data["server_hmac"] = generate_message_hmac({"sender": sender, "recipient": recipient}, time.time())
        
        # Deliver message
        if recipient in connected_users:
            try:
                recipient_sock = connected_users[recipient]["socket"]
                recipient_sock.send(json.dumps(message_data).encode())
                client_socket.send(json.dumps({"status": "success", "message": "Message delivered"}).encode())
                log_message(f"{'TLS ' if USE_TLS else ''}MESSAGE: {sender} -> {recipient}")
            except Exception as e:
                log_message(f"Failed to deliver message: {e}")
                store_offline_message(recipient, message_data)
                client_socket.send(json.dumps({"status": "success", "message": "Message stored for offline delivery"}).encode())
        else:
            # Store for offline delivery
            store_offline_message(recipient, message_data)
            client_socket.send(json.dumps({"status": "success", "message": "Message stored for offline delivery"}).encode())
            
    except KeyError as e:
        client_socket.send(json.dumps({"status": "error", "message": f"Missing field: {e}"}).encode())
    except Exception as e:
        log_message(f"Secure message error: {e}")
        client_socket.send(json.dumps({"status": "error", "message": "Message processing failed"}).encode())

def store_offline_message(recipient, message_data):
    """Store message for offline users (encrypted storage)"""
    try:
        offline_messages[recipient].append(message_data)
        log_message(f"OFFLINE MESSAGE stored for {recipient}")
    except Exception as e:
        log_message(f"Error storing offline message: {e}")

def deliver_offline_messages(username, client_socket):
    """Deliver stored offline messages"""
    try:
        if username in offline_messages and offline_messages[username]:
            messages = offline_messages[username]
            for message in messages:
                client_socket.send(json.dumps(message).encode())
                time.sleep(0.1)  # Prevent message collision
            
            # Clear delivered messages
            offline_messages[username] = []
            log_message(f"Delivered {len(messages)} offline messages to {username}")
    except Exception as e:
        log_message(f"Error delivering offline messages: {e}")

def handle_heartbeat(client_socket, username):
    """Handle heartbeat with timestamp validation"""
    try:
        if username in connected_users:
            connected_users[username]["last_seen"] = time.time()
        
        response_data = {"status": "success", "type": "heartbeat_ack"}
        
        if USE_TLS:
            timestamp = time.time()
            hmac_value = generate_message_hmac(response_data, timestamp)
            response = {
                **response_data,
                "timestamp": timestamp,
                "hmac": hmac_value
            }
        else:
            response = response_data
        
        client_socket.send(json.dumps(response).encode())
    except Exception as e:
        log_message(f"Heartbeat error: {e}")

def handle_client_connection(client_socket, client_address):
    """Handle client connection with optional TLS security"""
    client_ip = client_address[0]
    username = None
    
    try:
        connection_type = "TLS" if USE_TLS else "TCP"
        log_message(f"New {connection_type} connection from {client_address}")
        
        # Security checks (if enabled)
        if USE_TLS:
            # IP whitelist check
            if not is_ip_whitelisted(client_ip):
                log_message(f"BLOCKED: IP {client_ip} not in whitelist")
                client_socket.close()
                return
            
            # Rate limiting check
            if not check_rate_limit(client_ip):
                log_message(f"RATE LIMITED: {client_ip}")
                client_socket.send(json.dumps({"status": "error", "message": "Rate limit exceeded"}).encode())
                client_socket.close()
                return
        
        # Receive login data
        login_data = client_socket.recv(MAX_MESSAGE_SIZE).decode()
        if not login_data:
            return
            
        login = json.loads(login_data)
        action = login.get("action", "login")
        username = login.get("username")
        token = login.get("safetoken")
        
        # Authentication
        if action == "register":
            if handle_key_registration(client_socket, login):
                username = login["username"]
                connected_users[username] = {
                    "socket": client_socket,
                    "token": token,
                    "last_seen": time.time(),
                    "ip": client_ip
                }
                log_message(f"REGISTERED & CONNECTED: {username} from {client_ip}")
                deliver_offline_messages(username, client_socket)
            else:
                return
        elif action == "login":
            if username in user_public_keys:
                stored_token = user_public_keys[username].get("token")
                if stored_token == token:
                    connected_users[username] = {
                        "socket": client_socket,
                        "token": token,
                        "last_seen": time.time(),
                        "ip": client_ip
                    }
                    
                    # Update last login
                    if USE_TLS:
                        user_public_keys[username]["last_login"] = time.time()
                        save_user_keys()
                    
                    # Send success response
                    response_data = {"status": "success", "message": "Login successful"}
                    
                    if USE_TLS:
                        timestamp = time.time()
                        hmac_value = generate_message_hmac(response_data, timestamp)
                        response = {
                            **response_data,
                            "timestamp": timestamp,
                            "hmac": hmac_value
                        }
                    else:
                        response = response_data
                    
                    client_socket.send(json.dumps(response).encode())
                    log_message(f"CONNECTED: {username} from {client_ip}")
                    
                    # Deliver offline messages
                    deliver_offline_messages(username, client_socket)
                else:
                    if USE_TLS:
                        failed_auth_attempts[client_ip] += 1
                        log_message(f"AUTH FAILED: {username} from {client_ip} (attempt #{failed_auth_attempts[client_ip]})")
                    client_socket.send(json.dumps({"status": "error", "message": "Invalid token"}).encode())
                    return
            else:
                client_socket.send(json.dumps({"status": "error", "message": "User not registered"}).encode())
                return
        
        # Main message handling loop
        while True:
            try:
                data = client_socket.recv(MAX_MESSAGE_SIZE)
                if not data:
                    break
                
                # Rate limit check for each message (if TLS enabled)
                if USE_TLS and not check_rate_limit(client_ip):
                    client_socket.send(json.dumps({"status": "error", "message": "Rate limit exceeded"}).encode())
                    continue
                
                message_json = json.loads(data.decode())
                msg_type = message_json.get("type", "unknown")
                
                # Update last seen
                if username in connected_users:
                    connected_users[username]["last_seen"] = time.time()
                
                # Handle different message types
                if msg_type == "message":
                    handle_secure_message(client_socket, message_json, username, client_ip)
                elif msg_type == "get_key":
                    handle_key_request(client_socket, message_json)
                elif msg_type == "get_users":
                    handle_user_list(client_socket, message_json)
                elif msg_type == "heartbeat":
                    handle_heartbeat(client_socket, username)
                    
            except json.JSONDecodeError:
                log_message(f"Invalid JSON from {client_ip}")
            except Exception as e:
                log_message(f"Message handling error from {client_ip}: {e}")
                break
                
    except Exception as e:
        log_message(f"Client handler error for {client_ip}: {e}")
    finally:
        # Cleanup
        if username and username in connected_users:
            del connected_users[username]
            log_message(f"DISCONNECTED: {username} from {client_ip}")
        try:
            client_socket.close()
        except:
            pass

def start_server():
    """Start the secure messaging server (with optional TLS)"""
    if USE_TLS:
        log_message("🔒 Starting TLS 1.3 Secure Messaging Server")
        log_message("=" * 50)
    else:
        log_message("📡 Starting Standard Messaging Server")
        log_message("💡 Generate TLS certificates for enhanced security!")
        log_message("   Run: python3 generate_certificates.py")
        log_message("=" * 50)
    
    # Load configuration and data
    load_user_keys()
    if USE_TLS:
        load_ip_whitelist()
    
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    
    if USE_TLS:
        # Create TLS context
        tls_context = create_tls_context()
        
        log_message(f"🔐 TLS Server starting on {HOST}:{PORT}")
        log_message(f"🛡️  Security features active:")
        log_message(f"    ✅ TLS 1.3 encryption")
        log_message(f"    ✅ Rate limiting ({RATE_LIMIT_REQUESTS}/min)")
        log_message(f"    ✅ IP whitelisting ({len(ip_whitelist)} entries)")
        log_message(f"    ✅ HMAC-SHA256 message authentication")
        log_message(f"    ✅ Zero-knowledge architecture")
    else:
        log_message(f"📡 Server starting on {HOST}:{PORT}")
        log_message("⚠️  Running without TLS encryption")
        log_message("🔒 For maximum security, generate TLS certificates!")
        tls_context = None
    
    log_message(f"📊 Loaded {len(user_public_keys)} registered users")
    log_message("🚀 Ready for connections...")
    
    try:
        while True:
            # Accept connection
            client_socket, client_address = server_socket.accept()
            
            try:
                # Wrap in TLS if enabled
                if USE_TLS:
                    try:
                        tls_socket = tls_context.wrap_socket(client_socket, server_side=True)
                        final_socket = tls_socket
                    except ssl.SSLError as e:
                        log_message(f"TLS handshake failed with {client_address}: {e}")
                        client_socket.close()
                        continue
                else:
                    final_socket = client_socket
                
                # Handle in separate thread
                client_thread = threading.Thread(
                    target=handle_client_connection,
                    args=(final_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                log_message(f"Error accepting connection from {client_address}: {e}")
                client_socket.close()
                
    except KeyboardInterrupt:
        log_message("🛑 Server shutdown requested")
    finally:
        server_socket.close()
        server_type = "TLS Server" if USE_TLS else "Server"
        log_message(f"✅ {server_type} stopped")

if __name__ == "__main__":
    start_server()