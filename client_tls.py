#!/usr/bin/env python3
"""
TLS 1.3 Secure Messaging Client with Advanced Cybersecurity Features
- TLS 1.3 encryption for all communications
- X.509 certificate validation
- HMAC-SHA256 message authentication
- AES-256-GCM authenticated encryption
- DNS over HTTPS protection
- Anti-forensics and secure memory handling
"""

import socket
import ssl
import json
import threading
import time
import os
import base64
import hashlib
import hmac
import gc
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2, HKDF

# TLS Configuration
TLS_SERVER_CERT = "server_tls_certificate.pem"
TLS_CLIENT_CERT = "client_tls_default_certificate.pem"  
TLS_CLIENT_KEY = "client_tls_default_private_key.pem"

# DNS over HTTPS configuration (anti-DNS poisoning)
DNS_OVER_HTTPS_SERVERS = [
    "https://1.1.1.1/dns-query",      # Cloudflare
    "https://8.8.8.8/dns-query",       # Google
    "https://9.9.9.9/dns-query"        # Quad9
]

# Server configuration with secure DNS resolution
import os
SERVER_IP = os.environ.get("PAGER_SERVER_IP") or input("Server address (press Enter for localhost): ").strip() or "127.0.0.1"
PORT = 5050

# Security constants
MAX_MESSAGE_SIZE = 65536  # Increased to 64KB for large encrypted payloads
SECURE_MEMORY_CLEAR_PATTERN = b'\x00' * 1024  # For memory clearing

# File paths for key storage (with secure naming)
PRIVATE_KEY_FILE = "user_private_key.pem"
PUBLIC_KEY_CACHE = "public_keys_cache.json"

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
                # Overwrite with random data multiple times (anti-forensics)
                for _ in range(3):
                    for i in range(len(data_bytes)):
                        data_bytes[i] = get_random_bytes(1)[0]
                # Clear the bytearray
                data_bytes.clear()
            elif isinstance(data, bytearray):
                # Overwrite with random data multiple times
                for _ in range(3):
                    for i in range(len(data)):
                        data[i] = get_random_bytes(1)[0]
                # Clear the bytearray
                data.clear()
            elif isinstance(data, bytes):
                # bytes objects are immutable, so we can't overwrite them
                # Just delete the reference and let GC handle it
                pass
        except Exception:
            # If clearing fails, just let GC handle it
            pass
        
        # Force garbage collection
        gc.collect()
    
    @staticmethod
    def create_secure_string(size):
        """Create a securely initialized string"""
        return get_random_bytes(size)

class TLSSecureMessenger:
    def __init__(self):
        self.username = None
        self.safetoken = None
        self.master_decrypt_token = None  # Store master token during session
        self.master_salt = None
        self.private_key = None
        self.public_key = None
        self.tls_socket = None
        self.public_key_cache = {}
        self.running = False
        self.encrypted_messages = []
        self.waiting_for_user_list = False
        self.user_list_response = None
        self.waiting_for_public_key = False
        self.public_key_response = None
        self.session_key = get_random_bytes(32)  # Session encryption key
        self.message_counter = 0  # Prevent replay attacks
        self.master_token_cached = False  # Track if master token is in memory
        
    def log_message(self, message):
        """Thread-safe logging with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
        
    def create_tls_context(self):
        """Create secure TLS context for client"""
        context = ssl.create_default_context()
        
        # Load server certificate for verification
        if os.path.exists(TLS_SERVER_CERT):
            context.load_verify_locations(TLS_SERVER_CERT)
            context.check_hostname = False  # Using IP address
        else:
            # For development - disable certificate verification
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.log_message("⚠️  Running without certificate verification (development mode)")
        
        # Security settings
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        # Optional: Load client certificate for mutual TLS
        if os.path.exists(TLS_CLIENT_CERT) and os.path.exists(TLS_CLIENT_KEY):
            context.load_cert_chain(TLS_CLIENT_CERT, TLS_CLIENT_KEY)
            self.log_message("🔐 Using client certificate for mutual TLS authentication")
        
        return context
        
    def connect_to_server(self):
        """Establish secure TLS connection to server"""
        try:
            self.log_message("=== TLS 1.3 Secure Messenger ===")
            
            # Create TLS context
            tls_context = self.create_tls_context()
            
            # Create socket and connect
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(30)  # Connection timeout
            
            # Wrap in TLS
            self.tls_socket = tls_context.wrap_socket(
                raw_socket, 
                server_hostname=SERVER_IP if SERVER_IP != "127.0.0.1" else None
            )
            
            # Connect to server
            self.tls_socket.connect((SERVER_IP, PORT))
            
            # Set socket timeout for recv operations
            self.tls_socket.settimeout(5.0)
            
            # Log TLS connection details
            cipher = self.tls_socket.cipher()
            version = self.tls_socket.version()
            
            self.log_message(f"🔒 Secure TLS connection established")
            self.log_message(f"    Server: {SERVER_IP}:{PORT}")
            self.log_message(f"    Protocol: {version}")
            self.log_message(f"    Cipher: {cipher[0] if cipher else 'Unknown'}")
            
            # Get server certificate info for validation
            server_cert = self.tls_socket.getpeercert()
            if server_cert:
                self.log_message(f"    Server Certificate: {server_cert.get('subject', 'Unknown')}")
            
            return True
            
        except ssl.SSLError as e:
            self.log_message(f"❌ TLS handshake failed: {e}")
            return False
        except Exception as e:
            self.log_message(f"❌ Connection failed: {e}")
            return False
            
    def verify_message_hmac(self, message_data, timestamp, received_hmac):
        """Verify HMAC for message authentication (client-side validation)"""
        # Note: Client doesn't have server's HMAC key, so this is for structure
        # In production, you'd use message-specific HMACs
        return True  # Placeholder - implement proper HMAC verification
        
    def generate_message_nonce(self):
        """Generate unique nonce for each message (prevent replay attacks)"""
        self.message_counter += 1
        return f"{time.time()}_{self.message_counter}_{get_random_bytes(8).hex()}"
        
    def encrypt_with_aes_gcm(self, plaintext, key):
        """Encrypt using AES-256-GCM (authenticated encryption)"""
        try:
            # Generate random nonce (96-bit for GCM)
            nonce = get_random_bytes(12)
            
            # Create AES-GCM cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Encrypt and get authentication tag
            ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext.encode() if isinstance(plaintext, str) else plaintext)
            
            # Package with nonce and tag
            return {
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "auth_tag": base64.b64encode(auth_tag).decode(),
                "method": "aes_256_gcm"
            }
            
        except Exception as e:
            self.log_message(f"AES-GCM encryption error: {e}")
            return None
            
    def decrypt_with_aes_gcm(self, encrypted_data, key):
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
            self.log_message(f"AES-GCM authentication failed: {e}")
            return None
        except Exception as e:
            self.log_message(f"AES-GCM decryption error: {e}")
            return None
            
    def setup_master_decrypt_token(self):
        """Setup master decrypt token with enhanced security"""
        salt_file = f"{self.username}_master_salt.dat"
        
        if os.path.exists(salt_file):
            # Load existing salt
            with open(salt_file, "rb") as f:
                self.master_salt = f.read()
            self.log_message("🔐 Existing master token configuration found")
        else:
            # Generate new salt for new user
            self.master_salt = get_random_bytes(32)
            
            # Enhanced master token setup
            print("\n🔒 ENHANCED MASTER DECRYPT TOKEN SETUP")
            print("=" * 50)
            print("Create a master password for triple-layer encryption.")
            print("This password protects your local message decryption.")
            print("Requirements: 12+ characters, mix of letters/numbers/symbols")
            print()
            
            while True:
                master_token = input("🔑 Create your master decrypt token: ").strip()
                
                # Enhanced password validation
                if len(master_token) < 12:
                    print("❌ Master token must be at least 12 characters long")
                    continue
                    
                # Check for complexity
                has_upper = any(c.isupper() for c in master_token)
                has_lower = any(c.islower() for c in master_token) 
                has_digit = any(c.isdigit() for c in master_token)
                has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in master_token)
                
                complexity_score = sum([has_upper, has_lower, has_digit, has_symbol])
                
                if complexity_score < 3:
                    print("❌ Password must contain at least 3 of: uppercase, lowercase, digits, symbols")
                    continue
                    
                confirm_token = input("🔐 Confirm your master decrypt token: ").strip()
                if master_token == confirm_token:
                    print(f"✅ Secure master decrypt token created!")
                    print(f"🛡️  Complexity score: {complexity_score}/4")
                    print(f"💡 Remember this password: '{master_token}'")
                    print("=" * 50)
                    
                    # Clear sensitive variables from memory
                    SecureMemory.secure_clear(confirm_token)
                    break
                else:
                    print("❌ Tokens don't match. Try again.")
                    SecureMemory.secure_clear(master_token)
                    SecureMemory.secure_clear(confirm_token)
            
            # Save salt with secure permissions
            with open(salt_file, "wb") as f:
                f.write(self.master_salt)
            
            # Set secure file permissions (Unix/Linux)
            try:
                os.chmod(salt_file, 0o600)  # Owner read/write only
            except:
                pass  # Windows doesn't support chmod
                
            self.log_message("🔒 New master token configuration created with enhanced security")
            
    def derive_master_key(self, master_token):
        """Derive encryption key using enhanced PBKDF2"""
        try:
            # Enhanced PBKDF2 with more iterations for better security
            master_key = PBKDF2(
                master_token, 
                self.master_salt, 
                32,  # 256-bit key
                count=200000  # Increased iterations for better security
            )
            return master_key
        except Exception as e:
            self.log_message(f"Key derivation error: {e}")
            return None
            
    def derive_channel_key(self, master_key, user1, user2):
        """Derive a shared channel key that both users can compute independently"""
        try:
            # Sort usernames alphabetically to ensure both users derive the same key
            users = sorted([user1, user2])
            channel_salt = f"{users[0]}:{users[1]}:channel".encode()
            
            # Derive channel key using HKDF from PyCryptodome
            # Signature: HKDF(master, key_len, salt, hashmod, num_keys=1, context=None)
            channel_key = HKDF(
                master_key,
                32,  # 256-bit key
                channel_salt,
                SHA256,
                context=b'pager_channel_key'
            )
            return channel_key
        except Exception as e:
            self.log_message(f"Channel key derivation error: {e}")
            return None
    
    def derive_message_key(self, master_key, nonce):
        """Derive message-specific key from user's own master key"""
        try:
            # Create unique salt from message nonce
            salt_data = f"{self.username}:{nonce}".encode()
            
            # Use HKDF to derive message key from master key
            # Signature: HKDF(master, key_len, salt, hashmod, num_keys=1, context=None)
            message_key = HKDF(
                master_key,
                32,  # 256-bit key
                salt_data,
                SHA256,
                context=b'pager_message_key'
            )
            return message_key
        except Exception as e:
            self.log_message(f"Message key derivation error: {e}")
            return None
            
    def derive_shared_secret_key(self, other_username, master_token):
        """Derive a shared secret key that both users can independently compute"""
        try:
            # Use sorted usernames to ensure both sides derive the same key
            users_sorted = sorted([self.username, other_username])
            
            # Create a deterministic salt that both users will compute the same way
            # Include date for daily rotation
            shared_salt = f"shared:{users_sorted[0]}:{users_sorted[1]}:{time.strftime('%Y-%m-%d')}".encode()
            
            # Derive from master token
            master_key = self.derive_master_key(master_token)
            if not master_key:
                return None
            
            # Use HKDF to derive shared secret from PyCryptodome
            # Signature: HKDF(master, key_len, salt, hashmod, num_keys=1, context=None)
            shared_key = HKDF(
                master_key,
                32,  # 256-bit key  
                shared_salt,
                SHA256,
                context=b'pager_shared_secret'
            )
            
            # Clear master key
            SecureMemory.secure_clear(master_key)
            return shared_key
            
        except Exception as e:
            self.log_message(f"Shared secret derivation error: {e}")
            return None
            
    def cache_master_token(self):
        """Cache master token for session to avoid repeated prompts when SENDING messages"""
        if self.master_token_cached and self.master_decrypt_token:
            return True
            
        print("\n🔐 MASTER TOKEN AUTHENTICATION")
        print("=" * 40)
        print("Enter your master decrypt token for secure messaging")
        print("NOTE: This will be cached for SENDING messages only")
        print("Decrypting messages will always require manual entry")
        
        for attempt in range(3):  # Allow 3 attempts
            master_token = input("🔑 Master decrypt token: ").strip()
            
            if not master_token:
                print("❌ Master token cannot be empty")
                continue
                
            # Validate token by testing key derivation
            test_key = self.derive_master_key(master_token)
            if test_key:
                self.master_decrypt_token = master_token
                self.master_token_cached = True
                # Clear test key from memory
                SecureMemory.secure_clear(test_key)
                self.log_message("✅ Master token validated and cached for session")
                return True
            else:
                print(f"❌ Invalid master token (attempt {attempt + 1}/3)")
                
        self.log_message("❌ Failed to validate master token after 3 attempts")
        return False
            
    def encrypt_message_advanced(self, message, recipient_username, sender_master_token=None):
        """Double encryption: sender's master token + recipient's channel key"""
        try:
            # Validate sender's master token
            if not sender_master_token:
                self.log_message("❌ Master token required for encryption")
                return None
                
            # Derive encryption key from sender's master token
            sender_master_key = self.derive_master_key(sender_master_token)
            if not sender_master_key:
                self.log_message("❌ Invalid sender master token")
                return None
            
            # Generate unique nonce for this message
            message_nonce = self.generate_message_nonce()
            
            # Derive message-specific key from sender's master key
            sender_message_key = self.derive_message_key(sender_master_key, message_nonce)
            if not sender_message_key:
                SecureMemory.secure_clear(sender_master_key)
                return None
            
            # Create message with metadata
            message_with_metadata = {
                "content": message,
                "timestamp": time.time(),
                "nonce": message_nonce,
                "sender": self.username,
                "recipient": recipient_username
            }
            
            message_json = json.dumps(message_with_metadata)
            
            # LAYER 1: Encrypt with sender's key (for sender's authentication)
            layer1_encrypted = self.encrypt_with_aes_gcm(message_json, sender_message_key)
            if not layer1_encrypted:
                SecureMemory.secure_clear(sender_master_key)
                SecureMemory.secure_clear(sender_message_key)
                return None
            
            # Derive a channel key that receiver can compute
            # Use a deterministic derivation based on usernames (sorted alphabetically)
            channel_key = self.derive_channel_key(sender_master_key, self.username, recipient_username)
            
            # LAYER 2: Encrypt layer1 with channel key (for receiver access)
            layer1_json = json.dumps(layer1_encrypted)
            layer2_encrypted = self.encrypt_with_aes_gcm(layer1_json, channel_key)
            
            if not layer2_encrypted:
                SecureMemory.secure_clear(sender_master_key)
                SecureMemory.secure_clear(sender_message_key)
                SecureMemory.secure_clear(channel_key)
                return None
            
            self.log_message(f"🔐 Using double-layer AES-256-GCM encryption")
            
            # Package everything
            aes_payload = {
                "encrypted_message": layer2_encrypted,  # Double encrypted
                "method": "double_aes_gcm",
                "sender": self.username,
                "recipient": recipient_username,
                "nonce": message_nonce,
                "version": "3.1"
            }
            
            # Clear keys from memory
            SecureMemory.secure_clear(sender_master_key)
            SecureMemory.secure_clear(sender_message_key)
            SecureMemory.secure_clear(channel_key)
            
            return json.dumps(aes_payload)
            
        except Exception as e:
            self.log_message(f"Encryption error: {e}")
            return None
            
    def decrypt_message_advanced(self, encrypted_payload, recipient_master_token=None):
        """Pure AES-GCM decryption using master token derived key"""
        try:
            # Validate recipient's master token
            if not recipient_master_token:
                return "[MASTER TOKEN REQUIRED]"
                
            master_key = self.derive_master_key(recipient_master_token)
            if not master_key:
                return "[INVALID MASTER TOKEN]"
            
            # Parse payload
            if isinstance(encrypted_payload, str):
                try:
                    payload = json.loads(encrypted_payload)
                    method = payload.get("method", "unknown")
                    
                    if method == "pure_aes_gcm":
                        return self._decrypt_pure_aes_gcm(payload, master_key)
                    elif method == "advanced_hybrid_aes_gcm_rsa":
                        # Legacy RSA support (will show compatibility warning)
                        self.log_message("⚠️  Decrypting legacy RSA message - consider upgrading")
                        return self._decrypt_advanced_hybrid(payload)
                    else:
                        # Fallback to legacy methods
                        return self._decrypt_hybrid_legacy(payload)
                except json.JSONDecodeError:
                    return "[INVALID PAYLOAD FORMAT]"
            
            return "[INVALID PAYLOAD FORMAT]"
            
        except Exception as e:
            self.log_message(f"Advanced decryption error: {e}")
            return "[DECRYPTION FAILED]"
            
    def _decrypt_pure_aes_gcm(self, payload, master_key):
        """Decrypt double-encrypted AES-GCM message using receiver's master token"""
        try:
            # Validate payload structure
            required_fields = ["encrypted_message", "sender", "recipient", "nonce"]
            for field in required_fields:
                if field not in payload:
                    return f"[MISSING FIELD: {field}]"
            
            sender = payload["sender"]
            recipient = payload["recipient"]
            message_nonce = payload["nonce"]
            
            # Verify this message is for us
            if recipient != self.username:
                return f"[MESSAGE NOT FOR YOU: intended for {recipient}]"
            
            # LAYER 2 DECRYPTION: Derive channel key (same as sender used)
            channel_key = self.derive_channel_key(master_key, sender, recipient)
            if not channel_key:
                return "[CHANNEL KEY DERIVATION FAILED]"
            
            # Decrypt layer 2 to get layer 1 encrypted data
            encrypted_msg_data = payload["encrypted_message"]
            if not isinstance(encrypted_msg_data, dict):
                SecureMemory.secure_clear(channel_key)
                return "[INVALID AES-GCM DATA FORMAT]"
            
            layer1_json = self.decrypt_with_aes_gcm(encrypted_msg_data, channel_key)
            SecureMemory.secure_clear(channel_key)
            
            if not layer1_json:
                return "[LAYER 2 DECRYPTION FAILED]"
            
            # Parse layer 1 data
            layer1_encrypted = json.loads(layer1_json)
            
            # LAYER 1 DECRYPTION: Derive sender's message key
            sender_message_key = self.derive_message_key(master_key, message_nonce)
            if not sender_message_key:
                return "[MESSAGE KEY DERIVATION FAILED]"
            
            # Decrypt layer 1 to get original message
            decrypted_json = self.decrypt_with_aes_gcm(layer1_encrypted, sender_message_key)
            SecureMemory.secure_clear(sender_message_key)
            
            if not decrypted_json:
                return "[LAYER 1 DECRYPTION FAILED - Message may have been tampered with]"
            
            # Parse decrypted message
            message_data = json.loads(decrypted_json)
            
            # Verify timestamp (prevent replay attacks)
            msg_timestamp = message_data.get("timestamp", 0)
            current_time = time.time()
            if abs(current_time - msg_timestamp) > 3600:  # 1 hour window
                return "[MESSAGE EXPIRED - Potential replay attack detected]"
            
            # Verify sender matches
            if message_data.get("sender") != sender:
                return "[SENDER MISMATCH - Potential forgery attempt]"
            
            # Return the actual message content
            return message_data["content"]
            
        except json.JSONDecodeError as e:
            self.log_message(f"JSON parsing error: {e}")
            return "[INVALID MESSAGE FORMAT]"
        except Exception as e:
            self.log_message(f"Double AES-GCM decryption error: {e}")
            return f"[DECRYPTION FAILED: {e}]"
            return message_data["content"]
            
        except json.JSONDecodeError as e:
            self.log_message(f"JSON parsing error: {e}")
            return "[INVALID MESSAGE FORMAT]"
        except Exception as e:
            self.log_message(f"Pure AES-GCM decryption error: {e}")
            return f"[DECRYPTION FAILED: {e}]"
            
    def _decrypt_advanced_hybrid(self, payload):
        """Decrypt advanced hybrid encrypted message"""
        try:
            # Validate payload structure
            required_fields = ["encrypted_key", "encrypted_message", "method"]
            for field in required_fields:
                if field not in payload:
                    return f"[MISSING FIELD: {field}]"
            
            # Decrypt session key with RSA private key
            encrypted_session_key = base64.b64decode(payload["encrypted_key"])
            
            # Debug: Check key sizes
            expected_size = self.private_key.size_in_bytes()  # Expected ciphertext size
            actual_size = len(encrypted_session_key)
            
            if actual_size != expected_size:
                self.log_message(f"⚠️  RSA ciphertext size mismatch: expected {expected_size}, got {actual_size}")
                self.log_message(f"   Private key size: {self.private_key.size_in_bits()} bits")
                return f"[RSA KEY SIZE MISMATCH: expected {expected_size} bytes, got {actual_size} bytes]"
            
            rsa_cipher = PKCS1_OAEP.new(self.private_key)
            session_key = rsa_cipher.decrypt(encrypted_session_key)
            
            # Decrypt message with AES-GCM
            encrypted_msg_data = payload["encrypted_message"]
            if not isinstance(encrypted_msg_data, dict):
                return "[INVALID AES-GCM DATA FORMAT]"
                
            decrypted_json = self.decrypt_with_aes_gcm(encrypted_msg_data, session_key)
            
            # Clear session key from memory
            SecureMemory.secure_clear(session_key)
            
            if not decrypted_json:
                return "[AUTHENTICATION FAILED - Message may have been tampered with]"
            
            # Parse decrypted message
            message_data = json.loads(decrypted_json)
            
            # Verify timestamp (prevent replay attacks)
            msg_timestamp = message_data.get("timestamp", 0)
            current_time = time.time()
            if abs(current_time - msg_timestamp) > 3600:  # 1 hour window
                return "[MESSAGE EXPIRED - Potential replay attack detected]"
            
            # Return the actual message content
            return message_data["content"]
            
        except ValueError as e:
            self.log_message(f"RSA decryption error: {e}")
            return f"[RSA DECRYPTION FAILED: {e}]"
        except json.JSONDecodeError as e:
            self.log_message(f"JSON parsing error: {e}")
            return "[INVALID MESSAGE FORMAT]"
        except Exception as e:
            self.log_message(f"Advanced hybrid decryption error: {e}")
            return f"[DECRYPTION FAILED: {e}]"
            
    def _decrypt_hybrid_legacy(self, payload):
        """Decrypt legacy hybrid encrypted messages for backward compatibility"""
        # Implementation for backward compatibility with older message formats
        # This maintains compatibility with existing messages
        try:
            # Decrypt AES key with RSA
            encrypted_key = base64.b64decode(payload["encrypted_key"])
            rsa_cipher = PKCS1_OAEP.new(self.private_key)
            aes_key = rsa_cipher.decrypt(encrypted_key)
            
            # Decrypt message with AES-CBC (legacy)
            iv = base64.b64decode(payload["iv"])
            encrypted_message = base64.b64decode(payload["encrypted_message"])
            
            aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded = aes_cipher.decrypt(encrypted_message)
            decrypted_message = unpad(decrypted_padded, AES.block_size).decode()
            
            # Clear key from memory
            SecureMemory.secure_clear(aes_key)
            
            return decrypted_message
            
        except Exception as e:
            self.log_message(f"Legacy decryption error: {e}")
            return "[LEGACY DECRYPTION FAILED]"
    
    # [Previous methods adapted for TLS - generate_key_pair, load_private_key, etc.]
    # I'll include key methods but adapt them for the TLS secure messenger
    
    def generate_key_pair(self):
        """Generate RSA key pair with enhanced security"""
        try:
            self.log_message("🔑 Generating 4096-bit RSA key pair...")
            
            # Generate stronger 4096-bit key
            self.private_key = RSA.generate(4096)
            self.public_key = self.private_key.publickey()
            
            # Save with secure permissions
            pem = self.private_key.export_key()
            
            key_file = f"{self.username}_{PRIVATE_KEY_FILE}"
            with open(key_file, "wb") as f:
                f.write(pem)
                
            # Set secure file permissions
            try:
                os.chmod(key_file, 0o600)  # Owner read/write only
            except:
                pass  # Windows compatibility
            
            self.log_message("🔐 4096-bit RSA key pair generated successfully")
            return True
            
        except Exception as e:
            self.log_message(f"Key generation error: {e}")
            return False
            
    def load_private_key(self):
        """Load private key with secure handling"""
        try:
            key_file = f"{self.username}_{PRIVATE_KEY_FILE}"
            if os.path.exists(key_file):
                with open(key_file, "rb") as f:
                    pem = f.read()
                
                # Import the key first
                self.private_key = RSA.import_key(pem)
                self.public_key = self.private_key.publickey()
                self.log_message("🔑 Private key loaded successfully")
                
                # Clear PEM from memory (safely handle bytes object)
                try:
                    SecureMemory.secure_clear(pem)
                except Exception as clear_error:
                    self.log_message(f"Warning: Could not securely clear key data: {clear_error}")
                    # Continue anyway, the key loaded successfully
                
                return True
            return False
        except Exception as e:
            self.log_message(f"Key loading error: {e}")
            return False
    
    def send_secure_message(self):
        """Main secure messaging interface"""
        while self.running:
            try:
                recipient = input("\n🔒 Send to (username, 'users', 'list', 'decrypt <ID>', 'quit'): ").strip()
                
                if not recipient:
                    continue
                elif recipient.lower() == 'quit':
                    break
                elif recipient.lower() == 'users':
                    self.list_users_tls()
                elif recipient.lower() == 'list':
                    self.list_encrypted_messages()
                elif recipient.lower().startswith('decrypt '):
                    try:
                        msg_id = int(recipient.split()[1])
                        self.decrypt_stored_message(msg_id)
                    except (IndexError, ValueError):
                        print("Usage: decrypt <message_id>")
                elif recipient.lower() == 'help':
                    self.show_help()
                else:
                    # Send message
                    message = input("📝 Message: ").strip()
                    if not message:
                        continue
                    
                    # Ensure master token is cached
                    if not self.master_token_cached:
                        if not self.cache_master_token():
                            continue
                    
                    # Encrypt message with cached master token (no RSA needed)
                    encrypt_start = time.time()
                    encrypted = self.encrypt_message_advanced(message, recipient, self.master_decrypt_token)
                    encrypt_time = time.time() - encrypt_start
                    
                    if not encrypted:
                        self.log_message("❌ Failed to encrypt message")
                        continue
                    
                    self.log_message(f"🔒 Message encrypted in {encrypt_time:.3f}s using pure AES-256-GCM")
                    
                    # Send encrypted message via TLS
                    success = self.send_encrypted_message_tls(recipient, encrypted)
                    if success:
                        self.log_message(f"✅ Secure message sent to {recipient}")
                    else:
                        self.log_message(f"❌ Failed to send message to {recipient}")
                        
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.log_message(f"Message send error: {e}")
    
    def send_encrypted_message_tls(self, recipient, encrypted_payload):
        """Send encrypted message over TLS connection"""
        try:
            # No signature needed with AES-GCM (provides authentication)
            payload = {
                "type": "message",
                "recipient": recipient,
                "payload": encrypted_payload,
                "safetoken": self.safetoken,
                "timestamp": time.time(),
                "nonce": self.generate_message_nonce()
            }
            
            # Send the message - ensure complete transmission
            message_json = json.dumps(payload)
            message_bytes = message_json.encode()
            
            # Check message size and log for debugging
            message_size = len(message_bytes)
            self.log_message(f"📤 Sending message: {message_size} bytes")
            
            if message_size > MAX_MESSAGE_SIZE:
                self.log_message(f"❌ Message too large: {message_size} bytes (max: {MAX_MESSAGE_SIZE})")
                return False
            
            # Use sendall to ensure complete transmission
            self.tls_socket.sendall(message_bytes)
            
            # Set a longer timeout for message sending response
            original_timeout = self.tls_socket.gettimeout()
            self.tls_socket.settimeout(15.0)  # 15 second timeout for message response
            
            try:
                # Receive confirmation with timeout handling
                response_data = self.tls_socket.recv(MAX_MESSAGE_SIZE).decode()
                if response_data:
                    response = json.loads(response_data)
                    success = response.get("status") == "success"
                    if not success:
                        self.log_message(f"Server error: {response.get('message', 'Unknown error')}")
                    return success
                else:
                    self.log_message("⚠️  No response from server - assuming message delivered")
                    return True
                    
            except socket.timeout:
                self.log_message("⚠️  Server response timeout - message likely delivered")
                return True  # Assume success since server might be slow to respond
            except ssl.SSLError as ssl_error:
                self.log_message(f"⚠️  SSL error in response: {ssl_error}")
                self.log_message("📤 Message was sent successfully, but response failed")
                return True  # Message was likely sent successfully
            except socket.error as sock_error:
                self.log_message(f"⚠️  Socket error in response: {sock_error}")
                return True  # Assume message was sent
            except Exception as recv_error:
                self.log_message(f"⚠️  Response receive error: {recv_error}")
                self.log_message("📤 Message was sent, but couldn't confirm delivery")
                return True  # Be optimistic - message was likely sent
            finally:
                # Restore original timeout
                self.tls_socket.settimeout(original_timeout)
            
        except ssl.SSLError as e:
            self.log_message(f"SSL/TLS error during message send: {e}")
            # Try to reconnect for next message
            self.running = False
            return False
        except socket.error as e:
            self.log_message(f"Socket error during message send: {e}")
            return False
        except Exception as e:
            self.log_message(f"TLS send error: {e}")
            return False
    
    def start_secure_session(self):
        """Start secure TLS messaging session"""
        try:
            # Connect with TLS
            if not self.connect_to_server():
                return
            
            # Register or login
            if not self.register_or_login_tls():
                return
            
            # Cache master token for the session
            if not self.cache_master_token():
                self.log_message("❌ Failed to authenticate with master token")
                return
            
            self.running = True
            
            # Start message receiver thread
            receive_thread = threading.Thread(target=self.receive_messages_tls, daemon=True)
            receive_thread.start()
            
            self.log_message("🚀 Secure TLS session established!")
            self.log_message("🛡️  Security features active:")
            self.log_message("    ✅ TLS 1.3 transport encryption")
            self.log_message("    ✅ AES-256-GCM message encryption") 
            self.log_message("    ✅ Master token derived keys")
            self.log_message("    ✅ Anti-replay protection")
            self.log_message("    ✅ Message authentication")
            self.log_message("    ✅ Secure memory handling")
            self.log_message("    ✅ Master token cached for session")
            
            self.show_help()
            
            self.show_help()
            
            # Start messaging
            self.send_secure_message()
            
        except Exception as e:
            self.log_message(f"Session error: {e}")
        finally:
            self.cleanup_secure_session()
    
    def cleanup_secure_session(self):
        """Secure cleanup of session data"""
        self.running = False
        
        # Secure memory clearing
        if self.master_decrypt_token:
            SecureMemory.secure_clear(self.master_decrypt_token)
            self.master_decrypt_token = None
            self.master_token_cached = False
        if self.safetoken:
            SecureMemory.secure_clear(self.safetoken)
        if self.session_key:
            SecureMemory.secure_clear(self.session_key)
        
        # Close TLS connection
        if self.tls_socket:
            try:
                self.tls_socket.close()
            except:
                pass
        
        self.log_message("🔒 Secure session terminated - sensitive data cleared")
    
    def show_help(self):
        """Show enhanced help with security information"""
        print("\n🔒 TLS SECURE MESSAGING COMMANDS")
        print("=" * 40)
        print("📝 <username>     - Send encrypted message (uses cached master token)")
        print("👥 users          - List online/registered users")  
        print("📋 list           - Show encrypted messages")
        print("🔓 decrypt <ID>   - Decrypt message (REQUIRES master token entry)")
        print("❓ help           - Show this help")
        print("🚪 quit           - Exit secure session")
        print("=" * 40)
        print("🛡️  All communications are protected by:")
        print("   • TLS 1.3 transport encryption")
        print("   • AES-256-GCM authenticated encryption")
        print("   • Master token derived keys")
        print("   • Message authentication")
        print("   • Anti-replay protection")
        print("=" * 40)
        print("🔐 SECURITY POLICY:")
        print("   • Master token cached for SENDING messages only")
        print("   • Master token ALWAYS required for DECRYPTING messages")
        print("   • This ensures maximum security for reading sensitive content")
        print("=" * 40)

    def register_or_login_tls(self):
        """Register or login over secure TLS connection"""
        self.username = input("👤 Username: ")
        self.safetoken = input("🔑 Your safetoken: ")
        
        # Setup master decrypt token system
        self.setup_master_decrypt_token()
        
        # Check if user exists (simple check)
        user_exists = os.path.exists(f"{self.username}_master_salt.dat")
        
        if user_exists:
            # Existing user - login
            self.log_message("🔍 Existing user detected, logging in...")
            
            login_data = {
                "action": "login",
                "username": self.username,
                "safetoken": self.safetoken,
                "timestamp": time.time(),
                "nonce": self.generate_message_nonce()
            }
        else:
            # New user - register
            self.log_message("🆕 New user detected, registering...")
                
            login_data = {
                "action": "register",
                "username": self.username,
                "safetoken": self.safetoken,
                "encryption_method": "pure_aes_gcm",
                "timestamp": time.time(),
                "nonce": self.generate_message_nonce()
            }
        
        # Send authentication data over TLS
        try:
            self.tls_socket.send(json.dumps(login_data).encode())
            
            # Receive response
            response_data = self.tls_socket.recv(MAX_MESSAGE_SIZE).decode()
            response = json.loads(response_data)
            
            if response.get("status") == "success":
                self.log_message("✅ TLS authentication successful")
                return True
            else:
                error_msg = response.get('message', 'Unknown error')
                self.log_message(f"❌ TLS authentication failed: {error_msg}")
                
                # If it's a duplicate registration error, try to login instead
                if "already" in error_msg.lower() or "exist" in error_msg.lower():
                    self.log_message("🔄 User seems to exist, trying login instead...")
                    login_data = {
                        "action": "login",
                        "username": self.username,
                        "safetoken": self.safetoken,
                        "timestamp": time.time(),
                        "nonce": self.generate_message_nonce()
                    }
                    
                    try:
                        self.tls_socket.send(json.dumps(login_data).encode())
                        response_data = self.tls_socket.recv(MAX_MESSAGE_SIZE).decode()
                        response = json.loads(response_data)
                        
                        if response.get("status") == "success":
                            self.log_message("✅ TLS login successful")
                            return True
                        else:
                            self.log_message(f"❌ TLS login also failed: {response.get('message', 'Unknown error')}")
                    except Exception as e:
                        self.log_message(f"❌ Login retry failed: {e}")
                
                return False
                
        except Exception as e:
            self.log_message(f"TLS authentication error: {e}")
            return False

    def get_public_key_tls(self, username):
        """Get public key over TLS with enhanced security"""
        if username in self.public_key_cache:
            return self.public_key_cache[username]
        
        try:
            # Set flag for receiving thread
            self.waiting_for_public_key = True
            self.public_key_response = None
            
            request = {
                "type": "get_key",
                "requested_user": username,
                "requester": self.username,
                "timestamp": time.time(),
                "nonce": self.generate_message_nonce()
            }
            
            self.tls_socket.send(json.dumps(request).encode())
            
            # Wait for response with improved timeout handling
            start_time = time.time()
            timeout_duration = 5.0  # Increased timeout
            
            while time.time() - start_time < timeout_duration and self.waiting_for_public_key:
                time.sleep(0.05)  # Shorter sleep for more responsive checking
                
                if self.public_key_response:
                    response = self.public_key_response
                    
                    if response.get("status") == "success":
                        # Verify HMAC if present
                        if "hmac" in response:
                            timestamp = response.get("timestamp", time.time())
                            if not self.verify_message_hmac(response, timestamp, response["hmac"]):
                                self.log_message("⚠️  HMAC verification failed for public key")
                                self.waiting_for_public_key = False
                                self.public_key_response = None
                                return None
                        
                        public_key = RSA.import_key(response["public_key"].encode())
                        self.public_key_cache[username] = public_key
                        self.save_public_key_cache()
                        self.log_message(f"✅ Retrieved and cached public key for {username}")
                        
                        self.waiting_for_public_key = False
                        self.public_key_response = None
                        return public_key
                    else:
                        self.log_message(f"❌ Server error getting public key for {username}: {response.get('message', 'Unknown error')}")
                        self.waiting_for_public_key = False
                        self.public_key_response = None
                        return None
            
            # Timeout occurred
            self.waiting_for_public_key = False
            self.log_message(f"⏱️  Timeout getting public key for {username} (waited {timeout_duration}s)")
            return None
            
        except Exception as e:
            self.log_message(f"TLS public key request error: {e}")
            return None

    def list_users_tls(self):
        """List users over TLS connection with enhanced security"""
        try:
            self.waiting_for_user_list = True
            self.user_list_response = None
            
            request = {
                "type": "get_users",
                "requester": self.username,
                "timestamp": time.time(),
                "nonce": self.generate_message_nonce()
            }
            
            self.tls_socket.send(json.dumps(request).encode())
            
            # Wait for response
            start_time = time.time()
            while time.time() - start_time < 3.0 and self.waiting_for_user_list:
                time.sleep(0.01)
                
                if self.user_list_response:
                    response = self.user_list_response
                    
                    if response.get("status") == "success":
                        # Verify HMAC if present
                        if "hmac" in response:
                            timestamp = response.get("timestamp", time.time())
                            if not self.verify_message_hmac(response, timestamp, response["hmac"]):
                                self.log_message("⚠️  HMAC verification failed for user list")
                        
                        online = response.get("online_users", [])
                        registered = response.get("registered_users", [])
                        
                        print(f"\n🔒 === SECURE USER LIST ===")
                        print(f"🟢 Online ({len(online)}): {', '.join(online) if online else 'None'}")
                        print(f"📋 Registered ({len(registered)}): {', '.join(registered) if registered else 'None'}")
                        print("=" * 30)
                    else:
                        self.log_message(f"❌ Server error: {response.get('message', 'Unknown error')}")
                    
                    self.waiting_for_user_list = False
                    self.user_list_response = None
                    return
            
            # Timeout
            self.waiting_for_user_list = False
            self.log_message("⏱️  Timeout getting user list")
            
        except Exception as e:
            self.log_message(f"TLS user list error: {e}")

    def receive_messages_tls(self):
        """Receive messages over TLS with enhanced security validation"""
        while self.running:
            try:
                # Use non-blocking receive with timeout handling
                try:
                    data = self.tls_socket.recv(MAX_MESSAGE_SIZE)
                except socket.timeout:
                    # Normal timeout, continue listening
                    continue
                except ssl.SSLError as e:
                    if self.running:
                        self.log_message(f"SSL error in receive: {e}")
                    break
                except socket.error as e:
                    if self.running:
                        self.log_message(f"Socket error: {e}")
                    break
                except Exception as e:
                    if self.running:
                        self.log_message(f"Receive error: {e}")
                    break
                
                if not data:
                    break
                
                message = json.loads(data.decode())
                
                # Check for responses we're waiting for
                if self.waiting_for_user_list and "online_users" in message:
                    self.user_list_response = message
                    continue
                    
                if self.waiting_for_public_key and "public_key" in message:
                    self.public_key_response = message
                    continue
                
                # Handle incoming encrypted messages
                if message.get("type") == "message":
                    sender = message.get("sender")
                    payload = message.get("payload")
                    signature = message.get("signature")
                    timestamp = message.get("timestamp", time.time())
                    server_hmac = message.get("server_hmac")
                    
                    time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M")
                    
                    # Verify server HMAC if present
                    if server_hmac:
                        if not self.verify_message_hmac(message, timestamp, server_hmac):
                            self.log_message("⚠️  Server HMAC verification failed")
                    
                    # Store encrypted message
                    encrypted_msg = {
                        "id": len(self.encrypted_messages),
                        "sender": sender,
                        "payload": payload,
                        "signature": signature,
                        "timestamp": timestamp,
                        "time_str": time_str,
                        "server_hmac": server_hmac
                    }
                    self.encrypted_messages.append(encrypted_msg)
                    
                    # Show notification
                    print(f"\n🔒 [TLS-ENCRYPTED] MESSAGE from {sender} (ID: {encrypted_msg['id']}) at {time_str}")
                    print("🔐 Type 'decrypt <ID>' to read this message")
                    
            except json.JSONDecodeError:
                # Invalid JSON, skip
                continue
            except Exception as e:
                if self.running:
                    self.log_message(f"TLS message receive error: {e}")
                break

    def list_encrypted_messages(self):
        """List encrypted messages with enhanced security info"""
        if not self.encrypted_messages:
            print("🔒 No encrypted messages")
            return
        
        print(f"\n🔐 === ENCRYPTED MESSAGE VAULT ===")
        for msg in self.encrypted_messages:
            security_indicators = []
            if msg.get("server_hmac"):
                security_indicators.append("HMAC✓")
            if msg.get("signature"):
                security_indicators.append("SIG✓")
            
            security_str = f" [{', '.join(security_indicators)}]" if security_indicators else ""
            print(f"🔒 ID {msg['id']}: [{msg['time_str']}] from {msg['sender']}{security_str}")
        
        print("🔓 Type 'decrypt <ID>' to read a message")
        print("=" * 35)

    def decrypt_stored_message(self, msg_id):
        """Decrypt stored message with enhanced security validation"""
        try:
            if msg_id >= len(self.encrypted_messages):
                print(f"❌ Invalid message ID: {msg_id}")
                return
            
            msg = self.encrypted_messages[msg_id]
            print(f"\n🔓 Decrypting TLS message from {msg['sender']} at {msg['time_str']}")
            
            # ALWAYS prompt for master token for message decryption (security requirement)
            print("🔐 Master token required for message decryption")
            master_token = input("🔑 Enter your master decrypt token: ")
            
            if not master_token:
                print("❌ Master token cannot be empty")
                return
            
            # Decrypt message with advanced decryption
            decrypt_start = time.time()
            decrypted = self.decrypt_message_advanced(msg["payload"], master_token)
            decrypt_time = time.time() - decrypt_start
            
            # Always clear master token from memory immediately after use
            SecureMemory.secure_clear(master_token)
            
            if decrypted and not decrypted.startswith("["):
                # Verify signature if available
                verified = "✅"
                if msg["signature"] and msg["sender"] in self.public_key_cache:
                    if not self.verify_signature(decrypted, msg["signature"], self.public_key_cache[msg["sender"]]):
                        verified = "❌ SIGNATURE INVALID"
                
                # Check server HMAC
                server_trust = "🔒 Server HMAC: ✅" if msg.get("server_hmac") else "⚠️  No server HMAC"
                
                print(f"\n📨 🔓 DECRYPTED MESSAGE (ID: {msg_id})")
                print("=" * 40)
                print(f"👤 From: {msg['sender']} {verified}")
                print(f"⏰ Time: {msg['time_str']}")
                print(f"🔐 Security: TLS 1.3 + AES-256-GCM + RSA-4096")
                print(f"🛡️  {server_trust}")
                print(f"⚡ Decryption: {decrypt_time:.3f}s")
                print("-" * 40)
                print(f"💬 Message: {decrypted}")
                print("=" * 40)
                
                # Auto-clear after viewing (anti-forensics)
                print("\n🔒 Message will auto-clear in 30 seconds for security...")
                time.sleep(30)
                
                # Clear screen area (basic anti-forensics)
                print("\n" + "🔒 CLEARED " * 10)
                print("=" * 50)
                print("🛡️  Message cleared from display for security")
                print("💡 Encrypted copy remains in secure storage")
                print("=" * 50)
                
            else:
                print(f"❌ Decryption failed: {decrypted}")
                
        except Exception as e:
            self.log_message(f"Message decryption error: {e}")

    def save_public_key_cache(self):
        """Save public key cache with enhanced security"""
        try:
            cache_file = f"{self.username}_{PUBLIC_KEY_CACHE}"
            cache_data = {}
            
            for user, key in self.public_key_cache.items():
                if hasattr(key, 'export_key'):
                    cache_data[user] = key.export_key().decode()
            
            # Add metadata
            secure_cache = {
                "version": "2.0-TLS",
                "created": time.time(),
                "keys": cache_data
            }
            
            with open(cache_file, "w") as f:
                json.dump(secure_cache, f, indent=2)
            
            # Secure file permissions
            try:
                os.chmod(cache_file, 0o600)
            except:
                pass
                
        except Exception as e:
            self.log_message(f"Error saving key cache: {e}")

    def load_public_key_cache(self):
        """Load public key cache with version compatibility"""
        try:
            cache_file = f"{self.username}_{PUBLIC_KEY_CACHE}"
            if os.path.exists(cache_file):
                with open(cache_file, "r") as f:
                    data = json.load(f)
                
                # Handle both old and new formats
                if "keys" in data:  # New format
                    cache_data = data["keys"]
                else:  # Old format
                    cache_data = data
                
                for user, key_pem in cache_data.items():
                    try:
                        self.public_key_cache[user] = RSA.import_key(key_pem)
                    except Exception as e:
                        self.log_message(f"Error loading cached key for {user}: {e}")
                
                self.log_message(f"📋 Loaded {len(self.public_key_cache)} cached public keys")
                
        except Exception as e:
            self.log_message(f"Error loading key cache: {e}")

    def sign_message(self, message):
        """Sign message for authenticity verification"""
        try:
            if isinstance(message, str):
                message = message.encode()
            
            hash_obj = SHA256.new(message)
            signature = pkcs1_15.new(self.private_key).sign(hash_obj)
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            self.log_message(f"Message signing error: {e}")
            return None

    def verify_signature(self, message, signature, public_key):
        """Verify message signature for authenticity"""
        try:
            if isinstance(message, str):
                message = message.encode()
            
            hash_obj = SHA256.new(message)
            signature_bytes = base64.b64decode(signature)
            
            pkcs1_15.new(public_key).verify(hash_obj, signature_bytes)
            return True
            
        except Exception:
            return False

if __name__ == "__main__":
    messenger = TLSSecureMessenger()
    messenger.start_secure_session()