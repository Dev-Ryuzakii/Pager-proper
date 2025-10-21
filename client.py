import socket
import json
import os
import threading
import time
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

# Server configuration (can be changed to domain name or public IP)
import os
SERVER_IP = os.environ.get("PAGER_SERVER_IP") or input("Server address (press Enter for localhost): ").strip() or "127.0.0.1"
PORT = 5050

# File paths for key storage
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_CACHE = "public_keys_cache.json"

class SecureMessenger:
    def __init__(self):
        self.username = None
        self.safetoken = None
        self.master_decrypt_token = None  # New: master token for message decryption
        self.master_salt = None  # New: salt for PBKDF2 key derivation
        self.private_key = None
        self.public_key = None
        self.sock = None
        self.public_key_cache = {}
        self.running = False
        self.waiting_for_user_list = False  # Flag for user list requests
        self.user_list_response = None  # Store user list response
        self.waiting_for_public_key = False  # Flag for public key requests
        self.public_key_response = None  # Store public key response
        self.encrypted_messages = []  # New: store encrypted messages until decrypted
        
    def log_message(self, message):
        """Log messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
        
    def generate_key_pair(self):
        """Generate RSA key pair"""
        self.log_message("Generating RSA key pair...")
        key = RSA.generate(2048)
        self.private_key = key
        self.public_key = key.publickey()
        self.log_message("Key pair generated successfully")
        
    def save_private_key(self):
        """Save private key to file"""
        try:
            pem_private = self.private_key.export_key()
            with open(f"{self.username}_{PRIVATE_KEY_FILE}", "wb") as f:
                f.write(pem_private)
            self.log_message("Private key saved")
        except Exception as e:
            self.log_message(f"Error saving private key: {e}")
            
    def load_private_key(self):
        """Load private key from file"""
        try:
            filename = f"{self.username}_{PRIVATE_KEY_FILE}"
            if os.path.exists(filename):
                with open(filename, "rb") as f:
                    self.private_key = RSA.import_key(f.read())
                    self.public_key = self.private_key.publickey()
                self.log_message("Private key loaded")
                return True
        except Exception as e:
            self.log_message(f"Error loading private key: {e}")
        return False
        
    def save_public_key_cache(self):
        """Save cached public keys"""
        try:
            with open(f"{self.username}_{PUBLIC_KEY_CACHE}", "w") as f:
                # Convert RSA keys to PEM strings for JSON storage
                cache_data = {}
                for user, key in self.public_key_cache.items():
                    if hasattr(key, 'export_key'):
                        cache_data[user] = key.export_key().decode()
                json.dump(cache_data, f, indent=2)
        except Exception as e:
            self.log_message(f"Error saving public key cache: {e}")
            
    def load_public_key_cache(self):
        """Load cached public keys"""
        try:
            cache_file = f"{self.username}_{PUBLIC_KEY_CACHE}"
            if os.path.exists(cache_file):
                with open(cache_file, "r") as f:
                    cache_data = json.load(f)
                    # Convert PEM strings back to RSA keys
                    for user, key_pem in cache_data.items():
                        try:
                            self.public_key_cache[user] = RSA.import_key(key_pem)
                        except Exception as e:
                            self.log_message(f"Error loading cached key for {user}: {e}")
                self.log_message(f"Loaded {len(self.public_key_cache)} cached public keys")
        except Exception as e:
            self.log_message(f"Error loading public key cache: {e}")
            
    def setup_master_decrypt_token(self):
        """Setup or load master decrypt token for double encryption"""
        salt_file = f"{self.username}_master_salt.dat"
        
        if os.path.exists(salt_file):
            # Load existing salt
            with open(salt_file, "rb") as f:
                self.master_salt = f.read()
            self.log_message("Existing master token configuration found")
        else:
            # Generate new salt for new user
            self.master_salt = get_random_bytes(32)
            
            # Ask user to create their own master decrypt token
            print("\n🔐 MASTER DECRYPT TOKEN SETUP")
            print("=" * 40)
            print("Create a master password for double-layer encryption.")
            print("You'll need this password to decrypt your messages.")
            print("Choose something secure but memorable!")
            print()
            
            while True:
                master_token = input("Create your master decrypt token: ").strip()
                if len(master_token) < 8:
                    print("❌ Master token must be at least 8 characters long")
                    continue
                    
                confirm_token = input("Confirm your master decrypt token: ").strip()
                if master_token == confirm_token:
                    print(f"✅ Master decrypt token created successfully!")
                    print(f"💡 Remember this password: '{master_token}'")
                    print("=" * 40)
                    break
                else:
                    print("❌ Tokens don't match. Try again.")
            
            # Save salt
            with open(salt_file, "wb") as f:
                f.write(self.master_salt)
            self.log_message("New master token configuration created")
    
    def derive_master_key(self, master_token):
        """Derive encryption key from master token using PBKDF2"""
        try:
            # Use PBKDF2 to derive a strong key from the user's master token
            master_key = PBKDF2(master_token, self.master_salt, 32, count=100000)
            return master_key
        except Exception as e:
            self.log_message(f"Key derivation error: {e}")
            return None
    
    def encrypt_with_master_token(self, message, master_token):
        """Encrypt message with master token (first layer of double encryption)"""
        try:
            master_key = self.derive_master_key(master_token)
            if not master_key:
                return None
                
            # Encrypt with AES using master key
            cipher = AES.new(master_key, AES.MODE_CBC)
            iv = cipher.iv
            encrypted_data = cipher.encrypt(pad(message.encode(), AES.block_size))
            
            # Package with IV
            master_encrypted = {
                "iv": base64.b64encode(iv).decode(),
                "data": base64.b64encode(encrypted_data).decode()
            }
            
            return json.dumps(master_encrypted)
            
        except Exception as e:
            self.log_message(f"Master token encryption error: {e}")
            return None
    
    def decrypt_with_master_token(self, encrypted_data, master_token):
        """Decrypt message with master token (second layer of double decryption)"""
        try:
            master_key = self.derive_master_key(master_token)
            if not master_key:
                return None
                
            # Parse encrypted data
            data = json.loads(encrypted_data)
            iv = base64.b64decode(data["iv"])
            encrypted_bytes = base64.b64decode(data["data"])
            
            # Decrypt with master key
            cipher = AES.new(master_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_bytes)
            decrypted = unpad(decrypted_padded, AES.block_size)
            
            return decrypted.decode()
            
        except Exception as e:
            self.log_message(f"Master token decryption error: {e}")
            return None
        """Load cached public keys"""
        try:
            filename = f"{self.username}_{PUBLIC_KEY_CACHE}"
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    cache_data = json.load(f)
                # Convert PEM strings back to RSA keys
                for user, pem_key in cache_data.items():
                    self.public_key_cache[user] = RSA.import_key(pem_key.encode())
                self.log_message(f"Loaded {len(self.public_key_cache)} cached public keys")
        except Exception as e:
            self.log_message(f"Error loading public key cache: {e}")
            
    def encrypt_message(self, message, recipient_public_key, sender_master_token=None):
        """Hybrid encryption: AES + RSA (master token for sender validation only)"""
        try:
            # Validate sender's master token (but don't encrypt with it)
            if sender_master_token:
                master_key = self.derive_master_key(sender_master_token)
                if not master_key:
                    self.log_message("Invalid sender master token")
                    return None
            
            # Use hybrid AES+RSA encryption (recipient decrypts with their private key)
            # Generate random AES key (32 bytes = 256-bit)
            aes_key = get_random_bytes(32)
            
            # Encrypt message with AES (fast)
            aes_cipher = AES.new(aes_key, AES.MODE_CBC)
            iv = aes_cipher.iv
            encrypted_message = aes_cipher.encrypt(pad(message.encode(), AES.block_size))
            
            # Encrypt AES key with RSA (only small key, not full message)
            rsa_cipher = PKCS1_OAEP.new(recipient_public_key)
            encrypted_key = rsa_cipher.encrypt(aes_key)
            
            # Package everything together
            hybrid_payload = {
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "iv": base64.b64encode(iv).decode(),
                "encrypted_message": base64.b64encode(encrypted_message).decode(),
                "method": "hybrid_rsa_aes",
                "sender_validated": bool(sender_master_token)
            }
            
            return json.dumps(hybrid_payload)
            
        except Exception as e:
            self.log_message(f"Double-layer encryption error: {e}")
            return None
            
    def decrypt_message(self, encrypted_payload, recipient_master_token=None):
        """Decrypt message using recipient's private key (master token for local validation)"""
        try:
            # Validate recipient's master token first (for local security)
            if recipient_master_token:
                master_key = self.derive_master_key(recipient_master_token)
                if not master_key:
                    return "[INVALID MASTER TOKEN]"
            else:
                return "[MASTER TOKEN REQUIRED]"
            
            # Parse the payload
            if isinstance(encrypted_payload, str):
                # Try to parse as JSON (hybrid format)
                try:
                    payload = json.loads(encrypted_payload)
                    if payload.get("method") in ["hybrid_rsa_aes", "double_layer_hybrid", "hybrid_aes_rsa"]:
                        return self._decrypt_hybrid(payload)
                except json.JSONDecodeError:
                    pass
                
                # Fallback to old RSA-only format
                return self._decrypt_rsa_only(encrypted_payload)
            
            return "[INVALID PAYLOAD FORMAT]"
            
        except Exception as e:
            self.log_message(f"Decryption error: {e}")
            return "[DECRYPTION FAILED]"
    
    def _decrypt_double_layer(self, payload, recipient_master_token=None):
        """Decrypt double-layer encrypted message"""
        try:
            # First layer: Decrypt RSA+AES (same as before)
            # Decrypt the AES key with RSA
            encrypted_key = base64.b64decode(payload["encrypted_key"])
            rsa_cipher = PKCS1_OAEP.new(self.private_key)
            aes_key = rsa_cipher.decrypt(encrypted_key)
            
            # Decrypt the message with AES
            iv = base64.b64decode(payload["iv"])
            encrypted_message = base64.b64decode(payload["encrypted_message"])
            
            aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded = aes_cipher.decrypt(encrypted_message)
            layer1_decrypted = unpad(decrypted_padded, AES.block_size).decode()
            
            # Second layer: Decrypt with master token (if present)
            if payload.get("has_master_layer", False):
                if not recipient_master_token:
                    return "[MASTER TOKEN REQUIRED]"
                
                final_message = self.decrypt_with_master_token(layer1_decrypted, recipient_master_token)
                if not final_message:
                    return "[INVALID MASTER TOKEN]"
                return final_message
            else:
                return layer1_decrypted
            
        except Exception as e:
            self.log_message(f"Double-layer decryption error: {e}")
            return "[DOUBLE LAYER DECRYPTION FAILED]"
            
    def _decrypt_hybrid(self, payload):
        """Decrypt hybrid AES+RSA encrypted message"""
        try:
            # Decrypt the AES key with RSA
            encrypted_key = base64.b64decode(payload["encrypted_key"])
            rsa_cipher = PKCS1_OAEP.new(self.private_key)
            aes_key = rsa_cipher.decrypt(encrypted_key)
            
            # Decrypt the message with AES
            iv = base64.b64decode(payload["iv"])
            encrypted_message = base64.b64decode(payload["encrypted_message"])
            
            aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded = aes_cipher.decrypt(encrypted_message)
            decrypted = unpad(decrypted_padded, AES.block_size)
            
            return decrypted.decode()
            
        except Exception as e:
            self.log_message(f"Hybrid decryption error: {e}")
            return "[HYBRID DECRYPTION FAILED]"
            
    def _decrypt_rsa_only(self, encrypted_message):
        """Fallback: Decrypt old RSA-only format"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_message)
            cipher = PKCS1_OAEP.new(self.private_key)
            decrypted = cipher.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            return "[RSA DECRYPTION FAILED]"
            
    def sign_message(self, message):
        """Sign message with private key for authenticity"""
        try:
            message_hash = SHA256.new(message.encode())
            signature = pkcs1_15.new(self.private_key).sign(message_hash)
            return base64.b64encode(signature).decode()
        except Exception as e:
            self.log_message(f"Signing error: {e}")
            return None
            
    def verify_signature(self, message, signature, sender_public_key):
        """Verify message signature"""
        try:
            message_hash = SHA256.new(message.encode())
            signature_bytes = base64.b64decode(signature)
            pkcs1_15.new(sender_public_key).verify(message_hash, signature_bytes)
            return True
        except:
            return False
            
    def get_public_key(self, username):
        """Get public key for a user (from cache or server)"""
        if username in self.public_key_cache:
            return self.public_key_cache[username]
            
        # Request from server using fast cooperative approach
        try:
            # Set flag for receiving thread
            self.waiting_for_public_key = True
            self.public_key_response = None
            
            request = {
                "type": "get_key",
                "requested_user": username,
                "requester": self.username
            }
            self.sock.send(json.dumps(request).encode())
            
            # Wait for receiving thread to get the response
            import time
            start_time = time.time()
            max_wait = 2.0  # 2 second timeout
            
            while time.time() - start_time < max_wait and self.waiting_for_public_key:
                time.sleep(0.01)  # Small sleep to avoid busy waiting
                
                if self.public_key_response:
                    response = self.public_key_response
                    
                    if response["status"] == "success":
                        public_key = RSA.import_key(response["public_key"].encode())
                        self.public_key_cache[username] = public_key
                        self.save_public_key_cache()
                        self.log_message(f"✓ Got public key for {username}")
                        
                        # Reset flags
                        self.waiting_for_public_key = False
                        self.public_key_response = None
                        return public_key
                    else:
                        self.log_message(f"Failed to get public key: {response['message']}")
                        self.waiting_for_public_key = False
                        self.public_key_response = None
                        return None
            
            # Timeout occurred
            self.waiting_for_public_key = False
            self.log_message(f"Timeout waiting for {username}'s public key")
            return None
                
        except Exception as e:
            self.log_message(f"Error requesting public key: {e}")
            return None
            
    def register_or_login(self):
        """Register new user or login existing user"""
        self.username = input("Username: ")
        self.safetoken = input("Your safetoken: ")
        
        # Setup master decrypt token system
        self.setup_master_decrypt_token()
        
        # Try to load existing private key
        if self.load_private_key():
            # Existing user - login
            self.log_message("Found existing keys, logging in...")
            self.load_public_key_cache()
            
            login_data = {
                "action": "login",
                "username": self.username,
                "safetoken": self.safetoken
            }
        else:
            # New user - register
            self.log_message("New user detected, registering...")
            self.generate_key_pair()
            self.save_private_key()
            
            login_data = {
                "action": "register",
                "username": self.username,
                "safetoken": self.safetoken,
                "public_key": self.public_key.export_key().decode()
            }
            
        # Send login/registration data
        self.sock.send(json.dumps(login_data).encode())
        
        # Wait for confirmation
        try:
            response_data = self.sock.recv(4096).decode()
            response = json.loads(response_data)
            
            if response["status"] == "success":
                self.log_message(f"✓ {response['message']}")
                
                # For new users, prompt to create master decrypt token
                if not self.load_private_key() or not os.path.exists(f"{self.username}_master_salt.dat"):
                    self.log_message("Please create your master decrypt token (this will decrypt all your messages)")
                    master_token = input("Create master decrypt token (remember this!): ")
                    # Test the token by deriving a key (this also initializes the system)
                    test_key = self.derive_master_key(master_token)
                    if test_key:
                        self.log_message("✓ Master decrypt token configured")
                    else:
                        self.log_message("✗ Failed to configure master decrypt token")
                        return False
                
                return True
            else:
                self.log_message(f"✗ {response['message']}")
                return False
        except Exception as e:
            self.log_message(f"Login/Registration error: {e}")
            return False
            
    def connect_to_server(self):
        """Connect to the messaging server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_IP, PORT))
            self.log_message(f"Connected to server at {SERVER_IP}:{PORT}")
            return True
        except Exception as e:
            self.log_message(f"Connection failed: {e}")
            return False
            
    def send_message(self):
        """Send encrypted message to recipient"""
        while self.running:
            try:
                recipient = input("\nSend to (username, 'users', 'list', 'decrypt <ID>', 'quit'): ").strip()
                
                if recipient.lower() == 'quit':
                    break
                elif recipient.lower() == 'users':
                    self.list_users()
                    continue
                elif recipient.lower().startswith('decrypt '):
                    # Handle decrypt command
                    try:
                        msg_id = int(recipient.split()[1])
                        self.decrypt_stored_message(msg_id)
                    except (IndexError, ValueError):
                        print("Usage: decrypt <message_id>")
                    continue
                elif recipient.lower() == 'list':
                    # List encrypted messages
                    if not self.encrypted_messages:
                        print("No encrypted messages")
                    else:
                        print("\n=== ENCRYPTED MESSAGES ===")
                        for msg in self.encrypted_messages:
                            print(f"ID {msg['id']}: [{msg['time_str']}] from {msg['sender']}")
                        print("Type 'decrypt <ID>' to read a message")
                    continue
                elif not recipient:
                    continue
                    
                message = input("Message: ").strip()
                if not message:
                    continue
                    
                # Get recipient's public key
                recipient_key = self.get_public_key(recipient)
                if not recipient_key:
                    self.log_message(f"Could not get public key for {recipient}")
                    continue
                    
                # Get sender's master token for encryption
                sender_master_token = input("Enter your master decrypt token: ")
                
                # Encrypt message (double-layer: master token + hybrid AES+RSA)
                encrypt_start = time.time()
                encrypted = self.encrypt_message(message, recipient_key, sender_master_token)
                encrypt_time = time.time() - encrypt_start
                
                if not encrypted:
                    self.log_message("Failed to encrypt message")
                    continue
                    
                self.log_message(f"Message encrypted in {encrypt_time:.3f}s using double-layer encryption")
                    
                # Sign message for authenticity (sign original message, not encrypted)
                signature = self.sign_message(message)
                
                # Send message
                payload = {
                    "type": "message",
                    "sender": self.username,
                    "recipient": recipient,
                    "payload": encrypted,
                    "signature": signature,
                    "safetoken": self.safetoken
                }
                
                self.sock.send(json.dumps(payload).encode())
                self.log_message(f"Message sent to {recipient}")
                
            except KeyboardInterrupt:
                break
            except EOFError:
                # Handle EOF (when input is piped or Ctrl+D is pressed)
                self.log_message("Input ended, exiting...")
                break
            except Exception as e:
                self.log_message(f"Error sending message: {e}")
                break
                
    def decrypt_stored_message(self, msg_id):
        """Decrypt a stored encrypted message with master token"""
        try:
            if msg_id >= len(self.encrypted_messages):
                print(f"Invalid message ID: {msg_id}")
                return
                
            msg = self.encrypted_messages[msg_id]
            print(f"\nDecrypting message from {msg['sender']} at {msg['time_str']}")
            
            # Get master token from user
            master_token = input("Enter your master decrypt token: ")
            
            # Decrypt message (double-layer decryption)
            decrypt_start = time.time()
            decrypted = self.decrypt_message(msg["payload"], master_token)
            decrypt_time = time.time() - decrypt_start
            
            if decrypted and not decrypted.startswith("["):
                # Verify signature if available
                verified = "✓"
                if msg["signature"] and msg["sender"] in self.public_key_cache:
                    if not self.verify_signature(decrypted, msg["signature"], self.public_key_cache[msg["sender"]]):
                        verified = "✗ SIGNATURE INVALID"
                
                print(f"\n📨 DECRYPTED MESSAGE (ID: {msg_id})")
                print(f"From: {msg['sender']} {verified}")
                print(f"Time: {msg['time_str']}")
                print(f"Message: {decrypted}")
                print(f"Decryption time: {decrypt_time:.3f}s")
                
                # Auto-clear after 30 seconds (optional)
                print("\n(Message will auto-clear in 30 seconds...)")
                time.sleep(30)
                print("\n" + "="*50)
                print("Message cleared for security")
                print("="*50)
                
            else:
                print(f"❌ Decryption failed: {decrypted}")
                
        except Exception as e:
            print(f"Error decrypting message: {e}")
            
    def list_users(self):
        """Request and display list of users"""
        try:
            # Set a flag for the receiving thread to handle user list response
            self.waiting_for_user_list = True
            self.user_list_response = None
            
            request = {
                "type": "get_users",
                "requester": self.username
            }
            self.sock.send(json.dumps(request).encode())
            
            # Wait for the receiving thread to get the response
            import time
            start_time = time.time()
            max_wait = 3.0  # 3 second timeout
            
            while time.time() - start_time < max_wait and self.waiting_for_user_list:
                time.sleep(0.01)  # Small sleep to avoid busy waiting
                
                if self.user_list_response:
                    response = self.user_list_response
                    if response.get("status") == "success":
                        online = response.get("online_users", [])
                        registered = response.get("registered_users", [])
                        print("\n=== USERS ===")
                        print(f"Online ({len(online)}): {', '.join(online) if online else 'None'}")
                        print(f"Registered ({len(registered)}): {', '.join(registered) if registered else 'None'}")
                        print("=============")
                    else:
                        self.log_message(f"Server error: {response.get('message', 'Unknown error')}")
                    
                    # Reset flags
                    self.waiting_for_user_list = False
                    self.user_list_response = None
                    return
            
            # Timeout occurred
            self.waiting_for_user_list = False
            self.log_message("Timeout waiting for user list response")
                
        except Exception as e:
            self.log_message(f"Error getting user list: {e}")
            
    def handle_received_message(self, message):
        """Handle a single received message"""
        msg_type = message.get("type", "unknown")
        
        if msg_type == "message":
            sender = message.get("sender")
            payload = message.get("payload")
            signature = message.get("signature")
            timestamp = message.get("timestamp", time.time())
            
            time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M")
            
            # Store encrypted message for later decryption
            encrypted_msg = {
                "id": len(self.encrypted_messages),
                "sender": sender,
                "payload": payload,
                "signature": signature,
                "timestamp": timestamp,
                "time_str": time_str
            }
            self.encrypted_messages.append(encrypted_msg)
            
            # Show notification without decrypting
            print(f"\n[{time_str}] 🔒 ENCRYPTED MESSAGE from {sender} (ID: {encrypted_msg['id']})")
            print("Type 'decrypt <ID>' to read this message")
            
    def receive_messages(self):
        """Receive and decrypt messages"""
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                    
                message = json.loads(data.decode())
                msg_type = message.get("type", "unknown")
                
                # Check if this is a user list response we're waiting for
                if self.waiting_for_user_list and "online_users" in message:
                    self.user_list_response = message
                    continue
                    
                # Check if this is a public key response we're waiting for
                if self.waiting_for_public_key and "public_key" in message:
                    self.public_key_response = message
                    continue
                
                if msg_type == "message":
                    sender = message.get("sender")
                    payload = message.get("payload")
                    signature = message.get("signature")
                    timestamp = message.get("timestamp", time.time())
                    
                    time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M")
                    
                    # Store encrypted message for later decryption
                    encrypted_msg = {
                        "id": len(self.encrypted_messages),
                        "sender": sender,
                        "payload": payload,
                        "signature": signature,
                        "timestamp": timestamp,
                        "time_str": time_str
                    }
                    self.encrypted_messages.append(encrypted_msg)
                    
                    # Show encrypted message notification
                    print(f"\n[{time_str}] 🔒 ENCRYPTED MESSAGE from {sender} (ID: {encrypted_msg['id']})")
                    print("Type 'decrypt <ID>' to read this message")
                    
                elif msg_type == "heartbeat_ack":
                    pass  # Ignore heartbeat responses
                    
            except json.JSONDecodeError:
                pass  # Ignore invalid JSON
            except Exception as e:
                if self.running:
                    self.log_message(f"Error receiving message: {e}")
                break
                
    def send_heartbeat(self):
        """Send periodic heartbeat to server"""
        # Temporarily disabled to avoid message collision
        while self.running:
            try:
                time.sleep(120)  # Just sleep, don't send heartbeat for now
            except:
                break
                
    def start(self):
        """Start the messaging client"""
        self.log_message("=== Secure Messenger ===")
        
        if not self.connect_to_server():
            return
            
        if not self.register_or_login():
            return
            
        self.running = True
        
        # Start background threads
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        heartbeat_thread = threading.Thread(target=self.send_heartbeat, daemon=True)
        
        receive_thread.start()
        heartbeat_thread.start()
        
        self.log_message("Ready to send messages!")
        self.log_message("Commands: 'users' = list users, 'list' = show encrypted messages, 'decrypt <ID>' = decrypt message, 'quit' = exit")
        
        # Main message sending loop
        try:
            self.send_message()
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            if self.sock:
                self.sock.close()
            self.log_message("Disconnected from server")

# ===== MAIN =====
if __name__ == "__main__":
    messenger = SecureMessenger()
    messenger.start()

