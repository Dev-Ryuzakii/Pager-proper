import socket
import threading
import json
import time
import os
from datetime import datetime

# ===== CONFIG =====
HOST = "0.0.0.0"       # Listen on all interfaces
PORT = 5050

# Data storage
connected_users = {}      # {username: {"socket": conn, "token": token, "last_seen": timestamp}}
user_public_keys = {}     # {username: {"public_key": pem_string, "registered": timestamp}}
offline_messages = {}     # {username: [list_of_messages]}

def log_message(message):
    """Log server messages with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def save_user_data():
    """Save user public keys to file for persistence"""
    try:
        with open("user_keys.json", "w") as f:
            json.dump(user_public_keys, f, indent=2)
        log_message("User data saved")
    except Exception as e:
        log_message(f"Error saving user data: {e}")

def load_user_data():
    """Load user public keys from file"""
    global user_public_keys
    try:
        if os.path.exists("user_keys.json"):
            with open("user_keys.json", "r") as f:
                user_public_keys = json.load(f)
            log_message(f"Loaded {len(user_public_keys)} user keys")
    except Exception as e:
        log_message(f"Error loading user data: {e}")

def handle_key_registration(conn, data):
    """Handle public key registration"""
    try:
        username = data.get("username")
        public_key = data.get("public_key")
        token = data.get("safetoken")
        
        if not all([username, public_key, token]):
            conn.send(json.dumps({"status": "error", "message": "Missing registration data"}).encode())
            return False
            
        # Register the public key
        user_public_keys[username] = {
            "public_key": public_key,
            "registered": time.time(),
            "token": token
        }
        
        save_user_data()
        conn.send(json.dumps({"status": "success", "message": "Key registered successfully"}).encode())
        log_message(f"Registered public key for {username}")
        return True
        
    except Exception as e:
        log_message(f"Key registration error: {e}")
        conn.send(json.dumps({"status": "error", "message": "Registration failed"}).encode())
        return False

def handle_key_request(conn, data):
    """Handle public key requests"""
    try:
        requested_user = data.get("requested_user")
        requester = data.get("requester")
        
        if requested_user in user_public_keys:
            response = {
                "status": "success",
                "username": requested_user,
                "public_key": user_public_keys[requested_user]["public_key"]
            }
            conn.send(json.dumps(response).encode())
            log_message(f"{requester} requested public key for {requested_user}")
        else:
            conn.send(json.dumps({"status": "error", "message": f"User {requested_user} not found"}).encode())
            
    except Exception as e:
        log_message(f"Key request error: {e}")
        conn.send(json.dumps({"status": "error", "message": "Key request failed"}).encode())

def handle_user_list(conn, data):
    """Handle request for list of registered users"""
    try:
        online_users = list(connected_users.keys())
        registered_users = list(user_public_keys.keys())
        
        response = {
            "status": "success",
            "online_users": online_users,
            "registered_users": registered_users
        }
        log_message(f"Sending user list: online={online_users}, registered={registered_users}")
        conn.send(json.dumps(response).encode())
        
    except Exception as e:
        log_message(f"User list error: {e}")
        conn.send(json.dumps({"status": "error", "message": "Failed to get user list"}).encode())

def store_offline_message(recipient, message_data):
    """Store message for offline users"""
    if recipient not in offline_messages:
        offline_messages[recipient] = []
    
    offline_messages[recipient].append({
        "message": message_data,
        "timestamp": time.time()
    })
    log_message(f"Stored offline message for {recipient}")

def deliver_offline_messages(username, conn):
    """Deliver stored offline messages when user comes online"""
    if username in offline_messages:
        messages = offline_messages[username]
        for msg_data in messages:
            try:
                conn.send(json.dumps(msg_data["message"]).encode())
                time.sleep(0.1)  # Small delay between messages
            except Exception as e:
                log_message(f"Error delivering offline message: {e}")
        
        # Clear delivered messages
        del offline_messages[username]
        log_message(f"Delivered {len(messages)} offline messages to {username}")

def handle_client(conn):
    username = None
    try:
        # Step 1: Receive initial login/registration data
        login_data = conn.recv(4096).decode()
        login = json.loads(login_data)
        
        action = login.get("action", "login")
        username = login.get("username")
        token = login.get("safetoken")

        if action == "register":
            # Handle public key registration
            if handle_key_registration(conn, login):
                username = login["username"]
                # Add user to connected list after successful registration
                connected_users[username] = {
                    "socket": conn, 
                    "token": token, 
                    "last_seen": time.time()
                }
                log_message(f"REGISTERED & CONNECTED: {username}")
                
                # Deliver any offline messages
                deliver_offline_messages(username, conn)
            else:
                return
                
        elif action == "login":
            # Handle regular login
            if username in user_public_keys:
                stored_token = user_public_keys[username].get("token")
                if stored_token == token:
                    connected_users[username] = {
                        "socket": conn, 
                        "token": token, 
                        "last_seen": time.time()
                    }
                    log_message(f"CONNECTED: {username}")
                    
                    # Send success confirmation
                    conn.send(json.dumps({"status": "success", "message": "Login successful"}).encode())
                    
                    # Deliver any offline messages
                    deliver_offline_messages(username, conn)
                else:
                    conn.send(json.dumps({"status": "error", "message": "Invalid token"}).encode())
                    return
            else:
                conn.send(json.dumps({"status": "error", "message": "User not registered"}).encode())
                return

        while True:
            # Receive data from client
            data = conn.recv(4096)
            if not data:
                break

            try:
                message_json = json.loads(data.decode())
                msg_type = message_json.get("type", "message")
                
                if msg_type == "message":
                    # Handle encrypted message
                    sender = message_json["sender"]
                    recipient = message_json["recipient"]
                    payload = message_json["payload"]
                    sender_token = message_json.get("safetoken", "")

                    # Validate sender
                    if sender not in connected_users or connected_users[sender]["token"] != sender_token:
                        conn.send(json.dumps({"status": "error", "message": "Invalid sender token"}).encode())
                        continue

                    message_data = {
                        "type": "message",
                        "sender": sender,
                        "payload": payload,
                        "timestamp": time.time()
                    }

                    # Try to deliver to recipient
                    if recipient in connected_users:
                        try:
                            recipient_sock = connected_users[recipient]["socket"]
                            recipient_sock.send(json.dumps(message_data).encode())
                            conn.send(json.dumps({"status": "success", "message": "Message delivered"}).encode())
                            log_message(f"Message: {sender} -> {recipient}")
                        except Exception as e:
                            log_message(f"Failed to deliver message: {e}")
                            store_offline_message(recipient, message_data)
                            conn.send(json.dumps({"status": "success", "message": "Message stored for offline delivery"}).encode())
                    else:
                        # Store for offline delivery
                        store_offline_message(recipient, message_data)
                        conn.send(json.dumps({"status": "success", "message": "Message stored for offline delivery"}).encode())
                        
                elif msg_type == "get_key":
                    # Handle public key request
                    handle_key_request(conn, message_json)
                    
                elif msg_type == "get_users":
                    # Handle user list request
                    handle_user_list(conn, message_json)
                    
                elif msg_type == "heartbeat":
                    # Handle heartbeat/ping
                    if username in connected_users:
                        connected_users[username]["last_seen"] = time.time()
                    conn.send(json.dumps({"status": "success", "type": "heartbeat_ack"}).encode())

            except json.JSONDecodeError:
                log_message("Received invalid JSON")
            except Exception as e:
                log_message(f"Message handling error: {e}")

    except Exception as e:
        log_message(f"Client handler error: {e}")
    finally:
        # Clean up connection
        if username and username in connected_users:
            log_message(f"DISCONNECTED: {username}")
            del connected_users[username]
        conn.close()

def cleanup_inactive_users():
    """Remove users who haven't been seen for too long"""
    current_time = time.time()
    timeout = 300  # 5 minutes
    
    inactive_users = []
    for username, info in connected_users.items():
        if current_time - info["last_seen"] > timeout:
            inactive_users.append(username)
    
    for username in inactive_users:
        log_message(f"Removing inactive user: {username}")
        connected_users[username]["socket"].close()
        del connected_users[username]

def start_server():
    # Load existing user data
    load_user_data()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(20)  # Increased for more concurrent connections
    
    log_message(f"Server starting on {HOST}:{PORT}")
    log_message(f"Loaded {len(user_public_keys)} registered users")
    log_message("Ready for connections...")

    try:
        while True:
            conn, addr = server_socket.accept()
            log_message(f"New connection from {addr}")
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
            
            # Periodic cleanup of inactive connections
            if len(connected_users) > 0:
                threading.Thread(target=cleanup_inactive_users, daemon=True).start()
                
    except KeyboardInterrupt:
        log_message("Server shutting down...")
        save_user_data()
        server_socket.close()

if __name__ == "__main__":
    start_server()
