import socket
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

SERVER_IP = "10.10.8.37" 
PORT = 5050
SECRET_KEY = b"12345678901234567890123456789012"  # 32 bytes AES key

def encrypt_message(msg):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return json.dumps({"iv": iv, "ct": ct})

def decrypt_message(json_data, safetoken, expected_token):
    if safetoken != expected_token:
        return "[ACCESS DENIED]"
    try:
        data = json.loads(json_data)
        iv = base64.b64decode(data["iv"])
        ct = base64.b64decode(data["ct"])
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode()
    except:
        return "[DECRYPTION ERROR]"

# ===== CONNECT =====
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, PORT))

username = input("Username: ")
safetoken = input("Your safetoken: ")

# Send login info
sock.send(json.dumps({"username": username, "safetoken": safetoken}).encode())

def send_message():
    while True:
        recipient = input("Send to (username): ")
        msg = input("Message: ")
        encrypted = encrypt_message(msg)
        # Include sender safetoken for approval
        payload = {
            "sender": username,
            "recipient": recipient,
            "payload": encrypted,
            "safetoken": safetoken
        }
        sock.send(json.dumps(payload).encode())
        print(f"[ENCRYPTED SENT] {encrypted}")

def receive_message():
    while True:
        data = sock.recv(4096)
        if not data:
            break
        msg = json.loads(data.decode())
        sender = msg.get("sender")
        payload = msg.get("payload")
        print(f"\n[ENCRYPTED] from {sender}: {payload}")
        token = input("Enter your safetoken to decrypt: ")
        print(f"[DECRYPTED] {decrypt_message(payload, token, safetoken)}")

