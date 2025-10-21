import socket
import threading
import json

# ===== CONFIG =====
HOST = "0.0.0.0"       # Listen on all interfaces
PORT = 5050


connected_users = {}
def handle_client(conn):
    try:
        # Step 1: Receive initial login data
        login_data = conn.recv(1024).decode()
        login = json.loads(login_data)
        username = login["username"]
        token = login["safetoken"]

        # Add user to connected list
        connected_users[username] = {"socket": conn, "token": token}
        print(f"[CONNECTED] {username}")

        while True:
            # Receive encrypted message JSON from client
            data = conn.recv(4096)
            if not data:
                break

            try:
                message_json = json.loads(data.decode())
                sender = message_json["sender"]
                recipient = message_json["recipient"]
                payload = message_json["payload"]
                sender_token = message_json.get("safetoken", "")

                # Validate sender token (optional)
                if sender not in connected_users or connected_users[sender]["token"] != sender_token:
                    conn.send(json.dumps({"status": "error", "message": "Invalid sender token"}).encode())
                    continue

                # Forward encrypted message to intended recipient only
                if recipient in connected_users:
                    recipient_sock = connected_users[recipient]["socket"]
                    recipient_sock.send(json.dumps({
                        "sender": sender,
                        "payload": payload
                    }).encode())
                else:
                    # Recipient not connected
                    conn.send(json.dumps({"status": "error", "message": f"{recipient} not online"}).encode())

            except Exception as e:
                print(f"[ERROR] {e}")

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        for user, info in list(connected_users.items()):
            if info["socket"] == conn:
                print(f"[DISCONNECTED] {user}")
                del connected_users[user]
        conn.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    print(f"[LISTENING] Server running on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    start_server()
