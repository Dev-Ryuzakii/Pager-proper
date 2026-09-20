"""
One-time setup: generates the admin master RSA keypair used to decrypt any
message/file on demand (see ADMIN_MASTER_KEY_DIR usage in
fastapi_mobile_backend_postgresql.py). RSA-2048, same params clients use for
their own device keys (OAEP/SHA-256), so the private key here can unwrap a
key any client wrapped for it.

Run once, on the server, then never move/commit the private key — it lives
only at admin_master_key/private_key.der (gitignored). Losing it just means
new messages stop being admin-decryptable until a fresh key is generated and
clients start wrapping for the new public key; it does not affect normal
messaging at all.
"""

import os
from Crypto.PublicKey import RSA

KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin_master_key")


def generate():
    if os.path.exists(os.path.join(KEY_DIR, "private_key.der")):
        print("Admin master key already exists — refusing to overwrite. "
              "Delete admin_master_key/ first if you really want a new one "
              "(old messages wrapped for the old key become unreadable).")
        return

    os.makedirs(KEY_DIR, exist_ok=True)
    key = RSA.generate(2048)

    with open(os.path.join(KEY_DIR, "private_key.der"), "wb") as f:
        f.write(key.export_key(format="DER", pkcs=8))

    with open(os.path.join(KEY_DIR, "public_key.der"), "wb") as f:
        f.write(key.publickey().export_key(format="DER"))

    os.chmod(os.path.join(KEY_DIR, "private_key.der"), 0o600)
    print(f"Admin master keypair generated at {KEY_DIR}/")


if __name__ == "__main__":
    generate()
