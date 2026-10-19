"""Encrypted, verified storage for device archives captured before a wipe."""

import base64
import hashlib
import json
import os
import secrets
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

MAGIC = b"DBK1"
CHUNK = 1024 * 1024


def backup_key() -> bytes:
    encoded = os.getenv("DEVICE_BACKUP_KEY", "")
    try:
        key = base64.urlsafe_b64decode(encoded)
    except Exception as exc:
        raise RuntimeError("DEVICE_BACKUP_KEY must be a URL-safe base64 AES-256 key") from exc
    if len(key) != 32:
        raise RuntimeError("DEVICE_BACKUP_KEY must decode to 32 bytes")
    return key


def backup_root() -> Path:
    configured = os.getenv("DEVICE_BACKUP_DIR", "")
    if not configured or not Path(configured).is_absolute():
        raise RuntimeError("DEVICE_BACKUP_DIR must be an absolute persistent server path")
    root = Path(configured)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def inspect_archive(upload) -> dict:
    """Reject corrupt or incomplete archives before anything is wiped."""
    upload.seek(0)
    try:
        with zipfile.ZipFile(upload) as archive:
            names = set(archive.namelist())
            if "manifest.json" not in names:
                raise ValueError("Backup archive has no manifest")
            max_bytes = int(os.getenv("DEVICE_BACKUP_MAX_BYTES", str(10 * 1024 * 1024 * 1024)))
            if sum(item.file_size for item in archive.infolist()) > max_bytes:
                raise ValueError("Expanded backup exceeds configured size limit")
            if any(item.filename.startswith("/") or ".." in Path(item.filename).parts
                   for item in archive.infolist()):
                raise ValueError("Backup contains unsafe paths")
            if archive.testzip() is not None:
                raise ValueError("Backup archive is incomplete or corrupt")
            manifest = json.loads(archive.read("manifest.json"))
            if manifest.get("schema") != 1 or manifest.get("complete") is not True:
                raise ValueError("Backup manifest is incomplete")
            categories = manifest.get("categories")
            if not isinstance(categories, dict) or not isinstance(categories.get("app"), int) or categories["app"] < 1:
                raise ValueError("Backup manifest has no app data")
            for category, count in categories.items():
                if not isinstance(category, str) or not isinstance(count, int) or count < 0:
                    raise ValueError("Backup manifest has invalid category counts")
            return manifest
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
        raise ValueError("Backup archive is invalid") from exc
    finally:
        upload.seek(0)


def store_archive(upload, user_id: int, wipe_id: int) -> tuple[str, str, int]:
    key = backup_key()
    root = backup_root() / str(user_id)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    path = root / f"wipe_{wipe_id}.dbk"
    temporary = root / f".{wipe_id}.{secrets.token_hex(8)}.tmp"
    nonce = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    digest = hashlib.sha256()
    size = 0
    limit = int(os.getenv("DEVICE_BACKUP_MAX_BYTES", str(10 * 1024 * 1024 * 1024)))
    try:
        with open(temporary, "xb") as out:
            os.chmod(temporary, 0o600)
            out.write(MAGIC + nonce)
            while chunk := upload.read(CHUNK):
                size += len(chunk)
                if size > limit:
                    raise ValueError("Backup exceeds configured size limit")
                digest.update(chunk)
                out.write(encryptor.update(chunk))
            out.write(encryptor.finalize())
            out.write(encryptor.tag)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        return str(path), digest.hexdigest(), size
    finally:
        temporary.unlink(missing_ok=True)


def decrypt_archive(path: str):
    """Yield plaintext ZIP only after authenticating the complete ciphertext."""
    key = backup_key()
    with open(path, "rb") as source:
        source.seek(0, os.SEEK_END)
        length = source.tell()
        if length < len(MAGIC) + 12 + 16:
            raise ValueError("Backup file is truncated")
        source.seek(0)
        if source.read(4) != MAGIC:
            raise ValueError("Backup format is unknown")
        nonce = source.read(12)
        source.seek(-16, os.SEEK_END)
        tag = source.read(16)
        # Verify once without yielding or writing plaintext to disk, then
        # decrypt again for the response. An invalid tag sends no bytes.
        for verify_only in (True, False):
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            source.seek(16)
            remaining = length - 32
            while remaining:
                block = source.read(min(CHUNK, remaining))
                if not block:
                    raise ValueError("Backup file is truncated")
                remaining -= len(block)
                plaintext = decryptor.update(block)
                if not verify_only:
                    yield plaintext
            try:
                decryptor.finalize()
            except InvalidTag as exc:
                raise ValueError("Backup authentication failed") from exc
