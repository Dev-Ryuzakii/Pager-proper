"""Personal "You" chat and the recording cards that land in it.

A self message has sender_id == recipient_id. Recording cards are encrypted
for the user's own devices. The MP4 stays on disk and is delivered once per user.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import and_, case, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import meeting_ai
import meeting_notes
from database_models import (
    ChatSettings,
    ConferenceParticipant,
    ConferenceSession,
    HiddenMessage,
    LinkedDevice,
    Meeting,
    MeetingRecording,
    Message,
    RetentionPolicy,
    User,
)

logger = logging.getLogger(__name__)

_optional_bearer = HTTPBearer(auto_error=False)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso_z(dt: Optional[datetime]) -> Optional[str]:
    aware = as_utc(dt)
    if aware is None:
        return None
    return aware.strftime("%Y-%m-%dT%H:%M:%SZ")


def direct_flags(sender_id: int, recipient_id: int, disappear_after_hours: Optional[int]) -> dict:
    """Self notes never expire and are already read. Other DMs keep the timer."""
    if int(sender_id) == int(recipient_id):
        return {
            "expires_at": None,
            "auto_delete": False,
            "delivered": True,
            "read": True,
            "is_offline": False,
        }
    expires_at = None
    auto_delete = False
    if disappear_after_hours is not None and disappear_after_hours > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=disappear_after_hours)
        auto_delete = True
    return {
        "expires_at": expires_at,
        "auto_delete": auto_delete,
        "delivered": False,
        "read": False,
        "is_offline": True,
    }


def create_direct_message(
    db: Session,
    sender_id: int,
    recipient_id: int,
    content: str,
    disappear_after_hours: Optional[int] = None,
    encrypted_key: Optional[str] = None,
    iv: Optional[str] = None,
    decoy_content: Optional[str] = None,
    content_type: str = "encrypted",
    reply_to_message_id: Optional[int] = None,
    forwarded_from_message_id: Optional[int] = None,
    mentions=None,
) -> Message:
    flags = direct_flags(sender_id, recipient_id, disappear_after_hours)
    message = Message(
        sender_id=int(sender_id),
        recipient_id=int(recipient_id),
        encrypted_content=content,
        content_type=content_type,
        decoy_content=decoy_content,
        encrypted_key=encrypted_key,
        iv=iv,
        reply_to_message_id=reply_to_message_id,
        forwarded_from_message_id=forwarded_from_message_id,
        mentions=mentions,
        **flags,
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return message


def dm_clause(user_id: int, partner_id: int):
    """Self history is only messages where both sides are this user."""
    user_id = int(user_id)
    partner_id = int(partner_id)
    if user_id == partner_id:
        return and_(Message.sender_id == user_id, Message.recipient_id == user_id)
    return or_(
        and_(Message.sender_id == user_id, Message.recipient_id == partner_id),
        and_(Message.sender_id == partner_id, Message.recipient_id == user_id),
    )


def _preview(msg: Message, sender_username: str) -> dict:
    deleted = bool(getattr(msg, "is_deleted", False))
    return {
        "id": int(msg.id),
        "content": "" if deleted else str(getattr(msg, "encrypted_content", "") or ""),
        "decoy_content": "" if deleted else str(getattr(msg, "decoy_content", "") or ""),
        "content_type": "deleted" if deleted else str(getattr(msg, "content_type", "") or ""),
        "timestamp": iso_z(getattr(msg, "timestamp", None)),
        "sender_username": sender_username,
    }


def _cleared_before(db: Session, user_id: int) -> dict:
    rows = db.query(ChatSettings).filter(
        ChatSettings.user_id == user_id,
        ChatSettings.peer_username.isnot(None),
    ).all()
    return {row.peer_username: row.deleted_before for row in rows}


def _partner_id(user_id: int):
    return case((Message.sender_id == user_id, Message.recipient_id), else_=Message.sender_id)


def _dm_with_others(db: Session, user_id: int):
    return db.query(Message).filter(
        or_(Message.sender_id == user_id, Message.recipient_id == user_id),
        ~and_(Message.sender_id == user_id, Message.recipient_id == user_id),
        Message.sender_id.isnot(None),
        Message.recipient_id.isnot(None),
    )


def list_conversations(db: Session, user) -> list:
    """Self chat first. Latest message and unread counts are SQL aggregates, not a full scan."""
    user_id = int(user.id)
    username = str(getattr(user, "username", "") or "")
    now = datetime.now(timezone.utc)
    cleared = _cleared_before(db, user_id)
    partner = _partner_id(user_id)
    hidden = db.query(HiddenMessage.message_id).filter(HiddenMessage.user_id == user_id)
    alive = or_(Message.expires_at.is_(None), Message.expires_at > now)

    self_q = db.query(Message).filter(
        Message.sender_id == user_id,
        Message.recipient_id == user_id,
        ~Message.id.in_(hidden),
        alive,
    )
    self_cut = as_utc(cleared.get(username))
    if self_cut is not None:
        self_q = self_q.filter(Message.timestamp > self_cut)
    self_last = self_q.order_by(Message.timestamp.desc(), Message.id.desc()).first()

    activity = (
        _dm_with_others(db, user_id)
        .with_entities(partner.label("pid"), func.max(Message.timestamp).label("latest"))
        .group_by(partner)
        .order_by(func.max(Message.timestamp).desc(), partner.desc())
        .all()
    )
    partner_ids = [int(row.pid) for row in activity if row.pid is not None]
    users = {}
    if partner_ids:
        for row in db.query(User).filter(User.id.in_(partner_ids), User.is_active == True).all():
            users[int(row.id)] = row

    ranked = (
        _dm_with_others(db, user_id)
        .join(User, User.id == partner)
        .outerjoin(ChatSettings, and_(ChatSettings.user_id == user_id, ChatSettings.peer_username == User.username))
        .filter(
            ~Message.id.in_(hidden),
            alive,
            or_(ChatSettings.deleted_before.is_(None), Message.timestamp > ChatSettings.deleted_before),
        )
        .with_entities(
            Message.id.label("mid"),
            partner.label("pid"),
            func.row_number().over(
                partition_by=partner,
                order_by=(Message.timestamp.desc(), Message.id.desc()),
            ).label("rn"),
        )
        .subquery()
    )
    latest_by_pid = {}
    latest_ids = [row.mid for row in db.query(ranked.c.mid).filter(ranked.c.rn == 1).all()]
    if latest_ids:
        for msg in db.query(Message).filter(Message.id.in_(latest_ids)).all():
            other = msg.recipient_id if int(msg.sender_id) == user_id else msg.sender_id
            latest_by_pid[int(other)] = msg

    unread_rows = (
        _dm_with_others(db, user_id)
        .filter(Message.recipient_id == user_id, Message.read.is_(False), ~Message.id.in_(hidden), alive)
        .join(User, User.id == Message.sender_id)
        .outerjoin(ChatSettings, and_(ChatSettings.user_id == user_id, ChatSettings.peer_username == User.username))
        .filter(or_(ChatSettings.deleted_before.is_(None), Message.timestamp > ChatSettings.deleted_before))
        .with_entities(Message.sender_id, func.count(Message.id))
        .group_by(Message.sender_id)
        .all()
    )
    unread = {int(sid): int(count) for sid, count in unread_rows}

    items = [{
        "username": username,
        "partner_username": username,
        "is_self": True,
        "display_name": "You",
        "is_active": True,
        "last_message": _preview(self_last, username) if self_last is not None else None,
        "unread_count": 0,
    }]
    actor_org = getattr(user, "organization_id", None)
    is_admin = bool(getattr(user, "is_admin", False))
    for pid in partner_ids:
        person = users.get(pid)
        if not person:
            continue
        if not is_admin and (actor_org is None or actor_org != getattr(person, "organization_id", None)):
            continue
        name = str(getattr(person, "username", "") or "")
        last = latest_by_pid.get(pid)
        sender_name = username if last is not None and int(last.sender_id) == user_id else name
        items.append({
            "username": name,
            "partner_username": name,
            "is_self": False,
            "display_name": name,
            "is_active": bool(getattr(person, "is_active", False)),
            "last_message": _preview(last, sender_name) if last is not None else None,
            "unread_count": unread.get(pid, 0),
        })
    return items


def meeting_title(db: Session, conference_id: int) -> str:
    row = db.query(Meeting).filter(Meeting.conference_id == conference_id).order_by(Meeting.id.desc()).first()
    title = str(getattr(row, "title", "") or "").strip() if row else ""
    return title or "Meeting"


def duration_seconds(started, ended) -> Optional[int]:
    start, end = as_utc(started), as_utc(ended)
    if start is None or end is None:
        return None
    return max(0, int((end - start).total_seconds()))


def recipient_users(db: Session, recording: MeetingRecording) -> list:
    """Starter plus admitted participants, one organization, no duplicates."""
    starter = db.query(User).filter(User.id == recording.started_by_user_id).first()
    org_id = getattr(starter, "organization_id", None) if starter else None
    ids = meeting_notes._participant_ids(db, recording)
    users = db.query(User).filter(User.id.in_(list(ids))).all() if ids else []
    chosen = []
    seen = set()
    for person in users:
        if person.id in seen:
            continue
        same_org = org_id is not None and person.organization_id == org_id
        if same_org or (starter is not None and person.id == starter.id):
            seen.add(person.id)
            chosen.append(person)
    if starter is not None and starter.id not in seen:
        chosen.append(starter)
    chosen.sort(key=lambda person: int(person.id))
    return chosen


def recording_hash(recording_id: int, user_id: int) -> str:
    return f"rec:{int(recording_id)}:{int(user_id)}"


def notes_hash(recording_id: int, user_id: int) -> str:
    return f"notes:{int(recording_id)}:{int(user_id)}"


def _known_size(recording: MeetingRecording, path: str) -> Optional[int]:
    if path and os.path.exists(path):
        size = os.path.getsize(path)
        if size > 0:
            return int(size)
    stored = getattr(recording, "file_size", None)
    if stored:
        return int(stored)
    return None


def recording_card(db: Session, recording: MeetingRecording, recordings_dir: str) -> dict:
    path = meeting_ai.resolve_recording_path(recording.file_path, recordings_dir)
    host = db.query(User).filter(User.id == recording.started_by_user_id).first()
    rid = int(recording.id)
    return {
        "kind": "meeting_recording",
        "recording_id": rid,
        "conference_id": int(recording.conference_id),
        "meeting_title": meeting_title(db, recording.conference_id),
        "host_username": str(getattr(host, "username", "") or ""),
        "started_at": iso_z(recording.started_at),
        "ended_at": iso_z(recording.ended_at),
        "duration_seconds": duration_seconds(recording.started_at, recording.ended_at),
        "file_size": _known_size(recording, path),
        "download_path": f"/meetings/recordings/{rid}/file",
        "notes_path": f"/meetings/recordings/{rid}/notes",
    }


def notes_card(db: Session, recording: MeetingRecording) -> dict:
    body = meeting_notes.notes_body(recording.notes_json) or {}
    points = body.get("key_points") or []
    if not isinstance(points, list):
        points = []
    cleaned = [str(point) for point in points if str(point).strip()][:5]
    items = body.get("action_items") or []
    rid = int(recording.id)
    return {
        "kind": "meeting_notes",
        "recording_id": rid,
        "meeting_title": meeting_title(db, recording.conference_id),
        "summary": str(body.get("summary") or "")[:400],
        "key_points": cleaned,
        "action_item_count": len(items) if isinstance(items, list) else 0,
        "notes_path": f"/meetings/recordings/{rid}/notes",
    }


def _load_public_key(raw: str):
    from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_public_key
    text = (raw or "").strip()
    if "BEGIN PUBLIC KEY" in text:
        return load_pem_public_key(text.encode())
    der = base64.b64decode(text)
    return load_der_public_key(der)


def encrypt_for_user(db: Session, user, plaintext: str):
    """AES-GCM body plus one RSA-OAEP wrap per device. None when the user has no usable key."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    wraps = []
    devices = db.query(LinkedDevice).filter(
        LinkedDevice.user_id == int(user.id),
        LinkedDevice.revoked_at.is_(None),
    ).all()
    for device in devices:
        try:
            wraps.append((str(device.device_uuid), _load_public_key(device.public_key)))
        except Exception:
            logger.info("card key skipped device_uuid=%s", device.device_uuid)
    legacy = getattr(user, "public_key", None)
    if legacy:
        try:
            wraps.append((str(getattr(user, "username", "") or ""), _load_public_key(legacy)))
        except Exception:
            logger.info("card key skipped user_id=%s", user.id)
    if not wraps:
        return None
    aes_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(iv, plaintext.encode(), None)
    oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    wrapped = {}
    for label, public_key in wraps:
        if not label:
            continue
        wrapped[label] = base64.b64encode(public_key.encrypt(aes_key, oaep)).decode()
    if not wrapped:
        return None
    return base64.b64encode(ciphertext).decode(), json.dumps(wrapped), base64.b64encode(iv).decode()


def _insert_self_card(db: Session, user, payload: dict, content_type: str, decoy: str, message_hash: str):
    if db.query(Message.id).filter(Message.message_hash == message_hash).first():
        return None
    packed = encrypt_for_user(db, user, json.dumps(payload))
    if packed is None:
        logger.info("card skipped, no device key user_id=%s", user.id)
        return None
    ciphertext, encrypted_key, iv = packed
    message = Message(
        sender_id=int(user.id),
        recipient_id=int(user.id),
        encrypted_content=ciphertext,
        encrypted_key=encrypted_key,
        iv=iv,
        content_type=content_type,
        decoy_content=decoy,
        delivered=True,
        read=True,
        is_offline=False,
        expires_at=None,
        auto_delete=False,
        message_hash=message_hash,
        timestamp=meeting_notes.naive_utc(),
    )
    try:
        db.add(message)
        db.commit()
    except IntegrityError:
        db.rollback()
        return None
    db.refresh(message)
    return message


def deliver_recording_cards(db: Session, recording_id: int, recordings_dir: str) -> list:
    recording = db.query(MeetingRecording).filter(MeetingRecording.id == recording_id).first()
    if not recording:
        return []
    payload = recording_card(db, recording, recordings_dir)
    created = []
    for person in recipient_users(db, recording):
        message = _insert_self_card(
            db, person, payload, "meeting_recording", "🎥 Meeting recording",
            recording_hash(recording.id, person.id),
        )
        if message is not None:
            created.append(message)
    return created


def deliver_notes_cards(db: Session, recording_id: int) -> list:
    recording = db.query(MeetingRecording).filter(MeetingRecording.id == recording_id).first()
    if not recording or recording.ai_status != "done":
        return []
    payload = notes_card(db, recording)
    created = []
    for person in recipient_users(db, recording):
        message = _insert_self_card(
            db, person, payload, "meeting_notes", "📝 Meeting notes",
            notes_hash(recording.id, person.id),
        )
        if message is not None:
            created.append(message)
    return created


def retention_cutoff(db: Session, now: Optional[datetime] = None) -> Optional[datetime]:
    policy = db.query(RetentionPolicy).order_by(RetentionPolicy.id.asc()).first()
    if not policy or not policy.auto_delete_days:
        return None
    now = now or datetime.now(timezone.utc)
    return now - timedelta(days=int(policy.auto_delete_days))


def recording_expired(recording: MeetingRecording, cutoff: Optional[datetime]) -> bool:
    if cutoff is None or recording.ended_at is None:
        return False
    return meeting_notes.recording_is_expired(as_utc(recording.ended_at), as_utc(cutoff))


def safe_filename(title: str, started_at) -> str:
    slug = _SAFE_NAME.sub("-", title or "Meeting").strip("-") or "Meeting"
    stamp = as_utc(started_at)
    day = stamp.strftime("%Y-%m-%d") if stamp else "recording"
    return f"{slug}-{day}.mp4"


def openable_recording(db: Session, recording_id: int, user, recordings_dir: str):
    """(path, filename) or an HTTP error. Processing is never reported as expired."""
    recording = db.query(MeetingRecording).filter(MeetingRecording.id == recording_id).first()
    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found")
    meeting_notes._require_reader(db, recording, user)
    if recording.status == "failed":
        raise HTTPException(status_code=404, detail="This recording failed")
    if recording.status in ("recording", "processing"):
        raise HTTPException(status_code=409, detail="Recording is still being processed")
    if recording_expired(recording, retention_cutoff(db)):
        raise HTTPException(status_code=410, detail="This recording has expired")
    path = meeting_ai.resolve_recording_path(recording.file_path, recordings_dir)
    exists = bool(path) and os.path.isfile(path)
    size = os.path.getsize(path) if exists else 0
    if recording.status == "completed" and not exists:
        raise HTTPException(status_code=410, detail="This recording has expired")
    if not exists or size == 0:
        raise HTTPException(status_code=409, detail="Recording is still being processed")
    return path, safe_filename(meeting_title(db, recording.conference_id), recording.started_at)


def parse_byte_range(header: Optional[str], size: int):
    """(start, end) inclusive, 'invalid', or None when the header is absent."""
    if not header:
        return None
    if not header.lower().startswith("bytes="):
        return "invalid"
    spec = header.split("=", 1)[1].split(",", 1)[0].strip()
    if "-" not in spec:
        return "invalid"
    start_s, end_s = spec.split("-", 1)
    if start_s == "":
        try:
            suffix = int(end_s)
        except ValueError:
            return "invalid"
        if suffix <= 0:
            return "invalid"
        suffix = min(suffix, size)
        return size - suffix, size - 1
    try:
        start = int(start_s)
    except ValueError:
        return "invalid"
    if start < 0 or start >= size:
        return "invalid"
    if end_s == "":
        end = size - 1
    else:
        try:
            end = int(end_s)
        except ValueError:
            return "invalid"
        if end < start:
            return "invalid"
        end = min(end, size - 1)
    return start, end


def recording_file_response(path: str, filename: str, range_header: Optional[str]):
    size = os.path.getsize(path)
    parsed = parse_byte_range(range_header, size)
    if parsed == "invalid":
        return Response(status_code=416, headers={"Content-Range": f"bytes */{size}", "Accept-Ranges": "bytes"})
    start, end = (0, size - 1) if parsed is None else parsed
    length = end - start + 1

    def chunks():
        with open(path, "rb") as handle:
            handle.seek(start)
            remaining = length
            while remaining:
                block = handle.read(min(1024 * 1024, remaining))
                if not block:
                    break
                remaining -= len(block)
                yield block

    headers = {
        "Accept-Ranges": "bytes",
        "Content-Disposition": f'inline; filename="{filename}"',
        "Content-Length": str(length),
    }
    status = 200
    if parsed is not None:
        status = 206
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    return StreamingResponse(chunks(), status_code=status, media_type="video/mp4", headers=headers)


def my_recordings(db: Session, user) -> list:
    """Recordings this user started or was admitted to. Admins do not see other people's meetings."""
    user_id = int(user.id)
    started = db.query(MeetingRecording).filter(MeetingRecording.started_by_user_id == user_id).all()
    seats = db.query(ConferenceParticipant).filter(ConferenceParticipant.user_id == user_id).all()
    conference_ids = [
        row.conference_id for row in seats
        if meeting_notes.participant_was_admitted(row.status, row.is_active, row.left_at)
    ]
    joined = []
    if conference_ids:
        joined = db.query(MeetingRecording).filter(MeetingRecording.conference_id.in_(conference_ids)).all()
    by_id = {int(row.id): row for row in started}
    for row in joined:
        by_id[int(row.id)] = row
    readable = list(by_id.values())
    readable.sort(key=lambda row: (as_utc(row.started_at) or datetime.min.replace(tzinfo=timezone.utc), int(row.id)), reverse=True)
    items = []
    for recording in readable:
        host = db.query(User).filter(User.id == recording.started_by_user_id).first()
        rid = int(recording.id)
        items.append({
            "recording_id": rid,
            "meeting_title": meeting_title(db, recording.conference_id),
            "host_username": str(getattr(host, "username", "") or ""),
            "started_at": iso_z(recording.started_at),
            "ended_at": iso_z(recording.ended_at),
            "duration_seconds": duration_seconds(recording.started_at, recording.ended_at),
            "status": recording.status,
            "ai_status": recording.ai_status,
            "download_path": f"/meetings/recordings/{rid}/file",
            "notes_path": f"/meetings/recordings/{rid}/notes",
        })
    return items


async def _resolve_user(resolve_token, db: Session, raw: Optional[str]):
    if not raw:
        raise HTTPException(status_code=401, detail="Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
    user = resolve_token(db, raw)
    if hasattr(user, "__await__"):
        user = await user
    return user


def file_link_secret_default() -> str:
    from config import settings
    return settings.SECRET_KEY


def make_file_sig(secret: str, recording_id: int, user_id: int, expires_epoch: int) -> str:
    body = f"{int(recording_id)}.{int(user_id)}.{int(expires_epoch)}"
    mac = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{body}.{mac}".encode()).decode().rstrip("=")


def read_file_sig(secret: str, token: str, recording_id: int):
    """user id, or 'bad' / 'expired' / 'wrong'."""
    pad = "=" * (-len(token or "") % 4)
    try:
        raw = base64.urlsafe_b64decode((token or "") + pad).decode()
        rec_s, user_s, exp_s, mac = raw.split(".", 3)
        expected = hmac.new(secret.encode(), f"{rec_s}.{user_s}.{exp_s}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            return "bad"
    except Exception:
        return "bad"
    if int(exp_s) < int(time.time()):
        return "expired"
    if int(rec_s) != int(recording_id):
        return "wrong"
    return int(user_s)


def dm_fanout(sender_username: str, recipient_username: str, content_type: str) -> dict:
    """Self notes stay on the user's devices. They are not pushed and not webhooked."""
    is_self = sender_username == recipient_username
    data = {
        "sender_username": sender_username,
        "recipient_username": recipient_username,
    }
    if is_self:
        data["is_self"] = True
        data["content_type"] = content_type
    return {"ws": data, "push": not is_self, "webhook": not is_self}


def claim_recording(db: Session, recording_id: int, from_status: str, to_status: str, ended_at=None) -> bool:
    values = {MeetingRecording.status: to_status}
    if ended_at is not None:
        values[MeetingRecording.ended_at] = ended_at
    changed = db.query(MeetingRecording).filter(
        MeetingRecording.id == recording_id,
        MeetingRecording.status == from_status,
    ).update(values, synchronize_session="fetch")
    db.commit()
    return changed == 1


def claim_conference_recordings(db: Session, conference_id: int, now=None) -> list:
    """Move recording → processing. Only rows this call actually changed."""
    now = now or meeting_notes.naive_utc()
    rows = db.query(MeetingRecording).filter(
        MeetingRecording.conference_id == conference_id,
        MeetingRecording.status == "recording",
    ).all()
    claimed = []
    for row in rows:
        if claim_recording(db, int(row.id), "recording", "processing", now):
            claimed.append(row)
    return claimed


async def complete_live_recordings(db: Session, conference_id: int, stop_egress) -> list:
    """Claim each row before awaiting egress stop, so stop and leave cannot both win."""
    claimed = claim_conference_recordings(db, conference_id)
    for row in claimed:
        await stop_egress(row.egress_id)
    return claimed


def _file_size_now(recording: MeetingRecording, recordings_dir: str) -> Optional[int]:
    path = meeting_ai.resolve_recording_path(recording.file_path, recordings_dir)
    if path and os.path.isfile(path):
        size = os.path.getsize(path)
        if size > 0:
            return int(size)
    return None


def finalize_recording(db: Session, recording_id: int, recordings_dir: str) -> dict:
    """processing → completed exactly once, then queue notes and deliver cards."""
    recording = db.query(MeetingRecording).filter(MeetingRecording.id == recording_id).first()
    if not recording:
        return {"claimed": False, "run_ai": False, "messages": []}
    if recording.status == "recording":
        claim_recording(db, recording_id, "recording", "processing", meeting_notes.naive_utc())
        db.refresh(recording)
    if recording.status == "processing":
        if not claim_recording(db, recording_id, "processing", "completed"):
            db.refresh(recording)
            messages = deliver_recording_cards(db, recording_id, recordings_dir)
            if recording.ai_status == "done":
                messages.extend(deliver_notes_cards(db, recording_id))
            return {"claimed": False, "run_ai": False, "messages": messages}
        db.refresh(recording)
    elif recording.status == "completed":
        messages = deliver_recording_cards(db, recording_id, recordings_dir)
        if recording.ai_status == "done":
            messages.extend(deliver_notes_cards(db, recording_id))
        return {"claimed": False, "run_ai": False, "messages": messages}
    else:
        return {"claimed": False, "run_ai": False, "messages": []}
    size = _file_size_now(recording, recordings_dir)
    recording.file_size = size
    db.commit()
    db.refresh(recording)
    host = db.query(User).filter(User.id == recording.started_by_user_id).first()
    run_ai = meeting_notes.queue_if_enabled(db, recording, getattr(host, "organization_id", None))
    messages = deliver_recording_cards(db, recording_id, recordings_dir)
    return {"claimed": True, "run_ai": bool(run_ai), "messages": messages}


def fail_recording(db: Session, recording_id: int) -> bool:
    changed = db.query(MeetingRecording).filter(
        MeetingRecording.id == recording_id,
        MeetingRecording.status.in_(("recording", "processing")),
    ).update({MeetingRecording.status: "failed"}, synchronize_session="fetch")
    db.commit()
    return changed == 1


def conference_id_from_room(name: Optional[str]) -> Optional[int]:
    if not name or not str(name).startswith("conf-"):
        return None
    tail = str(name).split("-", 1)[1]
    return int(tail) if tail.isdigit() else None


def finish_conference(db: Session, conference_id: int, now=None) -> dict:
    """Same end state as /leave when the room is already empty. Idempotent."""
    now = now or meeting_notes.naive_utc()
    conf = db.query(ConferenceSession).filter(ConferenceSession.id == conference_id).first()
    notify = []
    if conf is not None and conf.is_active:
        conf.is_active = False
        conf.ended_at = now
        db.commit()
        notify = [
            int(row.user_id) for row in db.query(ConferenceParticipant).filter(
                ConferenceParticipant.conference_id == conference_id,
                ConferenceParticipant.is_active == True,
            ).all()
        ]
    claimed = claim_conference_recordings(db, conference_id, now)
    return {
        "notify_user_ids": notify,
        "stop_egress": [row.egress_id for row in claimed],
        "recording_ids": [int(row.id) for row in claimed],
    }


def _egress_blob(event: dict) -> dict:
    return event.get("egressInfo") or event.get("egress_info") or {}


def _egress_status_name(info: dict) -> str:
    status = info.get("status")
    names = {3: "EGRESS_COMPLETE", 4: "EGRESS_FAILED", 5: "EGRESS_ABORTED", 6: "EGRESS_LIMIT_REACHED"}
    if isinstance(status, int):
        return names.get(status, "")
    return str(status or "")


def apply_livekit_event(db: Session, event: dict, recordings_dir: str) -> dict:
    name = str(event.get("event") or "")
    outcome = {"notify_user_ids": [], "conference_id": None, "stop_egress": [], "ready": [], "failed": []}
    if name == "room_finished":
        room = event.get("room") or {}
        conference_id = conference_id_from_room(room.get("name") or room.get("roomName"))
        if conference_id is None:
            return outcome
        finished = finish_conference(db, conference_id)
        outcome.update(finished)
        outcome["conference_id"] = conference_id
        return outcome
    if name != "egress_ended":
        return outcome
    info = _egress_blob(event)
    egress_id = info.get("egressId") or info.get("egress_id")
    recording = db.query(MeetingRecording).filter(MeetingRecording.egress_id == egress_id).first() if egress_id else None
    if not recording:
        return outcome
    status = _egress_status_name(info)
    if status == "EGRESS_COMPLETE":
        ready = finalize_recording(db, int(recording.id), recordings_dir)
        outcome["ready"].append({"id": int(recording.id), **ready})
    elif status in ("EGRESS_FAILED", "EGRESS_ABORTED", "EGRESS_LIMIT_REACHED"):
        if fail_recording(db, int(recording.id)):
            outcome["failed"].append(int(recording.id))
    return outcome


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_livekit_webhook(body: bytes, api_key: str, api_secret: str, ttl: int = 60) -> str:
    """HS256 token with a sha256 claim, the shape LiveKit's WebhookReceiver checks."""
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode()
    payload = _b64url(json.dumps({
        "iss": api_key, "sub": "", "nbf": now - 5, "exp": now + ttl, "sha256": digest,
    }, separators=(",", ":")).encode())
    sig = hmac.new(api_secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_livekit_webhook(body: bytes, auth: Optional[str], api_key: str, api_secret: str) -> dict:
    """Reject anything that is not a signed LiveKit webhook. Never returns the body otherwise."""
    token = (auth or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token or not api_key or not api_secret:
        raise ValueError("missing signature")
    try:
        from livekit.api import TokenVerifier, WebhookReceiver
        event = WebhookReceiver(TokenVerifier(api_key, api_secret)).receive(body.decode(), token)
        try:
            from google.protobuf.json_format import MessageToDict
            return MessageToDict(event)
        except Exception:
            return json.loads(body.decode())
    except ImportError:
        pass
    except Exception as exc:
        raise ValueError("invalid signature") from exc
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid signature")
    signing = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(api_secret.encode(), signing, hashlib.sha256).digest()
    try:
        given = _b64url_decode(parts[2])
        claims = json.loads(_b64url_decode(parts[1]).decode())
    except Exception as exc:
        raise ValueError("invalid signature") from exc
    if not hmac.compare_digest(expected, given):
        raise ValueError("invalid signature")
    if claims.get("iss") != api_key:
        raise ValueError("invalid signature")
    exp = int(claims.get("exp") or 0)
    if exp < int(time.time()):
        raise ValueError("invalid signature")
    claimed = base64.b64decode(claims.get("sha256") or "")
    if not hmac.compare_digest(claimed, hashlib.sha256(body).digest()):
        raise ValueError("invalid signature")
    return json.loads(body.decode())


def sweep_recordings(db: Session, now: datetime, recordings_dir: str, egress_status, room_open, seen: dict) -> list:
    """Finalize processing rows and pick up recordings whose room is already gone."""
    actions = []
    recording_rows = db.query(MeetingRecording).filter(MeetingRecording.status == "recording").all()
    for row in recording_rows:
        conf = db.query(ConferenceSession).filter(ConferenceSession.id == row.conference_id).first()
        inactive = conf is None or not conf.is_active
        alive = room_open(int(row.conference_id)) if room_open else None
        if inactive or alive is False:
            if claim_recording(db, int(row.id), "recording", "processing", meeting_notes.naive_utc()):
                actions.append({"action": "processing", "id": int(row.id)})
    horizon = as_utc(now) - timedelta(minutes=2)
    stuck = db.query(MeetingRecording).filter(MeetingRecording.status == "processing").all()
    for row in stuck:
        ended = as_utc(row.ended_at)
        if ended is None or ended > horizon:
            continue
        status = None
        if egress_status:
            status = egress_status(row.egress_id)
        if status == "EGRESS_COMPLETE":
            actions.append({"action": "ready", "id": int(row.id), **finalize_recording(db, int(row.id), recordings_dir)})
            continue
        if status in ("EGRESS_FAILED", "EGRESS_ABORTED", "EGRESS_LIMIT_REACHED"):
            if fail_recording(db, int(row.id)):
                actions.append({"action": "failed", "id": int(row.id)})
            continue
        if status:
            continue
        size = _file_size_now(row, recordings_dir)
        if size:
            previous = seen.get(int(row.id))
            if previous and previous[0] == size and (as_utc(now) - as_utc(previous[1])).total_seconds() >= 60:
                actions.append({"action": "ready", "id": int(row.id), **finalize_recording(db, int(row.id), recordings_dir)})
            elif not previous or previous[0] != size:
                seen[int(row.id)] = (size, now)
            continue
        if ended <= as_utc(now) - timedelta(minutes=30):
            if fail_recording(db, int(row.id)):
                actions.append({"action": "failed", "id": int(row.id)})
    recent_cut = meeting_notes.naive_utc(as_utc(now) - timedelta(days=1))
    finished = db.query(MeetingRecording).filter(
        MeetingRecording.status == "completed",
        MeetingRecording.ended_at.isnot(None),
        MeetingRecording.ended_at >= recent_cut,
    ).all()
    for row in finished:
        ended = as_utc(row.ended_at)
        if ended is not None and ended >= as_utc(recent_cut):
            messages = deliver_recording_cards(db, int(row.id), recordings_dir)
            if row.ai_status == "done":
                messages.extend(deliver_notes_cards(db, int(row.id)))
            if messages:
                actions.append({"action": "cards", "id": int(row.id), "messages": messages})
    return actions


def install_recording_library_routes(app: FastAPI, get_current_user, resolve_token, get_database_session, recordings_dir, file_secret=None):
    """Bearer auth, or a short HMAC sig from POST .../file-link. Session tokens are not accepted in the query."""
    secret_of = file_secret or file_link_secret_default

    @app.get("/meetings/recordings/mine")
    async def list_my_recordings(
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        return {"recordings": my_recordings(db, current_user)}

    @app.post("/meetings/recordings/{recording_id}/file-link")
    async def create_file_link(
        recording_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        directory = recordings_dir() if callable(recordings_dir) else recordings_dir
        openable_recording(db, recording_id, current_user, directory)
        expires_epoch = int(time.time()) + 15 * 60
        secret = secret_of() if callable(secret_of) else secret_of
        sig = make_file_sig(secret, recording_id, int(current_user.id), expires_epoch)
        return {
            "url": f"/meetings/recordings/{recording_id}/file?sig={sig}",
            "expires_at": iso_z(datetime.fromtimestamp(expires_epoch, timezone.utc)),
        }

    @app.get("/meetings/recordings/{recording_id}/file")
    async def download_recording_file(
        recording_id: int,
        request: Request,
        sig: Optional[str] = Query(None),
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_optional_bearer),
        db: Session = Depends(get_database_session),
    ):
        directory = recordings_dir() if callable(recordings_dir) else recordings_dir
        if credentials and credentials.credentials:
            user = await _resolve_user(resolve_token, db, credentials.credentials)
        elif sig:
            secret = secret_of() if callable(secret_of) else secret_of
            verdict = read_file_sig(secret, sig, recording_id)
            if verdict == "wrong":
                raise HTTPException(status_code=403, detail="Not a participant in this meeting")
            if not isinstance(verdict, int):
                raise HTTPException(status_code=401, detail="Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
            user = db.query(User).filter(User.id == verdict, User.is_active == True).first()
            if not user:
                raise HTTPException(status_code=401, detail="Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
        else:
            raise HTTPException(status_code=401, detail="Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
        path, filename = openable_recording(db, recording_id, user, directory)
        return recording_file_response(path, filename, request.headers.get("range"))


def install_livekit_webhook_route(app: FastAPI, get_database_session, api_key, api_secret, recordings_dir, after=None):
    @app.post("/livekit/webhook")
    async def livekit_webhook(request: Request, db: Session = Depends(get_database_session)):
        body = await request.body()
        key = api_key() if callable(api_key) else api_key
        secret = api_secret() if callable(api_secret) else api_secret
        try:
            event = verify_livekit_webhook(body, request.headers.get("authorization"), key, secret)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
        directory = recordings_dir() if callable(recordings_dir) else recordings_dir
        outcome = apply_livekit_event(db, event, directory)
        if after is not None:
            await after(db, outcome)
        return {"ok": True}


class RedactRecordingQuery(logging.Filter):
    """Access logs must not keep ?sig= or any other query on the file route."""

    _query = re.compile(r"(/meetings/recordings/\d+/file)\?[^ \"]*")

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._query.sub(r"\1", record.msg)
        if record.args:
            record.args = tuple(
                self._query.sub(r"\1", item) if isinstance(item, str) else item
                for item in record.args
            )
        return True
