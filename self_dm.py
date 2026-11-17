"""Personal "You" chat and the recording cards that land in it.

A self message has sender_id == recipient_id. Recording cards are plain
system messages (the file stays on disk) and are delivered once per user.
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

import meeting_ai
import meeting_notes
from database_models import (
    ChatSettings,
    HiddenMessage,
    Meeting,
    MeetingRecording,
    Message,
    RetentionPolicy,
    User,
)

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


def _hidden_ids(db: Session, user_id: int) -> set:
    return {
        row.message_id
        for row in db.query(HiddenMessage.message_id).filter(HiddenMessage.user_id == user_id).all()
    }


def _cleared_before(db: Session, user_id: int) -> dict:
    rows = db.query(ChatSettings).filter(
        ChatSettings.user_id == user_id,
        ChatSettings.peer_username.isnot(None),
    ).all()
    return {row.peer_username: row.deleted_before for row in rows}


def _visible(msg: Message, peer_username: str, hidden: set, cleared: dict, now: datetime) -> bool:
    if msg.id in hidden:
        return False
    expires = as_utc(getattr(msg, "expires_at", None))
    if expires is not None and expires <= now:
        return False
    cutoff = as_utc(cleared.get(peer_username))
    stamp = as_utc(getattr(msg, "timestamp", None))
    if cutoff is not None and stamp is not None and stamp <= cutoff:
        return False
    return True


def list_conversations(db: Session, user) -> list:
    """Self chat first, even with no messages. It is never unread."""
    user_id = int(user.id)
    username = str(getattr(user, "username", "") or "")
    now = datetime.now(timezone.utc)
    hidden = _hidden_ids(db, user_id)
    cleared = _cleared_before(db, user_id)
    msgs = db.query(Message).filter(
        or_(Message.sender_id == user_id, Message.recipient_id == user_id)
    ).order_by(Message.timestamp.desc(), Message.id.desc()).all()

    partner_ids = []
    seen = set()
    self_last = None
    for msg in msgs:
        other = msg.recipient_id if msg.sender_id == user_id else msg.sender_id
        if other is None:
            continue
        if int(other) == user_id:
            if self_last is None and _visible(msg, username, hidden, cleared, now):
                self_last = msg
            continue
        other = int(other)
        if other not in seen:
            seen.add(other)
            partner_ids.append(other)

    users = {}
    if partner_ids:
        for row in db.query(User).filter(User.id.in_(partner_ids), User.is_active == True).all():
            users[int(row.id)] = row

    self_item = {
        "username": username,
        "partner_username": username,
        "is_self": True,
        "display_name": "You",
        "is_active": True,
        "last_message": _preview(self_last, username) if self_last is not None else None,
        "unread_count": 0,
    }
    items = [self_item]
    for pid in partner_ids:
        partner = users.get(pid)
        if not partner:
            continue
        actor_org = getattr(user, "organization_id", None)
        if not bool(getattr(user, "is_admin", False)):
            if actor_org is None or actor_org != getattr(partner, "organization_id", None):
                continue
        name = str(getattr(partner, "username", "") or "")
        visible_last = None
        unread_count = 0
        for msg in msgs:
            other = msg.recipient_id if msg.sender_id == user_id else msg.sender_id
            if other is None or int(other) != pid:
                continue
            if not _visible(msg, name, hidden, cleared, now):
                continue
            if visible_last is None:
                visible_last = msg
            if int(msg.recipient_id or 0) == user_id and int(msg.sender_id or 0) == pid and not bool(msg.read):
                unread_count += 1
        sender_name = username if visible_last is not None and int(visible_last.sender_id) == user_id else name
        items.append({
            "username": name,
            "partner_username": name,
            "is_self": False,
            "display_name": name,
            "is_active": bool(getattr(partner, "is_active", False)),
            "last_message": _preview(visible_last, sender_name) if visible_last is not None else None,
            "unread_count": unread_count,
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


def _insert_self_card(db: Session, user, payload: dict, content_type: str, decoy: str, message_hash: str):
    if db.query(Message.id).filter(Message.message_hash == message_hash).first():
        return None
    message = Message(
        sender_id=int(user.id),
        recipient_id=int(user.id),
        encrypted_content=json.dumps(payload),
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
    db.add(message)
    db.commit()
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
    """(path, filename) or an HTTP error. 410 once retention or cleanup took the file."""
    recording = db.query(MeetingRecording).filter(MeetingRecording.id == recording_id).first()
    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found")
    meeting_notes._require_reader(db, recording, user)
    if recording_expired(recording, retention_cutoff(db)):
        raise HTTPException(status_code=410, detail="This recording has expired")
    path = meeting_ai.resolve_recording_path(recording.file_path, recordings_dir)
    exists = bool(path) and os.path.isfile(path)
    size = os.path.getsize(path) if exists else 0
    if recording.status != "completed" or not exists or size == 0:
        if recording.status == "completed" and not exists:
            raise HTTPException(status_code=410, detail="This recording has expired")
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
    rows = db.query(MeetingRecording).all()
    readable = []
    for recording in rows:
        try:
            meeting_notes._require_reader(db, recording, user)
        except HTTPException:
            continue
        readable.append(recording)
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


def install_recording_library_routes(app: FastAPI, get_current_user, resolve_token, get_database_session, recordings_dir):
    """File download accepts ?token= as well as Authorization, for a <video> tag."""

    @app.get("/meetings/recordings/mine")
    async def list_my_recordings(
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        return {"recordings": my_recordings(db, current_user)}

    @app.get("/meetings/recordings/{recording_id}/file")
    async def download_recording_file(
        recording_id: int,
        request: Request,
        token: Optional[str] = Query(None),
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_optional_bearer),
        db: Session = Depends(get_database_session),
    ):
        raw = credentials.credentials if credentials else None
        if not raw:
            raw = token
        user = await _resolve_user(resolve_token, db, raw)
        directory = recordings_dir() if callable(recordings_dir) else recordings_dir
        path, filename = openable_recording(db, recording_id, user, directory)
        return recording_file_response(path, filename, request.headers.get("range"))
