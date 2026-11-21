"""Live meeting transcript (captions while the meeting is happening).

Anyone in the meeting can turn it on, switch its language or turn it off. A separate process (captions_worker.py) joins the LiveKit
room as a hidden participant, transcribes each speaker's audio on this server
with faster-whisper, writes segments to the database and asks this API to push
them to everyone in the meeting over the existing WebSocket.

Nothing goes to a third party. Meeting audio already reaches the server through
LiveKit, so this adds no new place the audio travels; the transcript text is
stored in plain text like recordings and meeting notes, readable only by people
who were admitted to the meeting.

Routes (installed by `install_live_caption_routes`):
    POST /calls/conference/{id}/captions/start   anyone in the meeting; body {"language": "en"|"auto"|...}
                                                 also changes the language while it runs
    POST /calls/conference/{id}/captions/stop    anyone in the meeting
    GET  /calls/conference/{id}/captions         admitted participants
    POST /internal/captions/broadcast            captions worker only (shared secret)

WebSocket events sent to active participants:
    meeting_captions_state  {conference_id, enabled, status, started_by, language}
    meeting_caption         {conference_id, id, speaker_username, speaker_name, text, started_at, ended_at}
"""

import hmac
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import Session

from database_models import Base, ConferenceParticipant, ConferenceSession

logger = logging.getLogger(__name__)

ACTIVE_STATUSES = ("requested", "running")

# Spoken languages the host can pick. "auto" lets the model detect the language
# of each utterance; picking one is faster and more accurate. Codes are the
# ones faster-whisper takes.
CAPTION_LANGUAGES = [
    ("auto", "Detect automatically"),
    ("en", "English"),
    ("fr", "French"),
    ("es", "Spanish"),
    ("pt", "Portuguese"),
    ("de", "German"),
    ("it", "Italian"),
    ("nl", "Dutch"),
    ("ar", "Arabic"),
    ("zh", "Chinese"),
    ("ja", "Japanese"),
    ("ko", "Korean"),
    ("hi", "Hindi"),
    ("ru", "Russian"),
    ("tr", "Turkish"),
    ("sw", "Swahili"),
    ("yo", "Yoruba"),
    ("ha", "Hausa"),
]
_LANGUAGE_CODES = {code for code, _ in CAPTION_LANGUAGES}


def normalize_language(value: Optional[str]) -> Optional[str]:
    """None means detect automatically. Raises 400 for a code we don't offer."""
    code = (value or "").strip().lower()
    if code in ("", "auto"):
        return None
    if code not in _LANGUAGE_CODES:
        raise HTTPException(status_code=400, detail="That language isn't supported for the live transcript")
    return code


def captions_enabled() -> bool:
    return os.getenv("CAPTIONS_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")


def worker_secret() -> str:
    return os.getenv("CAPTIONS_WORKER_SECRET", "").strip()


def naive_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_z(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class MeetingCaptionSession(Base):
    """One run of live captions in one conference (room)."""
    __tablename__ = "meeting_caption_sessions"

    id = Column(Integer, primary_key=True, index=True)
    conference_id = Column(Integer, nullable=False, index=True)
    started_by_user_id = Column(Integer, nullable=False)
    # requested -> running -> stopped | failed
    status = Column(String(20), nullable=False, default="requested")
    error = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=naive_utc)
    started_at = Column(DateTime, nullable=True)
    stopped_at = Column(DateTime, nullable=True)
    heartbeat_at = Column(DateTime, nullable=True)
    # Spoken language for transcription; NULL = detect automatically.
    language = Column(String(10), nullable=True)


class MeetingCaptionSegment(Base):
    """One finished utterance from one speaker."""
    __tablename__ = "meeting_caption_segments"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)
    conference_id = Column(Integer, nullable=False, index=True)
    speaker_username = Column(String(120), nullable=False)
    speaker_name = Column(String(200), nullable=True)
    text = Column(Text, nullable=False)
    started_at = Column(DateTime, nullable=False)
    ended_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=naive_utc)


def active_session(db: Session, conference_id: int) -> Optional[MeetingCaptionSession]:
    return (
        db.query(MeetingCaptionSession)
        .filter(
            MeetingCaptionSession.conference_id == conference_id,
            MeetingCaptionSession.status.in_(ACTIVE_STATUSES),
        )
        .order_by(MeetingCaptionSession.id.desc())
        .first()
    )


def segment_json(row: MeetingCaptionSegment) -> dict:
    return {
        "conference_id": int(row.conference_id),
        "id": int(row.id),
        "speaker_username": row.speaker_username,
        "speaker_name": row.speaker_name or row.speaker_username,
        "text": row.text,
        "started_at": iso_z(row.started_at),
        "ended_at": iso_z(row.ended_at),
    }


def state_json(conference_id: int, session: Optional[MeetingCaptionSession], usernames: dict) -> dict:
    if session is None or session.status not in ACTIVE_STATUSES:
        return {"conference_id": conference_id, "enabled": False, "status": "off", "started_by": None, "language": None, "error": getattr(session, "error", None)}
    return {
        "conference_id": conference_id,
        "enabled": True,
        "status": "running" if session.status == "running" else "starting",
        "started_by": usernames.get(int(session.started_by_user_id)),
        "language": session.language or "auto",
        "error": None,
    }


def can_read(db: Session, conference_id: int, user) -> bool:
    """Admitted participants (current or past) and platform admins."""
    if getattr(user, "is_admin", False):
        return True
    rows = db.query(ConferenceParticipant).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.user_id == int(user.id),
    ).all()
    for row in rows:
        status = getattr(row, "status", None) or "admitted"
        if status == "admitted" and (bool(row.is_active) or row.left_at is not None):
            return True
    return False


def active_user_ids(db: Session, conference_id: int) -> list:
    rows = db.query(ConferenceParticipant.user_id, ConferenceParticipant.status).filter(
        ConferenceParticipant.conference_id == conference_id,
        ConferenceParticipant.is_active == True,  # noqa: E712
    ).all()
    return sorted({int(uid) for uid, status in rows if (status or "admitted") == "admitted"})


class StartBody(BaseModel):
    language: Optional[str] = None


class BroadcastBody(BaseModel):
    segment_id: Optional[int] = None
    session_id: Optional[int] = None


def install_live_caption_routes(
    app: FastAPI,
    get_current_user,
    get_database_session,
    host_id_for,
    send_to_user,
    username_for,
):
    """
    host_id_for(db, conference_id) -> int        the meeting's real host
    send_to_user(user_id, payload) -> awaitable  WebSocket push
    username_for(db, user_id) -> Optional[str]
    """

    async def push_to_room(db: Session, conference_id: int, event_type: str, data: dict) -> None:
        for uid in active_user_ids(db, conference_id):
            try:
                await send_to_user(uid, {"type": event_type, "data": data})
            except Exception as e:  # never fail the caller because one socket is gone
                logger.warning("captions push failed user=%s: %s", uid, type(e).__name__)

    def state_for(db: Session, conference_id: int, session: Optional[MeetingCaptionSession]) -> dict:
        names = {}
        if session is not None:
            names[int(session.started_by_user_id)] = username_for(db, int(session.started_by_user_id))
        return state_json(conference_id, session, names)

    def require_member(db: Session, conference_id: int, user) -> None:
        """The host or anyone currently admitted to the meeting."""
        conf = db.query(ConferenceSession).filter(ConferenceSession.id == conference_id).first()
        if not conf:
            raise HTTPException(status_code=404, detail="Meeting not found")
        if host_id_for(db, conference_id) != int(user.id) and int(user.id) not in active_user_ids(db, conference_id):
            raise HTTPException(status_code=403, detail="Join the meeting to use the live transcript")
        if not bool(getattr(conf, "is_active", False)):
            raise HTTPException(status_code=409, detail="This meeting has ended")

    @app.post("/calls/conference/{conference_id}/captions/start")
    async def start_live_captions(
        conference_id: int,
        body: Optional[StartBody] = Body(None),
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        if not captions_enabled():
            raise HTTPException(status_code=503, detail="Live transcript isn't available on this server")
        require_member(db, conference_id, current_user)
        language = normalize_language(body.language) if body is not None else None
        session = active_session(db, conference_id)
        if session is None:
            session = MeetingCaptionSession(
                conference_id=conference_id,
                started_by_user_id=int(current_user.id),
                status="requested",
                language=language,
            )
            db.add(session)
            db.commit()
            db.refresh(session)
            state = state_for(db, conference_id, session)
            await push_to_room(db, conference_id, "meeting_captions_state", state)
            return state
        # Already on: a request that names a language switches to it. The
        # worker reads it on its next check, a few seconds later.
        if body is not None and body.language is not None and session.language != language:
            session.language = language
            db.commit()
            state = state_for(db, conference_id, session)
            await push_to_room(db, conference_id, "meeting_captions_state", state)
            return state
        return state_for(db, conference_id, session)

    @app.post("/calls/conference/{conference_id}/captions/stop")
    async def stop_live_captions(
        conference_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        require_member(db, conference_id, current_user)
        session = active_session(db, conference_id)
        if session is not None:
            session.status = "stopped"
            session.stopped_at = naive_utc()
            db.commit()
        state = state_for(db, conference_id, None)
        await push_to_room(db, conference_id, "meeting_captions_state", state)
        return state

    @app.get("/calls/conference/{conference_id}/captions")
    async def get_live_captions(
        conference_id: int,
        after_id: int = Query(0, ge=0),
        limit: int = Query(300, ge=1, le=1000),
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        if not can_read(db, conference_id, current_user):
            raise HTTPException(status_code=403, detail="Not a participant in this meeting")
        rows = (
            db.query(MeetingCaptionSegment)
            .filter(MeetingCaptionSegment.conference_id == conference_id, MeetingCaptionSegment.id > after_id)
            .order_by(MeetingCaptionSegment.id.desc())
            .limit(limit)
            .all()
        )
        rows.reverse()
        state = state_for(db, conference_id, active_session(db, conference_id))
        state["available"] = captions_enabled()
        state["languages"] = [{"code": code, "name": name} for code, name in CAPTION_LANGUAGES]
        state["segments"] = [segment_json(r) for r in rows]
        return state

    @app.post("/internal/captions/broadcast")
    async def captions_broadcast(
        body: BroadcastBody,
        x_captions_secret: Optional[str] = Header(None),
        db: Session = Depends(get_database_session),
    ):
        secret = worker_secret()
        if not secret:
            raise HTTPException(status_code=503, detail="Captions worker is not configured")
        if not x_captions_secret or not hmac.compare_digest(x_captions_secret, secret):
            raise HTTPException(status_code=401, detail="Invalid worker secret")
        if body.segment_id is not None:
            row = db.query(MeetingCaptionSegment).filter(MeetingCaptionSegment.id == body.segment_id).first()
            if not row:
                raise HTTPException(status_code=404, detail="Segment not found")
            await push_to_room(db, int(row.conference_id), "meeting_caption", segment_json(row))
            return {"sent": True}
        if body.session_id is not None:
            session = db.query(MeetingCaptionSession).filter(MeetingCaptionSession.id == body.session_id).first()
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            current = session if session.status in ACTIVE_STATUSES else None
            await push_to_room(db, int(session.conference_id), "meeting_captions_state", {
                **state_for(db, int(session.conference_id), current),
                "error": session.error if session.status == "failed" else None,
            })
            return {"sent": True}
        raise HTTPException(status_code=400, detail="segment_id or session_id is required")
