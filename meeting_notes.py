"""
Who may read meeting notes, and the small decisions around tasks, sharing
and retention. The transcription pipeline itself stays in meeting_ai.py.
The server never writes a chat message for shared notes: the client encrypts
the text this module formats.
"""

import json
from datetime import datetime
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database_models import (
    ConferenceParticipant,
    Meeting,
    MeetingRecording,
    Organization,
    Task,
    TaskAssignee,
    User,
)


def notes_body(raw: Optional[str]) -> Optional[dict]:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def notes_view(recording, include_transcript: bool = False) -> dict:
    out = {
        "recording_id": int(recording.id),
        "ai_status": recording.ai_status,
        "ai_error": recording.ai_error,
        "providers": recording.ai_providers,
        "processed_at": recording.ai_processed_at.isoformat() if recording.ai_processed_at else None,
        "notes": notes_body(recording.notes_json),
        "segments": recording.transcript_segments or None,
    }
    if include_transcript:
        out["transcript"] = recording.transcript
    return out


def start_block(status: Optional[str], ai_status: Optional[str]) -> Optional[tuple]:
    """(http_status, detail) when a notes job must not start."""
    if status != "completed":
        return 409, "Recording is not finished yet"
    if ai_status == "processing":
        return 409, "Already processing"
    return None


def match_assignee(owner: str, people: list) -> Optional[int]:
    """people: {id, username, full_name}. None when the name is missing or ambiguous."""
    needle = (owner or "").strip().casefold()
    if not needle:
        return None
    hits = []
    for person in people:
        names = {
            (person.get("username") or "").casefold(),
            (person.get("full_name") or "").casefold(),
        }
        names.discard("")
        if needle in names:
            hits.append(person["id"])
    unique = list(dict.fromkeys(hits))
    if len(unique) != 1:
        return None
    return int(unique[0])


def share_markdown(notes: Optional[dict]) -> str:
    """Plain text the client encrypts. Empty string when there are no notes."""
    if not notes:
        return ""
    lines = []
    summary = (notes.get("summary") or "").strip()
    if summary:
        lines.append(summary)
    for label, key in (("Key points", "key_points"), ("Decisions", "decisions")):
        items = [str(x).strip() for x in (notes.get(key) or []) if str(x).strip()]
        if items:
            lines.append("")
            lines.append(label)
            lines.extend(f"- {item}" for item in items)
    actions = notes.get("action_items") or []
    rendered = []
    for item in actions:
        if not isinstance(item, dict):
            continue
        task = str(item.get("task") or "").strip()
        if not task:
            continue
        extra = " ".join(
            part for part in (
                f"({item.get('owner')})" if item.get("owner") else "",
                f"due {item.get('due')}" if item.get("due") else "",
            ) if part
        )
        rendered.append(f"- {task}" + (f" {extra}" if extra else ""))
    if rendered:
        lines.append("")
        lines.append("Action items")
        lines.extend(rendered)
    return "\n".join(lines).strip()


def recording_is_expired(ended_at: Optional[datetime], cutoff: datetime) -> bool:
    return ended_at is not None and ended_at <= cutoff


class OrgNotesSetting(BaseModel):
    auto_meeting_notes: bool


def _load(db: Session, recording_id: int) -> MeetingRecording:
    row = db.query(MeetingRecording).filter(MeetingRecording.id == recording_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Recording not found")
    return row


def _participant_ids(db: Session, recording: MeetingRecording) -> set:
    ids = {
        row.user_id for row in db.query(ConferenceParticipant.user_id).filter(
            ConferenceParticipant.conference_id == recording.conference_id
        ).all()
    }
    if recording.started_by_user_id:
        ids.add(recording.started_by_user_id)
    return ids


def _require_reader(db: Session, recording: MeetingRecording, user) -> None:
    if getattr(user, "is_admin", False):
        return
    if int(user.id) not in _participant_ids(db, recording):
        raise HTTPException(status_code=403, detail="Not a participant in this meeting")


def _people(db: Session, recording: MeetingRecording) -> list:
    ids = _participant_ids(db, recording)
    if not ids:
        return []
    rows = db.query(User).filter(User.id.in_(ids)).all()
    return [{"id": int(row.id), "username": row.username or "", "full_name": row.full_name or ""} for row in rows]


def install_meeting_notes_routes(app: FastAPI, get_current_user, get_database_session, start_job, audit):
    """start_job(recording_id) queues the pipeline. audit(db, user_id, event, description)."""

    @app.get("/meetings/recordings/{recording_id}/notes")
    async def get_notes(
        recording_id: int,
        include_transcript: bool = False,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        recording = _load(db, recording_id)
        _require_reader(db, recording, current_user)
        return notes_view(recording, include_transcript)

    @app.post("/meetings/recordings/{recording_id}/notes", status_code=202)
    async def start_notes(
        recording_id: int,
        background_tasks: BackgroundTasks,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        recording = _load(db, recording_id)
        _require_reader(db, recording, current_user)
        block = start_block(recording.status, recording.ai_status)
        if block:
            raise HTTPException(status_code=block[0], detail=block[1])
        recording.ai_status = "processing"
        recording.ai_error = None
        db.commit()
        background_tasks.add_task(start_job, recording_id)
        return {"recording_id": recording_id, "ai_status": "processing"}

    @app.post("/meetings/recordings/{recording_id}/notes/action-items/{index}/task", status_code=201)
    async def action_item_task(
        recording_id: int,
        index: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        recording = _load(db, recording_id)
        _require_reader(db, recording, current_user)
        notes = notes_body(recording.notes_json) or {}
        items = notes.get("action_items") or []
        if index < 0 or index >= len(items) or not isinstance(items[index], dict):
            raise HTTPException(status_code=404, detail="Action item not found")
        item = items[index]
        title = str(item.get("task") or "").strip()
        if not title:
            raise HTTPException(status_code=404, detail="Action item not found")
        meeting = db.query(Meeting).filter(Meeting.conference_id == recording.conference_id).first()
        assignee = match_assignee(str(item.get("owner") or ""), _people(db, recording))
        task = Task(
            group_id=meeting.group_id if meeting else None,
            created_by_id=int(current_user.id),
            title=title[:255],
            description=str(item.get("due") or "").strip() or None,
        )
        db.add(task)
        db.flush()
        if assignee:
            db.add(TaskAssignee(task_id=task.id, user_id=assignee))
        db.commit()
        db.refresh(task)
        return {"task_id": int(task.id), "title": task.title, "assignee_id": assignee}

    @app.post("/meetings/recordings/{recording_id}/notes/share")
    async def share_notes(
        recording_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        """Returns text for the client to encrypt into the meeting channel. Nothing is posted here."""
        recording = _load(db, recording_id)
        _require_reader(db, recording, current_user)
        notes = notes_body(recording.notes_json)
        if not notes:
            raise HTTPException(status_code=409, detail="Notes are not ready")
        meeting = db.query(Meeting).filter(Meeting.conference_id == recording.conference_id).first()
        return {
            "group_id": int(meeting.group_id) if meeting and meeting.group_id else None,
            "text": share_markdown(notes),
        }

    @app.get("/org/meeting-notes")
    async def get_org_setting(
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        org = _org(db, current_user)
        return {"auto_meeting_notes": bool(org.auto_meeting_notes)}

    @app.put("/org/meeting-notes")
    async def set_org_setting(
        body: OrgNotesSetting,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        if not _can_edit_org(current_user):
            raise HTTPException(status_code=403, detail="Only an organization admin can change this")
        org = _org(db, current_user)
        org.auto_meeting_notes = body.auto_meeting_notes
        db.commit()
        audit(db, int(current_user.id), "auto_meeting_notes", f"organization {org.id} auto_meeting_notes={body.auto_meeting_notes}")
        return {"auto_meeting_notes": bool(org.auto_meeting_notes)}


def _org(db: Session, user) -> Organization:
    org_id = getattr(user, "organization_id", None)
    org = db.query(Organization).filter(Organization.id == org_id).first() if org_id else None
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


def _can_edit_org(user) -> bool:
    if getattr(user, "is_admin", False):
        return True
    if getattr(user, "organization_role", None) in ("admin", "viewer") or getattr(user, "user_type", None) == "organization":
        return True
    privs = getattr(user, "org_privileges", None) or []
    return "manage_groups" in privs or "*" in privs


def consent_audit_text(conference_id: int) -> str:
    return f"Recording and transcription started for conference {conference_id}"


def queue_if_enabled(db: Session, recording: MeetingRecording, organization_id: Optional[int]) -> bool:
    """Mark processing when the org asked for notes automatically. Caller queues the job."""
    if not organization_id:
        return False
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org or not org.auto_meeting_notes:
        return False
    if start_block(recording.status, recording.ai_status):
        return False
    recording.ai_status = "processing"
    recording.ai_error = None
    db.commit()
    return True
