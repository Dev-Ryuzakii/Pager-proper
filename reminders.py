"""Personal reminders: "remind me to do X at time Y".

Separate from calendar meetings and tasks. A reminder belongs to one user, fires
once at remind_at (or repeats), and can be snoozed or dismissed. The sweep in
dispatch_due_reminders() runs every 30 seconds from the backend lifespan.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from database_models import Base

logger = logging.getLogger(__name__)

RECURRENCES = {None, "daily", "weekdays", "weekly", "monthly"}
STATUSES = {"scheduled", "fired", "dismissed", "done"}


class Reminder(Base):
    __tablename__ = "reminders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    # Who set it. Differs from user_id when an AI agent or a manager set it for someone.
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    title = Column(String(255), nullable=False)
    note = Column(Text, nullable=True)
    remind_at = Column(DateTime(timezone=True), nullable=False, index=True)
    recurrence = Column(String(20), nullable=True)
    status = Column(String(20), default="scheduled", nullable=False, index=True)
    # Optional link to something in the app (a chat, task, meeting, whiteboard).
    link_type = Column(String(30), nullable=True)
    link_id = Column(Integer, nullable=True)
    source = Column(String(20), default="user", nullable=False)  # user / ai_agent
    fired_at = Column(DateTime(timezone=True), nullable=True)
    snooze_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    dt = _utc(dt)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def reminder_dict(r: Reminder) -> dict:
    return {
        "id": r.id,
        "user_id": r.user_id,
        "created_by_id": r.created_by_id,
        "title": r.title,
        "note": r.note,
        "remind_at": _iso(r.remind_at),
        "recurrence": r.recurrence,
        "status": r.status,
        "link_type": r.link_type,
        "link_id": r.link_id,
        "source": r.source,
        "fired_at": _iso(r.fired_at),
        "snooze_count": r.snooze_count,
        "created_at": _iso(r.created_at),
    }


def next_occurrence(at: datetime, recurrence: Optional[str]) -> Optional[datetime]:
    at = _utc(at)
    if recurrence == "daily":
        return at + timedelta(days=1)
    if recurrence == "weekdays":
        nxt = at + timedelta(days=1)
        while nxt.weekday() >= 5:
            nxt += timedelta(days=1)
        return nxt
    if recurrence == "weekly":
        return at + timedelta(weeks=1)
    if recurrence == "monthly":
        month = at.month + 1
        year = at.year + (month - 1) // 12
        month = (month - 1) % 12 + 1
        day = min(at.day, [31, 29 if year % 4 == 0 and (year % 100 or year % 400 == 0) else 28,
                           31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1])
        return at.replace(year=year, month=month, day=day)
    return None


def create_reminder(db: Session, user_id: int, title: str, remind_at: datetime, *, note=None,
                    recurrence=None, link_type=None, link_id=None, created_by_id=None,
                    source="user") -> Reminder:
    """Shared by the API and the AI agent runner."""
    if recurrence not in RECURRENCES:
        raise ValueError("recurrence must be daily, weekdays, weekly or monthly")
    title = (title or "").strip()
    if not title:
        raise ValueError("title is required")
    row = Reminder(
        user_id=int(user_id),
        created_by_id=int(created_by_id or user_id),
        title=title[:255],
        note=(note or "").strip() or None,
        remind_at=_utc(remind_at),
        recurrence=recurrence,
        link_type=link_type,
        link_id=link_id,
        source=source,
    )
    db.add(row)
    db.flush()
    return row


class ReminderCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    remind_at: datetime
    note: Optional[str] = Field(None, max_length=4000)
    recurrence: Optional[str] = None
    link_type: Optional[str] = Field(None, max_length=30)
    link_id: Optional[int] = None


class ReminderUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    remind_at: Optional[datetime] = None
    note: Optional[str] = Field(None, max_length=4000)
    recurrence: Optional[str] = None
    clear_recurrence: bool = False


class SnoozeBody(BaseModel):
    minutes: int = Field(10, ge=1, le=60 * 24 * 7)


async def dispatch_due_reminders(db: Session, notify, push) -> int:
    """Fire every reminder whose time has come. notify(user_ids, payload) is the
    websocket fan-out; push(db, user_id, title, body) is the device push fallback."""
    now = datetime.now(timezone.utc)
    due: List[Reminder] = (
        db.query(Reminder)
        .filter(Reminder.status == "scheduled", Reminder.remind_at <= now)
        .order_by(Reminder.remind_at)
        .limit(500)
        .all()
    )
    for r in due:
        payload = {"type": "reminder_due", "data": reminder_dict(r)}
        try:
            await notify([r.user_id], payload)
        except Exception:
            pass
        try:
            await push(db, r.user_id, "Reminder", r.title, bypass_quiet=False)
        except TypeError:
            await push(db, r.user_id, "Reminder", r.title)
        except Exception as e:
            logger.warning("reminder push failed: %s", type(e).__name__)
        r.fired_at = now
        nxt = next_occurrence(r.remind_at, r.recurrence)
        if nxt is not None:
            while nxt <= now:  # server was down: skip missed repeats, fire once
                nxt = next_occurrence(nxt, r.recurrence)
            r.remind_at = nxt
            r.snooze_count = 0
        else:
            r.status = "fired"
    if due:
        db.commit()
    return len(due)


def install_reminder_routes(app: FastAPI, get_current_user, get_database_session):

    def _own(db: Session, user, reminder_id: int) -> Reminder:
        row = db.query(Reminder).filter(Reminder.id == reminder_id, Reminder.user_id == int(user.id)).first()
        if not row:
            raise HTTPException(status_code=404, detail="Reminder not found")
        return row

    @app.post("/reminders", status_code=201)
    async def create_reminder_route(body: ReminderCreate, current_user=Depends(get_current_user),
                                    db: Session = Depends(get_database_session)):
        try:
            row = create_reminder(db, current_user.id, body.title, body.remind_at, note=body.note,
                                  recurrence=body.recurrence, link_type=body.link_type, link_id=body.link_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        db.commit()
        return reminder_dict(row)

    @app.get("/reminders")
    async def list_reminders(
        status: Optional[str] = Query(None, description="scheduled, fired, dismissed, done, or 'active'"),
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = Query(200, ge=1, le=500),
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        q = db.query(Reminder).filter(Reminder.user_id == int(current_user.id))
        if status == "active":
            q = q.filter(Reminder.status.in_(("scheduled", "fired")))
        elif status:
            q = q.filter(Reminder.status == status)
        if start:
            q = q.filter(Reminder.remind_at >= _utc(start))
        if end:
            q = q.filter(Reminder.remind_at <= _utc(end))
        rows = q.order_by(Reminder.remind_at).limit(limit).all()
        return {"reminders": [reminder_dict(r) for r in rows]}

    @app.get("/reminders/{reminder_id}")
    async def get_reminder(reminder_id: int, current_user=Depends(get_current_user),
                           db: Session = Depends(get_database_session)):
        return reminder_dict(_own(db, current_user, reminder_id))

    @app.patch("/reminders/{reminder_id}")
    async def update_reminder(reminder_id: int, body: ReminderUpdate, current_user=Depends(get_current_user),
                              db: Session = Depends(get_database_session)):
        row = _own(db, current_user, reminder_id)
        if body.recurrence is not None and body.recurrence not in RECURRENCES:
            raise HTTPException(status_code=400, detail="recurrence must be daily, weekdays, weekly or monthly")
        if body.title is not None:
            row.title = body.title.strip()
        if body.note is not None:
            row.note = body.note.strip() or None
        if body.recurrence is not None:
            row.recurrence = body.recurrence
        if body.clear_recurrence:
            row.recurrence = None
        if body.remind_at is not None:
            row.remind_at = _utc(body.remind_at)
            row.status = "scheduled"
            row.fired_at = None
        db.commit()
        return reminder_dict(row)

    @app.post("/reminders/{reminder_id}/snooze")
    async def snooze_reminder(reminder_id: int, body: SnoozeBody, current_user=Depends(get_current_user),
                              db: Session = Depends(get_database_session)):
        row = _own(db, current_user, reminder_id)
        row.remind_at = datetime.now(timezone.utc) + timedelta(minutes=body.minutes)
        row.status = "scheduled"
        row.snooze_count = (row.snooze_count or 0) + 1
        db.commit()
        return reminder_dict(row)

    @app.post("/reminders/{reminder_id}/done")
    async def complete_reminder(reminder_id: int, current_user=Depends(get_current_user),
                                db: Session = Depends(get_database_session)):
        row = _own(db, current_user, reminder_id)
        row.status = "done"
        db.commit()
        return reminder_dict(row)

    @app.post("/reminders/{reminder_id}/dismiss")
    async def dismiss_reminder(reminder_id: int, current_user=Depends(get_current_user),
                               db: Session = Depends(get_database_session)):
        row = _own(db, current_user, reminder_id)
        row.status = "dismissed"
        db.commit()
        return reminder_dict(row)

    @app.delete("/reminders/{reminder_id}", status_code=204)
    async def delete_reminder(reminder_id: int, current_user=Depends(get_current_user),
                              db: Session = Depends(get_database_session)):
        db.delete(_own(db, current_user, reminder_id))
        db.commit()
