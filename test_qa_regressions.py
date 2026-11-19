"""Regression checks for the browser QA findings from 19 November 2026."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import fastapi_mobile_backend_postgresql as backend
from database_models import Base, Group, GroupMember, Media, Meeting, MeetingParticipant, Message, User


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def users(db):
    admin = User(username="admin", phone_number="+15550101", is_admin=True, is_active=True)
    bright = User(username="Dr.Bright", phone_number="+15550102", is_admin=False, is_active=True)
    outsider = User(username="outsider", phone_number="+15550103", is_admin=False, is_active=True)
    db.add_all([admin, bright, outsider])
    db.commit()
    return admin, bright, outsider


def test_platform_admin_can_create_group_with_selected_user(db, users, monkeypatch):
    admin, bright, outsider = users
    monkeypatch.setattr(backend.MessageService, "send_message_to_group", lambda *args, **kwargs: None)
    monkeypatch.setattr(backend.AuditService, "log_event", lambda *args, **kwargs: None)

    group = backend.GroupService.create_group(db, admin.id, "QA Group", None, [bright.username])

    assert {(m.user_id, m.role) for m in db.query(GroupMember).filter(GroupMember.group_id == group.id)} == {
        (admin.id, "admin"), (bright.id, "member")
    }
    with pytest.raises(HTTPException) as error:
        backend.GroupService.create_group(db, outsider.id, "No tenant", None, [bright.username])
    assert error.value.status_code == 403


def test_channel_admin_can_read_members_but_outsider_cannot(db, users):
    admin, bright, outsider = users
    channel = Group(name="Test", created_by=bright.id, kind="channel", visibility="private")
    db.add(channel)
    db.flush()
    db.add(GroupMember(group_id=channel.id, user_id=bright.id, role="owner"))
    db.commit()

    members = asyncio.run(backend.get_group_members(channel.id, current_user=admin, db=db))
    assert [member["username"] for member in members] == ["Dr.Bright"]
    with pytest.raises(HTTPException) as error:
        asyncio.run(backend.get_group_members(channel.id, current_user=outsider, db=db))
    assert error.value.status_code == 403


def test_search_returns_people_channels_and_files(db, users):
    admin, bright, _ = users
    channel = Group(name="Test", created_by=bright.id, kind="channel", visibility="public")
    db.add(channel)
    db.flush()
    db.add(GroupMember(group_id=channel.id, user_id=bright.id, role="owner"))
    message = Message(sender_id=admin.id, recipient_id=bright.id, encrypted_content="ciphertext")
    db.add(message)
    db.flush()
    db.add(Media(media_id="qa-file", filename="Test notes.pdf", file_size=7, media_type="document",
                 content_type="application/pdf", encrypted_file_path="/tmp/qa-file", message_id=message.id,
                 sender_id=admin.id))
    db.commit()

    people = asyncio.run(backend.unified_search(q="Bright", limit=20, current_user=admin, db=db))
    results = asyncio.run(backend.unified_search(q="Test", limit=20, current_user=admin, db=db))
    empty = asyncio.run(backend.unified_search(q="no_such_match", limit=20, current_user=admin, db=db))

    assert [person["username"] for person in people["people"]] == ["Dr.Bright"]
    assert [item["name"] for item in results["channels"]] == ["Test"]
    assert [item["filename"] for item in results["files"]] == ["Test notes.pdf"]
    assert not any(empty[key] for key in ("people", "groups", "channels", "files"))


def test_meeting_times_are_utc_and_past_rows_leave_upcoming(db, users, monkeypatch):
    admin, _, _ = users
    monkeypatch.setattr(backend, "_send_meeting_card", AsyncMock())
    monkeypatch.setattr(backend, "_fire_webhooks", AsyncMock())
    monkeypatch.setattr(backend, "monitor_record_event", lambda *args, **kwargs: None)
    local_start = (datetime.now(timezone.utc) + timedelta(days=1)).astimezone(timezone(timedelta(hours=1)))
    payload = backend.MeetingCreateRequest(title="QA meeting", scheduled_at=local_start, duration_minutes=30)
    created = asyncio.run(backend.create_meeting(payload, BackgroundTasks(), current_user=admin, db=db))
    meeting = db.query(Meeting).filter(Meeting.id == created["meeting_id"]).one()
    assert meeting.scheduled_at == local_start.astimezone(timezone.utc).replace(tzinfo=None)
    assert datetime.fromisoformat(created["scheduled_at"]) == local_start.astimezone(timezone.utc)

    old = Meeting(creator_id=admin.id, title="Old live meeting",
                  scheduled_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30),
                  duration_minutes=30, join_code="OLDQA001", status="live")
    db.add(old)
    db.flush()
    db.add(MeetingParticipant(meeting_id=old.id, user_id=admin.id))
    db.commit()

    upcoming = asyncio.run(backend.list_upcoming_meetings(current_user=admin, db=db))["meetings"]
    assert [item["title"] for item in upcoming] == ["QA meeting"]
    assert datetime.fromisoformat(upcoming[0]["scheduled_at"]) == local_start.astimezone(timezone.utc)
    with pytest.raises(HTTPException) as error:
        asyncio.run(backend.join_meeting_by_code(backend.MeetingJoinRequest(join_code="OLDQA001"), current_user=admin, db=db))
    assert error.value.status_code == 400
    assert error.value.detail == "Meeting has already ended"
