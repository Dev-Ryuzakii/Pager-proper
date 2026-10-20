"""SMTP acceptance and failure are recorded once per requested email."""

import asyncio

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import fastapi_mobile_backend_postgresql as api
from database_models import Base, EmailDeliveryLog


class FakeSmtp:
    sent = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def login(self, *args):
        pass

    def send_message(self, message):
        self.sent.append(message)


def test_email_attempts_are_visible_to_admins(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(api.db_config, "get_session", sessions)
    monkeypatch.setattr(api, "_email_providers", lambda: [
        ("smtp", "mail.example.test", 465, "user", "password", True, False, "team@example.test")
    ])
    monkeypatch.setattr(api.smtplib, "SMTP_SSL", FakeSmtp)
    FakeSmtp.sent = []

    assert api._send_email_message("person@example.test", "Welcome", "Hello") is True
    assert len(FakeSmtp.sent) == 1

    with sessions() as db:
        result = asyncio.run(api.admin_email_logs(
            status_filter=None, search="", limit=50, offset=0, current_admin=object(), db=db,
        ))
    assert result["total"] == 1
    assert result["today"]["sent"] == 1
    assert result["items"][0]["recipient"] == "person@example.test"
    assert result["items"][0]["status"] == "sent"
    assert "provider" not in result["items"][0]

    monkeypatch.setattr(api, "_email_providers", lambda: [])
    assert api._send_email_message("other@example.test", "Invitation", "Code") is False
    with sessions() as db:
        rows = db.query(EmailDeliveryLog).order_by(EmailDeliveryLog.id).all()
        assert [row.status for row in rows] == ["sent", "failed"]
        assert rows[1].failure_reason == "No email provider configured"


def test_fallback_attempt_is_one_email_log(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(api.db_config, "get_session", sessions)
    monkeypatch.setattr(api, "_email_providers", lambda: [
        ("first", "first.example.test", 465, "user", "password", True, False, "team@example.test"),
        ("second", "second.example.test", 465, "user", "password", True, False, "team@example.test"),
    ])

    class FirstFails(FakeSmtp):
        def send_message(self, message):
            raise api.smtplib.SMTPException("provider unavailable")

    monkeypatch.setattr(api.smtplib, "SMTP_SSL", lambda host, *args, **kwargs: (
        FirstFails() if host == "first.example.test" else FakeSmtp()
    ))
    FakeSmtp.sent = []
    assert api._send_email_message("person@example.test", "Notice", "Body") is True
    assert len(FakeSmtp.sent) == 1
    with sessions() as db:
        rows = db.query(EmailDeliveryLog).all()
        assert len(rows) == 1
        assert rows[0].status == "sent"


def test_two_resend_accounts_rotate_and_keep_one_log_per_email(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(api.db_config, "get_session", sessions)
    for name in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RESEND_API_KEY", "first-key")
    monkeypatch.setenv("RESEND_FROM_EMAIL", "first@one.example")
    monkeypatch.setenv("RESEND_API_KEY_2", "second-key")
    monkeypatch.setenv("RESEND_FROM_EMAIL_2", "second@two.example")

    used_keys = []

    class RecordingSmtp(FakeSmtp):
        def login(self, user, password):
            used_keys.append(password)

    monkeypatch.setattr(api.smtplib, "SMTP_SSL", RecordingSmtp)
    assert api._send_email_message("one@example.test", "First", "Body") is True
    assert api._send_email_message("two@example.test", "Second", "Body") is True
    assert used_keys == ["first-key", "second-key"]
    with sessions() as db:
        rows = db.query(EmailDeliveryLog).all()
        assert len(rows) == 2
        assert all(row.status == "sent" for row in rows)

    # A second key from the same account must never be counted as another pool.
    monkeypatch.setenv("RESEND_API_KEY_2", "first-key")
    assert len(api._email_providers()) == 1
