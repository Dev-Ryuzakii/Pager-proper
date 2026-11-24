"""Sign-in approval: a new device waits for approval instead of signing others out."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import fastapi_mobile_backend_postgresql as backend
import login_approval
from database_models import User, UserSession


@pytest.fixture
def env(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in (User.__table__, UserSession.__table__, login_approval.LoginRequest.__table__):
        table.create(engine, checkfirst=True)
    Session = sessionmaker(bind=engine)
    db = Session()
    user = User(username="ada", phone_number="+15550001", is_active=True)
    db.add(user)
    db.commit()

    sent = []

    async def send_to_user(uid, payload):
        sent.append((uid, payload))
        return True

    monkeypatch.setattr(backend.ws_manager, "send_to_user", send_to_user)
    monkeypatch.setattr(backend.ws_manager, "disconnect_devices", AsyncMock(return_value=0))
    monkeypatch.setattr(backend.AdminService, "authenticate_user", lambda *a, **k: db.query(User).first())
    monkeypatch.setattr(backend.AuditService, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(backend, "monitor_record_event", lambda *a, **k: None)
    monkeypatch.setattr(backend, "_approximate_location", AsyncMock(return_value="Lagos, Nigeria"))

    def get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    backend.app.dependency_overrides[backend.get_database_session] = get_db
    client = TestClient(backend.app)
    yield SimpleNamespace(db=db, user=user, sent=sent, client=client, Session=Session, monkeypatch=monkeypatch)
    backend.app.dependency_overrides.clear()


def login(env, device_id, name="Infinix SMART 7", platform="android"):
    return env.client.post("/auth/login", json={
        "username": "ada", "token": "pw", "device_id": device_id, "device_name": name, "platform": platform,
    })


def test_first_device_signs_in_directly(env):
    res = login(env, "phone-1")
    assert res.status_code == 200, res.text
    assert res.json()["token"]


def test_second_device_waits_and_first_stays_signed_in(env):
    first = login(env, "phone-1").json()["token"]
    res = login(env, "laptop-1", name="MacBook Air", platform="desktop")
    assert res.status_code == 202, res.text
    body = res.json()
    assert body["status"] == "approval_required"
    assert body["device_name"] == "MacBook Air"
    assert body["location"] == "Lagos, Nigeria"
    assert "token" not in body
    # The first device is untouched and was asked.
    s = env.Session()
    assert s.query(UserSession).filter(UserSession.session_token == first).first().is_active
    asks = [p for _, p in env.sent if p["type"] == "login_approval_request"]
    assert asks and asks[0]["data"]["device_name"] == "MacBook Air"
    # Still waiting.
    st = env.client.post("/auth/login-requests/status", json={"request_token": body["request_token"]})
    assert st.json()["status"] == "pending"


def test_approval_from_signed_in_device_lets_new_device_in(env):
    first = login(env, "phone-1").json()["token"]
    body = login(env, "laptop-1", platform="desktop").json()
    pending = env.client.get("/auth/login-requests/pending", headers={"Authorization": f"Bearer {first}"}).json()
    rid = pending["requests"][0]["request_id"]
    res = env.client.post(f"/auth/login-requests/{rid}/decision", json={"approve": True},
                          headers={"Authorization": f"Bearer {first}"})
    assert res.json()["status"] == "approved"
    st = env.client.post("/auth/login-requests/status", json={"request_token": body["request_token"]}).json()
    assert st["status"] == "completed"
    assert st["login"]["token"]
    # Collected once only.
    again = env.client.post("/auth/login-requests/status", json={"request_token": body["request_token"]})
    assert again.status_code == 409
    # Both devices signed in.
    s = env.Session()
    assert s.query(UserSession).filter(UserSession.is_active == True).count() == 2


def test_denied_request_never_gets_a_session(env):
    first = login(env, "phone-1").json()["token"]
    body = login(env, "laptop-1", platform="desktop").json()
    rid = env.client.get("/auth/login-requests/pending", headers={"Authorization": f"Bearer {first}"}).json()["requests"][0]["request_id"]
    env.client.post(f"/auth/login-requests/{rid}/decision", json={"approve": False},
                    headers={"Authorization": f"Bearer {first}"})
    st = env.client.post("/auth/login-requests/status", json={"request_token": body["request_token"]}).json()
    assert st["status"] == "denied"
    assert "login" not in st


def test_master_token_fallback_and_lockout(env):
    login(env, "phone-1")
    env.monkeypatch.setattr(backend, "validate_master_token", lambda db, uid, t: t == "right")
    ok_req = login(env, "laptop-1", platform="desktop").json()
    wrong = env.client.post("/auth/login-requests/master-token",
                            json={"request_token": ok_req["request_token"], "master_token": "nope"})
    assert wrong.status_code == 401
    right = env.client.post("/auth/login-requests/master-token",
                            json={"request_token": ok_req["request_token"], "master_token": "right"})
    assert right.status_code == 200, right.text
    assert right.json()["login"]["token"]

    locked = login(env, "tablet-1", platform="android").json()
    codes = [env.client.post("/auth/login-requests/master-token",
                             json={"request_token": locked["request_token"], "master_token": "nope"}).status_code
             for _ in range(login_approval.MAX_MASTER_TOKEN_ATTEMPTS)]
    assert codes[-1] == 403
    st = env.client.post("/auth/login-requests/status", json={"request_token": locked["request_token"]}).json()
    assert st["status"] == "denied"


def test_same_device_signing_in_again_needs_no_approval(env):
    login(env, "phone-1")
    res = login(env, "phone-1")
    assert res.status_code == 200
    s = env.Session()
    assert s.query(UserSession).filter(UserSession.is_active == True).count() == 1


def test_email_page_get_changes_nothing_and_post_approves(env):
    login(env, "phone-1")
    body = login(env, "laptop-1", platform="desktop").json()
    s = env.Session()
    row = s.query(login_approval.LoginRequest).filter(login_approval.LoginRequest.status == "pending").first()
    token = "known-email-token-for-test-0123456789"
    row.email_token_hash = login_approval._hash(token)
    s.commit()
    page = env.client.get(f"/auth/login-requests/email/{token}")
    assert page.status_code == 200 and "Is this you?" in page.text
    st = env.client.post("/auth/login-requests/status", json={"request_token": body["request_token"]}).json()
    assert st["status"] == "pending"
    done = env.client.post(f"/auth/login-requests/email/{token}", data={"action": "approve"})
    assert "approved" in done.text
    st = env.client.post("/auth/login-requests/status", json={"request_token": body["request_token"]}).json()
    assert st["status"] == "completed"


def test_device_used_before_signs_back_in_while_another_is_signed_in(env):
    # Laptop was approved earlier and later signed out on its own.
    login(env, "phone-1")
    env.monkeypatch.setattr(backend, "validate_master_token", lambda db, uid, t: t == "right")
    req = login(env, "laptop-1", platform="desktop").json()
    env.client.post("/auth/login-requests/master-token",
                    json={"request_token": req["request_token"], "master_token": "right"})
    s = env.Session()
    laptop = s.query(UserSession).filter(UserSession.device_id == "laptop-1").first()
    laptop.is_active = False
    laptop.logout_reason = "user_logout"
    s.commit()
    # Signing back in on it is not a new device, so no approval needed.
    assert login(env, "laptop-1", platform="desktop").status_code == 200


def test_device_the_owner_signed_out_needs_approval_again(env):
    login(env, "phone-1")
    env.monkeypatch.setattr(backend, "validate_master_token", lambda db, uid, t: t == "right")
    req = login(env, "laptop-1", platform="desktop").json()
    env.client.post("/auth/login-requests/master-token",
                    json={"request_token": req["request_token"], "master_token": "right"})
    s = env.Session()
    laptop = s.query(UserSession).filter(UserSession.device_id == "laptop-1").first()
    laptop.is_active = False
    laptop.logout_reason = "signed_out_by_owner"
    s.commit()
    assert login(env, "laptop-1", platform="desktop").status_code == 202


def _age_session(env, token, minutes):
    from datetime import datetime, timedelta, timezone
    s = env.Session()
    row = s.query(UserSession).filter(UserSession.session_token == token).first()
    row.last_activity = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    s.commit()


def test_stale_session_on_another_device_does_not_need_approval(env):
    # The phone idle-locked or closed without telling the server: its session is
    # still active but nobody is there to approve, so sign-in goes straight in.
    first = login(env, "phone-1").json()["token"]
    _age_session(env, first, login_approval.LIVE_SESSION_WINDOW.total_seconds() / 60 + 5)
    res = login(env, "laptop-1", name="MacBook Air", platform="desktop")
    assert res.status_code == 200, res.text
    assert not [p for _, p in env.sent if p["type"] == "login_approval_request"]


def test_idle_device_still_connected_needs_approval(env):
    # Not used for a while but its app is open (WebSocket connected): it can
    # approve, so the new device still has to ask.
    first = login(env, "phone-1").json()["token"]
    _age_session(env, first, 120)
    env.monkeypatch.setattr(backend.ws_manager, "get_user_devices", lambda uid: [{"device_id": "phone-1"}])
    res = login(env, "laptop-1", name="MacBook Air", platform="desktop")
    assert res.status_code == 202, res.text
