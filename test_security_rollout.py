"""Security regressions for the November 2026 deployment fixes."""

import base64
from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import fastapi_mobile_backend_postgresql as backend
from database_models import Base, RemoteCommand, User, UserSession


def test_hardcoded_superadmin_routes_are_not_registered():
    paths = {route.path for route in backend.app.routes}
    assert not any(path.startswith("/ryuzakii/") for path in paths)


def test_admin_media_routes_do_not_accept_session_tokens_in_query():
    for route in backend.app.routes:
        if (not route.path.startswith("/admin/") or not hasattr(route, "dependant")
                or not hasattr(route, "methods")):
            continue
        assert "token" not in {param.name for param in route.dependant.query_params}, route.path

    response = TestClient(backend.app).get(
        "/admin/monitoring/policy/violations/1/screenshot?token=old-session-token")
    assert response.status_code == 401


def test_live_chunks_require_current_command_for_same_target_and_admin():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    try:
        admin = User(username="admin", phone_number="+15550101", is_admin=True, is_active=True)
        target = User(username="target", phone_number="+15550102", is_admin=False, is_active=True)
        outsider = User(username="outsider", phone_number="+15550103", is_admin=False, is_active=True)
        db.add_all([admin, target, outsider])
        db.commit()
        assert not backend._authorized_live_chunk(db, target.id, admin.id, "device-1", "audio")

        start = RemoteCommand(target_user_id=target.id, target_device_id="device-1",
                              issued_by_admin_id=admin.id, command_type="start_live_audio",
                              status="delivered", issued_at=datetime.utcnow())
        db.add(start)
        db.commit()
        assert backend._authorized_live_chunk(db, target.id, admin.id, "device-1", "audio")
        assert not backend._authorized_live_chunk(db, outsider.id, admin.id, "device-1", "audio")
        assert not backend._authorized_live_chunk(db, target.id, admin.id, "other-device", "audio")
        assert not backend._authorized_live_chunk(db, target.id, admin.id, "device-1", "video")

        stop = RemoteCommand(target_user_id=target.id, issued_by_admin_id=admin.id,
                             command_type="stop_live_audio", status="delivered",
                             issued_at=datetime.utcnow())
        db.add(stop)
        db.commit()
        assert not backend._authorized_live_chunk(db, target.id, admin.id, "device-1", "audio")

        db.delete(stop)
        start.issued_at = datetime.utcnow() - timedelta(hours=3)
        db.commit()
        assert not backend._authorized_live_chunk(db, target.id, admin.id, "device-1", "audio")
    finally:
        db.close()
        engine.dispose()


def test_websocket_ticket_is_scoped_and_expires_with_session(monkeypatch):
    assert TestClient(backend.app).post("/auth/ws-ticket").status_code in (401, 403)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    try:
        user = User(username="ticket-user", phone_number="+15550109", is_active=True)
        db.add(user)
        db.flush()
        session = UserSession(user_id=user.id, session_token="random-session-secret",
                              expires_at=datetime.utcnow() + timedelta(hours=1), is_active=True)
        db.add(session)
        db.commit()
        ticket = backend._make_ws_ticket(session)
        assert backend._validate_ws_ticket(db, ticket).id == session.id
        monkeypatch.setattr(backend.db_config, "get_session", sessionmaker(bind=engine))
        issued = TestClient(backend.app).post(
            "/auth/ws-ticket", headers={"Authorization": "Bearer random-session-secret"})
        assert issued.status_code == 200
        assert backend._validate_ws_ticket(db, issued.json()["ticket"]).id == session.id
        with TestClient(backend.app).websocket_connect(f"/ws?ticket={ticket}&device_id=test-device") as ws:
            first = ws.receive_json()
            assert first["type"] == "connected" or ws.receive_json()["type"] == "connected"
        with TestClient(backend.app).websocket_connect(
            "/ws?device_id=native-device", headers={"Authorization": "Bearer random-session-secret"}) as ws:
            first = ws.receive_json()
            assert first["type"] == "connected" or ws.receive_json()["type"] == "connected"
        decoded = base64.urlsafe_b64decode(ticket + "=" * (-len(ticket) % 4)).decode()
        modified = decoded[:-1] + ("0" if decoded[-1] != "0" else "1")
        tampered = base64.urlsafe_b64encode(modified.encode()).rstrip(b"=").decode()
        assert backend._validate_ws_ticket(db, tampered) is None
        session.is_active = False
        db.commit()
        assert backend._validate_ws_ticket(db, ticket) is None
    finally:
        db.close()
        engine.dispose()
