"""Security regressions for the November 2026 deployment fixes."""

from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import fastapi_mobile_backend_postgresql as backend
from database_models import Base, RemoteCommand, User


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
