import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

import fastapi_mobile_backend_postgresql as backend


def test_replaced_token_has_specific_unauthorized_reason(monkeypatch):
    monkeypatch.setattr(backend.SessionService, "validate_session", lambda db, token: None)

    class Query:
        def __init__(self, row):
            self.row = row

        def filter(self, *args):
            return self

        def first(self):
            return self.row

    class DB:
        def query(self, model):
            if model is backend.LinkedDevice:
                return Query(None)
            if model is backend.UserSession:
                return Query(SimpleNamespace(logout_reason="replaced"))
            raise AssertionError(model)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(backend._user_for_session_token(DB(), "old-token"))
    assert exc.value.status_code == 401
    assert exc.value.detail == "Session replaced by another login"


def test_replaced_device_socket_is_closed_without_closing_other_devices():
    manager = backend.ConnectionManager()
    old_ws, other_ws = AsyncMock(), AsyncMock()
    manager._connections[7] = {"old-web": old_ws, "phone": other_ws}
    manager._devices["old-web"] = {"device_id": "old-web"}
    manager._devices["phone"] = {"device_id": "phone"}
    manager._usernames[7] = "admin"
    manager.broadcast_online_status = AsyncMock()

    closed = asyncio.run(manager.disconnect_devices(7, {"old-web"}))

    assert closed == 1
    old_ws.close.assert_awaited_once_with(code=4001, reason="session_replaced")
    other_ws.close.assert_not_awaited()
    assert set(manager._connections[7]) == {"phone"}
    manager.broadcast_online_status.assert_awaited_once()


def test_new_web_login_closes_replaced_web_socket(monkeypatch):
    old = SimpleNamespace(device_id="old-web", device_name="Chrome", platform="web",
                          is_active=True, logout_reason=None)
    user = SimpleNamespace(id=7, username="admin", is_admin=True, organization_id=None,
                           onboarding_completed_at=None)
    new = SimpleNamespace(id=99, session_token="new-token")
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = [old]
    db.query.return_value.filter.return_value.update.return_value = 0
    monkeypatch.setattr(backend.AdminService, "authenticate_user", lambda *args, **kwargs: user)
    monkeypatch.setattr(backend.SessionService, "create_session", lambda *args, **kwargs: new)
    monkeypatch.setattr(backend.AuditService, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, "monitor_record_event", lambda *args, **kwargs: None)
    close = AsyncMock(return_value=1)
    monkeypatch.setattr(backend.ws_manager, "disconnect_devices", close)
    login_data = SimpleNamespace(username="admin", token="password", device_id="new-web",
                                 device_name="Chrome QA", platform="web")

    result = asyncio.run(backend.login_user(login_data, db, None))

    assert result["token"] == "new-token"
    assert old.is_active is False
    assert old.logout_reason == "replaced"
    close.assert_awaited_once_with(7, {"old-web"})


def test_idle_socket_closes_after_replacement_in_another_worker(monkeypatch):
    class Query:
        def __init__(self, db, model):
            self.db = db
            self.model = model

        def filter(self, *args):
            return self

        def first(self):
            if self.model is backend.User:
                return SimpleNamespace(id=7, username="admin", is_active=True,
                                       suspended_at=None, is_admin=True)
            self.db.session_reads += 1
            if self.db.session_reads == 1:
                return None  # The active-session check sees the revocation.
            return SimpleNamespace(logout_reason="replaced")

    class DB:
        def __init__(self):
            self.session_reads = 0

        def query(self, model):
            return Query(self, model)

        def close(self):
            pass

    initial_db, check_db = DB(), DB()
    sessions = iter([initial_db, check_db])
    monkeypatch.setattr(backend.db_config, "get_session", lambda: next(sessions))
    monkeypatch.setattr(backend.SessionService, "validate_session",
                        lambda db, token: SimpleNamespace(user_id=7))
    monkeypatch.setattr(backend, "_ws_auth_blocked", lambda token: False)
    monkeypatch.setattr(backend, "_ws_auth_ok", lambda token: None)
    monkeypatch.setattr(backend, "flush_pending_ice", AsyncMock())
    monkeypatch.setattr(backend.ws_manager, "connect", AsyncMock())
    disconnect = AsyncMock()
    monkeypatch.setattr(backend.ws_manager, "disconnect", disconnect)
    monkeypatch.setattr(backend, "WS_SESSION_RECHECK_SECONDS", 0.01)
    async def idle():
        await asyncio.sleep(1)
        return ""
    ws = SimpleNamespace(accept=AsyncMock(), send_text=AsyncMock(), close=AsyncMock(),
                         receive_text=AsyncMock(side_effect=idle))

    asyncio.run(backend.websocket_chat(ws, token="old-token", device_id="old-web", platform="web"))

    ws.close.assert_awaited_once_with(code=4001, reason="session_replaced")
    disconnect.assert_awaited_once_with(ws, 7)
