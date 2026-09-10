"""
Realtime service-health monitoring.

Every traced feature (calls, messages, media, meetings, copilot, webhooks,
auth) calls record_event() at its success/failure points. Message
encryption/decryption itself happens on the CLIENT (that's the point of
E2EE — this server never sees plaintext), so those two channels are fed by
clients self-reporting local crypto failures via POST /monitoring/client-event
instead of anything the server can observe directly.

record_event() never blocks or raises into the caller's request path: the DB
write and the realtime WebSocket fan-out both run in a background asyncio
task, and any failure there is logged and swallowed, not propagated.

Access control: superadmin sees every service. An admin/operator only sees
the services superadmin has listed in their `monitored_services` column.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# Canonical set — the client-event endpoint and the admin access-assignment
# endpoint both validate against this so a typo'd service name can't silently
# create an unmonitorable channel.
SERVICE_NAMES: List[str] = [
    "auth",
    "calls",
    "conference",
    "messages",
    "media",
    "meetings",
    "whiteboard",
    "copilot",
    "encryption",
    "decryption",
    "webhooks",
    "devices",
]


def service_allowed(user, service: str) -> bool:
    """True if `user` (a User row, already known to be is_admin) may view `service`."""
    if getattr(user, "admin_role", None) == "superadmin":
        return True
    allowed = getattr(user, "monitored_services", None) or []
    return service in allowed


def record_event(
    service: str,
    event_type: str,
    status: str = "ok",
    detail: Optional[str] = None,
    duration_ms: Optional[int] = None,
    user_id: Optional[int] = None,
) -> None:
    """Fire-and-forget. Safe to call from any async request handler; does
    nothing (just logs) if called with no running event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.debug("record_event(%s.%s) called with no running loop, dropped", service, event_type)
        return
    loop.create_task(_persist_and_broadcast(service, event_type, status, detail, duration_ms, user_id))


async def _persist_and_broadcast(
    service: str,
    event_type: str,
    status: str,
    detail: Optional[str],
    duration_ms: Optional[int],
    user_id: Optional[int],
) -> None:
    from database_models import SessionLocal, ServiceEvent

    event_row = None
    try:
        db = SessionLocal()
        try:
            row = ServiceEvent(
                service=service,
                event_type=event_type,
                status=status,
                detail=(detail or None) and str(detail)[:500],
                duration_ms=duration_ms,
                user_id=user_id,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            event_row = row
        finally:
            db.close()
    except Exception:
        logger.exception("service_monitor: failed to persist event %s.%s", service, event_type)
        return

    payload = {
        "type": "service_event",
        "id": event_row.id,
        "service": service,
        "event_type": event_type,
        "status": status,
        "detail": detail,
        "duration_ms": duration_ms,
        "user_id": user_id,
        "created_at": event_row.created_at.isoformat() if event_row.created_at else None,
    }
    await _broadcast(payload)


# ── Realtime fan-out ────────────────────────────────────────────────────────
# Separate from the main chat ws_manager on purpose: this is a broadcast
# filtered per-subscriber by allowed service set, not a send-to-one-user model.

class _MonitorHub:
    def __init__(self):
        # websocket -> None (all services, superadmin) | Set[str] (allowed services)
        self._subscribers: Dict[WebSocket, Optional[Set[str]]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, websocket: WebSocket, allowed_services: Optional[Set[str]]) -> None:
        async with self._lock:
            self._subscribers[websocket] = allowed_services

    async def unsubscribe(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._subscribers.pop(websocket, None)

    async def broadcast(self, payload: Dict[str, Any]) -> None:
        service = payload.get("service")
        async with self._lock:
            targets = list(self._subscribers.items())
        for ws, allowed in targets:
            if allowed is not None and service not in allowed:
                continue
            try:
                await ws.send_json(payload)
            except Exception:
                await self.unsubscribe(ws)


_hub = _MonitorHub()


async def _broadcast(payload: Dict[str, Any]) -> None:
    await _hub.broadcast(payload)


async def subscribe(websocket: WebSocket, allowed_services: Optional[Set[str]]) -> None:
    await _hub.subscribe(websocket, allowed_services)


async def unsubscribe(websocket: WebSocket) -> None:
    await _hub.unsubscribe(websocket)
