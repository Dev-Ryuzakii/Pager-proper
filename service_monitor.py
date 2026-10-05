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

Access control: superadmin sees every service. An admin/operator also sees
every service until a superadmin narrows them via the `monitored_services`
column — NULL means "never restricted" (default: all), while an explicitly
saved list (including an empty one) is a deliberate restriction.

Organization: every event is attributed to a tenant — the caller may pass
`organization_id` directly, otherwise it is resolved from the acting user when
the event is written. Readers may scope to one organization, and the realtime
fan-out honors the same scope per subscriber.
"""

import asyncio
import logging
from dataclasses import dataclass
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
    # Fed by the uptime checker's own scheduler rather than request handlers —
    # a target going down or recovering appears in the same feed.
    "uptime",
]


def allowed_service_names(user) -> Optional[Set[str]]:
    """The services `user` may view, or None meaning every service.

    None is returned for a superadmin, and for an admin/operator who has
    never been restricted (`monitored_services` is NULL) — monitoring is
    visible by default and a superadmin narrows it, rather than every new
    admin starting out unable to see anything. An explicitly saved list is
    honored as-is, so an empty list really does mean "no channels".
    """
    if getattr(user, "admin_role", None) == "superadmin":
        return None
    configured = getattr(user, "monitored_services", None)
    if configured is None:
        return None
    return set(configured)


def service_allowed(user, service: str) -> bool:
    """True if `user` (a User row, already known to be is_admin) may view `service`."""
    allowed = allowed_service_names(user)
    return allowed is None or service in allowed


def record_event(
    service: str,
    event_type: str,
    status: str = "ok",
    detail: Optional[str] = None,
    duration_ms: Optional[int] = None,
    user_id: Optional[int] = None,
    organization_id: Optional[int] = None,
) -> None:
    """Fire-and-forget. Safe to call from any async request handler; does
    nothing (just logs) if called with no running event loop.

    `organization_id` is optional — pass it when the call site already knows
    the tenant; otherwise it is resolved from the user inside the background
    task, so no existing call site had to change."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.debug("record_event(%s.%s) called with no running loop, dropped", service, event_type)
        return
    loop.create_task(
        _persist_and_broadcast(service, event_type, status, detail, duration_ms, user_id, organization_id)
    )


def _resolve_organization_id(db, user_id: Optional[int], organization_id: Optional[int]) -> Optional[int]:
    """The tenant an event belongs to: whatever the caller passed, else the
    acting user's organization. Runs on the background task's own session."""
    if organization_id is not None:
        return organization_id
    if user_id is None:
        return None
    try:
        from database_models import User

        return db.query(User.organization_id).filter(User.id == user_id).scalar()
    except Exception:
        # Attribution is best-effort; an event must still be recorded without it.
        logger.exception("service_monitor: could not resolve organization for user_id=%s", user_id)
        return None


async def _persist_and_broadcast(
    service: str,
    event_type: str,
    status: str,
    detail: Optional[str],
    duration_ms: Optional[int],
    user_id: Optional[int],
    organization_id: Optional[int] = None,
) -> None:
    from database_models import SessionLocal, ServiceEvent

    event_row = None
    try:
        db = SessionLocal()
        try:
            resolved_org_id = _resolve_organization_id(db, user_id, organization_id)
            row = ServiceEvent(
                service=service,
                event_type=event_type,
                status=status,
                detail=(detail or None) and str(detail)[:500],
                duration_ms=duration_ms,
                user_id=user_id,
                organization_id=resolved_org_id,
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
        "organization_id": event_row.organization_id,
        "created_at": event_row.created_at.isoformat() if event_row.created_at else None,
    }
    await _broadcast(payload)


# ── Realtime fan-out ────────────────────────────────────────────────────────
# Separate from the main chat ws_manager on purpose: this is a broadcast
# filtered per-subscriber by allowed service set, not a send-to-one-user model.

@dataclass(frozen=True)
class MonitorFilter:
    """What one subscriber may see. `services` is None for "every channel";
    `organization_id` is None for "every organization"."""
    services: Optional[Set[str]] = None
    organization_id: Optional[int] = None


class _MonitorHub:
    def __init__(self):
        self._subscribers: Dict[WebSocket, MonitorFilter] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, websocket: WebSocket, filter_: MonitorFilter) -> None:
        async with self._lock:
            self._subscribers[websocket] = filter_

    async def unsubscribe(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._subscribers.pop(websocket, None)

    async def broadcast(self, payload: Dict[str, Any]) -> None:
        service = payload.get("service")
        organization_id = payload.get("organization_id")
        async with self._lock:
            targets = list(self._subscribers.items())
        for ws, sub in targets:
            if sub.services is not None and service not in sub.services:
                continue
            # A subscriber scoped to one tenant must not receive another's
            # events — including platform-wide events that carry no tenant.
            if sub.organization_id is not None and organization_id != sub.organization_id:
                continue
            try:
                await ws.send_json(payload)
            except Exception:
                await self.unsubscribe(ws)


_hub = _MonitorHub()


async def _broadcast(payload: Dict[str, Any]) -> None:
    await _hub.broadcast(payload)


async def subscribe(websocket: WebSocket, filter_: MonitorFilter) -> None:
    await _hub.subscribe(websocket, filter_)


async def unsubscribe(websocket: WebSocket) -> None:
    await _hub.unsubscribe(websocket)
