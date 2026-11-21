"""Sign-in approval: a new device has to be approved before it gets a session.

A correct password on a new device no longer signs the account out anywhere.
If the account is already signed in on another device, the new device gets a
pending sign-in request instead of a session, and the account owner is asked
"Is this you?" on every signed-in device (live over the WebSocket, by push and
by email), with the device name, location, IP address and time.

The new device gets in when one of these happens before the request expires:
  * someone taps "Yes, it's me" on an already signed-in device,
  * the owner presses Approve on the page linked from the email,
  * the new device enters the account's master token (and the master-token
    2FA password when that is turned on).

A denied, expired or locked request never yields a session. Accounts with no
other signed-in device sign in straight away, and still get a "new sign-in"
email whose link signs that device out again if it wasn't them.

Secrets: the new device holds a random request token, the email holds a
separate random link token; only their SHA-256 hashes are stored.

Routes (installed by `install_login_approval_routes`):
    POST /auth/login-requests/status          new device polls {request_token}
    POST /auth/login-requests/master-token    new device approves itself
    POST /auth/login-requests/cancel          new device gives up
    GET  /auth/login-requests/pending         signed-in device catches up
    POST /auth/login-requests/{id}/decision   signed-in device: {approve}
    GET  /auth/login-requests/email/{token}   confirmation page (no change on GET)
    POST /auth/login-requests/email/{token}   approve / deny / sign out from email

WebSocket events to the account's signed-in devices:
    login_approval_request   {request_id, device_name, platform, location, ip, time, expires_at}
    login_approval_resolved  {request_id, status}
"""

import asyncio
import hashlib
import hmac
import html
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import Session

from database_models import Base, User, UserSession

logger = logging.getLogger(__name__)

REQUEST_TTL = timedelta(minutes=10)
MAX_PENDING_PER_USER = 5
MAX_MASTER_TOKEN_ATTEMPTS = 5

PENDING = "pending"
APPROVED = "approved"      # approved, session not collected yet
COMPLETED = "completed"    # session handed to the new device
DENIED = "denied"
EXPIRED = "expired"
CANCELLED = "cancelled"
AUTO = "auto"              # no approval needed (no other signed-in device)
SIGNED_OUT = "signed_out"  # owner used the email link to sign an auto login out


def naive_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_z(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat() + "Z"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class LoginRequest(Base):
    __tablename__ = "login_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    request_token_hash = Column(String(64), nullable=False, unique=True, index=True)
    email_token_hash = Column(String(64), nullable=True, unique=True, index=True)
    status = Column(String(20), nullable=False, default=PENDING)
    device_id = Column(String(128), nullable=True)
    device_name = Column(String(120), nullable=True)
    platform = Column(String(20), nullable=True)
    ip_address = Column(String(64), nullable=True)
    location = Column(String(200), nullable=True)
    created_at = Column(DateTime, nullable=False, default=naive_utc)
    expires_at = Column(DateTime, nullable=False)
    decided_at = Column(DateTime, nullable=True)
    # device | email | master_token | auto
    decided_via = Column(String(20), nullable=True)
    decided_by_session_id = Column(Integer, nullable=True)
    master_token_attempts = Column(Integer, nullable=False, default=0)
    # The session given to the new device (auto logins and completed ones).
    session_id = Column(Integer, nullable=True)
    email_sent = Column(Boolean, nullable=False, default=False)


def _expired(row: LoginRequest) -> bool:
    exp = row.expires_at
    if exp is not None and exp.tzinfo is not None:
        exp = exp.astimezone(timezone.utc).replace(tzinfo=None)
    return exp is None or exp <= naive_utc()


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def other_signed_in_sessions(db: Session, user_id: int, device_id: Optional[str]) -> List[UserSession]:
    """Live app sessions on a device other than this one (portal/admin logins don't count)."""
    now = datetime.now(timezone.utc)
    rows = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.is_active == True,
        UserSession.session_type == "mobile",
    ).all()
    out = []
    for row in rows:
        exp = _aware(row.expires_at)
        if exp is not None and exp <= now:
            continue
        if device_id and row.device_id == device_id:
            continue
        out.append(row)
    return out


def request_json(row: LoginRequest) -> Dict[str, Any]:
    return {
        "request_id": int(row.id),
        "device_name": row.device_name or (row.platform or "Unknown device").capitalize(),
        "platform": row.platform,
        "location": row.location or "Unknown location",
        "ip": row.ip_address or "unknown",
        "time": iso_z(row.created_at),
        "expires_at": iso_z(row.expires_at),
    }


def time_display(dt: datetime) -> str:
    return _aware(dt).strftime("%d %b %Y, %H:%M UTC")


class StatusBody(BaseModel):
    request_token: str = Field(..., min_length=20, max_length=200)


class MasterTokenBody(BaseModel):
    request_token: str = Field(..., min_length=20, max_length=200)
    master_token: str = Field(..., min_length=1, max_length=500)
    two_fa_password: Optional[str] = Field(None, max_length=500)


class DecisionBody(BaseModel):
    approve: bool


def install_login_approval_routes(
    app: FastAPI,
    *,
    get_current_user,
    get_current_session: Callable[..., Any],
    get_database_session,
    finish_login: Callable[[Session, User, LoginRequest], Awaitable[Dict[str, Any]]],
    send_to_user: Callable[[int, dict], Awaitable[Any]],
    push_to_user: Callable[[Session, int, str, str], Awaitable[Any]],
    send_email: Callable[[str, str, str, str], Awaitable[Any]],
    email_template: Callable[..., str],
    validate_master_token: Callable[[Session, int, str], bool],
    check_two_fa: Callable[[User, str], bool],
    revoke_session: Callable[[Session, int, int], Awaitable[Any]],
    audit: Callable[[Session, int, str, str], Any],
    public_base_url: Callable[[Optional[Request]], str],
):
    """
    finish_login(db, user, request) -> the normal /auth/login response, with a
        fresh session for the request's device (sets request.session_id).
    get_current_session(...) -> FastAPI dependency giving the caller's UserSession.
    check_two_fa(user, password) -> bool; only called when 2FA is enabled.
    revoke_session(db, user_id, session_id) -> sign that session out everywhere.
    """

    async def notify_resolved(user_id: int, row: LoginRequest) -> None:
        try:
            await send_to_user(user_id, {"type": "login_approval_resolved",
                                         "data": {"request_id": int(row.id), "status": row.status}})
        except Exception:
            pass

    def by_request_token(db: Session, token: str) -> LoginRequest:
        row = db.query(LoginRequest).filter(LoginRequest.request_token_hash == _hash(token)).first()
        if not row:
            raise HTTPException(status_code=404, detail="Sign-in request not found")
        if row.status == PENDING and _expired(row):
            row.status = EXPIRED
            db.commit()
        return row

    async def decide(db: Session, row: LoginRequest, approve: bool, via: str, session_id: Optional[int] = None) -> None:
        row.status = APPROVED if approve else DENIED
        row.decided_at = naive_utc()
        row.decided_via = via
        row.decided_by_session_id = session_id
        db.commit()
        audit(db, int(row.user_id), "login_request_approved" if approve else "login_request_denied",
              f"Sign-in on {row.device_name or row.platform or 'a new device'} from "
              f"{row.location or 'unknown location'} ({row.ip_address or 'unknown IP'}) "
              f"{'approved' if approve else 'denied'} via {via}")
        await notify_resolved(int(row.user_id), row)

    # ── New device ────────────────────────────────────────────────────────

    @app.post("/auth/login-requests/status")
    async def login_request_status(body: StatusBody, db: Session = Depends(get_database_session)):
        row = by_request_token(db, body.request_token)
        user = db.query(User).filter(User.id == row.user_id).first()
        base = {
            "status": row.status,
            "expires_at": iso_z(row.expires_at),
            "two_fa_required": bool(getattr(user, "mastertoken_2fa_enabled", False)),
        }
        if row.status == APPROVED and user is not None:
            # Hand the session over exactly once.
            response = await finish_login(db, user, row)
            row.status = COMPLETED
            db.commit()
            return {**base, "status": COMPLETED, "login": response}
        if row.status == COMPLETED:
            raise HTTPException(status_code=409, detail="This sign-in was already completed")
        return base

    @app.post("/auth/login-requests/master-token")
    async def login_request_master_token(body: MasterTokenBody, db: Session = Depends(get_database_session)):
        row = by_request_token(db, body.request_token)
        if row.status != PENDING:
            raise HTTPException(status_code=409, detail="This sign-in request is no longer waiting")
        user = db.query(User).filter(User.id == row.user_id).first()
        if user is None:
            raise HTTPException(status_code=404, detail="Sign-in request not found")
        ok = validate_master_token(db, int(user.id), body.master_token.strip())
        if ok and getattr(user, "mastertoken_2fa_enabled", False):
            ok = bool(body.two_fa_password) and check_two_fa(user, body.two_fa_password or "")
        if not ok:
            row.master_token_attempts = int(row.master_token_attempts or 0) + 1
            if row.master_token_attempts >= MAX_MASTER_TOKEN_ATTEMPTS:
                await decide(db, row, False, "master_token")
                raise HTTPException(status_code=403, detail="Too many wrong attempts. Start the sign-in again.")
            db.commit()
            raise HTTPException(status_code=401, detail="Wrong master token or 2FA password")
        await decide(db, row, True, "master_token")
        response = await finish_login(db, user, row)
        row.status = COMPLETED
        db.commit()
        return {"status": COMPLETED, "login": response}

    @app.post("/auth/login-requests/cancel")
    async def login_request_cancel(body: StatusBody, db: Session = Depends(get_database_session)):
        row = by_request_token(db, body.request_token)
        if row.status == PENDING:
            row.status = CANCELLED
            row.decided_at = naive_utc()
            db.commit()
            await notify_resolved(int(row.user_id), row)
        return {"status": row.status}

    # ── Signed-in devices ─────────────────────────────────────────────────

    @app.get("/auth/login-requests/pending")
    async def login_requests_pending(current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        rows = db.query(LoginRequest).filter(
            LoginRequest.user_id == int(current_user.id),
            LoginRequest.status == PENDING,
        ).order_by(LoginRequest.id.desc()).all()
        return {"requests": [request_json(r) for r in rows if not _expired(r)]}

    @app.post("/auth/login-requests/{request_id}/decision")
    async def login_request_decision(
        request_id: int,
        body: DecisionBody,
        current_user=Depends(get_current_user),
        current_session=Depends(get_current_session),
        db: Session = Depends(get_database_session),
    ):
        row = db.query(LoginRequest).filter(
            LoginRequest.id == request_id, LoginRequest.user_id == int(current_user.id),
        ).first()
        if not row:
            raise HTTPException(status_code=404, detail="Sign-in request not found")
        if row.status == PENDING and _expired(row):
            row.status = EXPIRED
            db.commit()
        if row.status != PENDING:
            return {"status": row.status}
        await decide(db, row, body.approve, "device", getattr(current_session, "id", None))
        if not body.approve:
            await alert_denied(db, current_user, row)
        return {"status": row.status}

    # ── Email link ────────────────────────────────────────────────────────

    def by_email_token(db: Session, token: str) -> LoginRequest:
        row = db.query(LoginRequest).filter(LoginRequest.email_token_hash == _hash(token)).first()
        if not row:
            raise HTTPException(status_code=404, detail="This link is not valid")
        if row.status == PENDING and _expired(row):
            row.status = EXPIRED
            db.commit()
        return row

    @app.get("/auth/login-requests/email/{token}", response_class=HTMLResponse)
    async def login_request_email_page(token: str, db: Session = Depends(get_database_session)):
        # GET never changes anything: mail scanners open links on their own.
        try:
            row = by_email_token(db, token)
        except HTTPException:
            return HTMLResponse(_page("Link not valid", "This sign-in link is not valid or has been replaced."), status_code=404)
        return HTMLResponse(_email_page(row, token))

    @app.post("/auth/login-requests/email/{token}", response_class=HTMLResponse)
    async def login_request_email_action(token: str, action: str = Form(...), db: Session = Depends(get_database_session)):
        try:
            row = by_email_token(db, token)
        except HTTPException:
            return HTMLResponse(_page("Link not valid", "This sign-in link is not valid or has been replaced."), status_code=404)
        user = db.query(User).filter(User.id == row.user_id).first()
        if row.status == AUTO and action == "signout":
            if row.session_id:
                await revoke_session(db, int(row.user_id), int(row.session_id))
            row.status = SIGNED_OUT
            row.decided_at = naive_utc()
            row.decided_via = "email"
            db.commit()
            audit(db, int(row.user_id), "login_signed_out_from_email",
                  f"Owner signed out {row.device_name or 'a device'} from the new-sign-in email")
            return HTMLResponse(_page("Device signed out",
                                      "That device has been signed out. Change your login password now and tell your administrator."))
        if row.status != PENDING:
            return HTMLResponse(_email_page(row, token))
        if action not in ("approve", "deny"):
            raise HTTPException(status_code=400, detail="Unknown action")
        await decide(db, row, action == "approve", "email")
        if action == "deny" and user is not None:
            await alert_denied(db, user, row)
            return HTMLResponse(_page("Sign-in blocked",
                                      "We blocked that sign-in. If you didn't try to sign in, change your login password now and tell your administrator."))
        return HTMLResponse(_page("Sign-in approved", "The new device will finish signing in by itself in a few seconds."))

    async def alert_denied(db: Session, user, row: LoginRequest) -> None:
        try:
            await push_to_user(db, int(user.id), "Sign-in blocked",
                               f"You blocked a sign-in on {row.device_name or 'a new device'}.")
        except Exception:
            pass

    # ── Public helpers used by /auth/login ────────────────────────────────

    async def start_request(db: Session, user: User, *, device_id, device_name, platform, ip, location,
                            request: Optional[Request]) -> Dict[str, Any]:
        """Create (or reuse) a pending request and tell the owner. Returns the 202 body."""
        user_id = int(user.id)
        now = naive_utc()
        pending = [r for r in db.query(LoginRequest).filter(
            LoginRequest.user_id == user_id, LoginRequest.status == PENDING,
        ).all() if not _expired(r)]
        if len(pending) >= MAX_PENDING_PER_USER:
            raise HTTPException(status_code=429, detail="Too many sign-in requests are waiting. Try again in a few minutes.")
        request_token = secrets.token_urlsafe(32)
        email_token = secrets.token_urlsafe(32)
        row = LoginRequest(
            user_id=user_id,
            request_token_hash=_hash(request_token),
            email_token_hash=_hash(email_token),
            status=PENDING,
            device_id=device_id,
            device_name=device_name,
            platform=platform,
            ip_address=ip,
            location=location,
            created_at=now,
            expires_at=now + REQUEST_TTL,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        audit(db, user_id, "login_request_created",
              f"Sign-in on {device_name or platform or 'a new device'} from {location or 'unknown location'} "
              f"({ip or 'unknown IP'}) is waiting for approval")

        info = request_json(row)
        try:
            await send_to_user(user_id, {"type": "login_approval_request", "data": info})
        except Exception:
            logger.warning("login approval push over WS failed")
        try:
            await push_to_user(db, user_id, "Is this you signing in?",
                               f"{info['device_name']} · {info['location']}. Open Dilarion to approve or block it.")
        except Exception:
            pass
        if getattr(user, "email", None):
            link = f"{public_base_url(request)}/auth/login-requests/email/{email_token}"
            # Don't make the new device wait on SMTP.
            asyncio.create_task(email_request(user, row, link))
            row.email_sent = True
            db.commit()
        return {
            "status": "approval_required",
            "request_token": request_token,
            "request_id": int(row.id),
            "expires_at": iso_z(row.expires_at),
            "device_name": info["device_name"],
            "location": info["location"],
            "email_sent": bool(row.email_sent),
            "two_fa_required": bool(getattr(user, "mastertoken_2fa_enabled", False)),
        }

    async def record_auto_login(db: Session, user: User, session_id: int, *, device_id, device_name, platform,
                                ip, location, request: Optional[Request], email: bool) -> None:
        """Log a sign-in that needed no approval and send the new-sign-in email."""
        now = naive_utc()
        email_token = secrets.token_urlsafe(32)
        row = LoginRequest(
            user_id=int(user.id),
            request_token_hash=_hash(secrets.token_urlsafe(32)),
            email_token_hash=_hash(email_token),
            status=AUTO, decided_via="auto", decided_at=now,
            device_id=device_id, device_name=device_name, platform=platform,
            ip_address=ip, location=location, created_at=now,
            # The "wasn't me" link keeps working for a week.
            expires_at=now + timedelta(days=7),
            session_id=session_id,
        )
        db.add(row)
        db.commit()
        if email and getattr(user, "email", None):
            link = f"{public_base_url(request)}/auth/login-requests/email/{email_token}"
            asyncio.create_task(email_new_login(user, row, link))
            row.email_sent = True
            db.commit()

    def details(row: LoginRequest) -> List[tuple]:
        return [
            ("Device", row.device_name or (row.platform or "Unknown").capitalize()),
            ("Platform", (row.platform or "unknown").capitalize()),
            ("Location", row.location or "Unknown location"),
            ("IP address", row.ip_address or "unknown"),
            ("Time", time_display(row.created_at)),
        ]

    async def email_request(user, row: LoginRequest, link: str) -> None:
        name = getattr(user, "full_name", None) or user.username
        paragraphs = [
            "Someone entered your Dilarion password on a new device. Your other devices stay signed in; "
            "this device can only get in after you approve it.",
            "If it was you, approve it here or on any device where you're already signed in. "
            "If it wasn't you, block it and change your password.",
        ]
        text = (f"Dear {name},\n\n" + "\n\n".join(paragraphs) + "\n\n"
                + "\n".join(f"{k}: {v}" for k, v in details(row))
                + f"\n\nApprove or block: {link}\n\nThis link expires in 10 minutes.\n\nThe Dilarion Team")
        try:
            await send_email(user.email, "Is this you signing in to Dilarion?", text,
                             email_template("New sign-in request", f"Dear {name},", paragraphs,
                                            cta_label="Approve or block", cta_url=link,
                                            details=details(row), eyebrow="Security",
                                            after=["This link expires in 10 minutes."]))
        except Exception:
            logger.exception("sign-in request email failed")

    async def email_new_login(user, row: LoginRequest, link: str) -> None:
        name = getattr(user, "full_name", None) or user.username
        paragraphs = [
            "Your Dilarion account was just signed in on a device that hasn't been used before.",
            "If this was you, there's nothing to do. If it wasn't, sign that device out right away and change your password.",
        ]
        text = (f"Dear {name},\n\n" + "\n\n".join(paragraphs) + "\n\n"
                + "\n".join(f"{k}: {v}" for k, v in details(row))
                + f"\n\nWasn't you? Sign it out: {link}\n\nThe Dilarion Team")
        try:
            await send_email(user.email, "New sign-in to your Dilarion account", text,
                             email_template("New sign-in", f"Dear {name},", paragraphs,
                                            cta_label="Wasn't me, sign it out", cta_url=link,
                                            details=details(row), eyebrow="Security"))
        except Exception:
            logger.exception("new sign-in email failed")

    def _email_page(row: LoginRequest, token: str) -> str:
        rows = "".join(
            f"<tr><td style='color:#8a7f7d;padding:4px 14px 4px 0'>{html.escape(k)}</td>"
            f"<td style='padding:4px 0'>{html.escape(str(v))}</td></tr>" for k, v in details(row)
        )
        action_url = f"/auth/login-requests/email/{html.escape(token)}"
        if row.status == PENDING:
            body = (f"<p>Someone is trying to sign in to your account.</p><table>{rows}</table>"
                    f"<form method='post' action='{action_url}' style='margin-top:22px;display:flex;gap:10px'>"
                    "<button name='action' value='approve' style='" + _btn('#c0392b') + "'>Yes, it's me</button>"
                    "<button name='action' value='deny' style='" + _btn('#3a2c2b') + "'>No, block it</button></form>")
            return _page("Is this you?", body, raw=True)
        if row.status == AUTO:
            body = (f"<p>This device signed in to your account.</p><table>{rows}</table>"
                    f"<form method='post' action='{action_url}' style='margin-top:22px'>"
                    "<button name='action' value='signout' style='" + _btn('#c0392b') + "'>Wasn't me, sign it out</button></form>")
            return _page("New sign-in", body, raw=True)
        label = {
            APPROVED: "This sign-in was approved.", COMPLETED: "This sign-in was approved.",
            DENIED: "This sign-in was blocked.", EXPIRED: "This sign-in request expired.",
            CANCELLED: "This sign-in was cancelled on the new device.",
            SIGNED_OUT: "That device was signed out.",
        }.get(row.status, "This request is closed.")
        return _page("Sign-in request", f"<p>{label}</p><table>{rows}</table>", raw=True)

    return start_request, record_auto_login


def _btn(bg: str) -> str:
    return (f"background:{bg};color:#fff;border:0;border-radius:10px;padding:12px 18px;"
            "font-weight:700;font-size:15px;cursor:pointer")


def _page(title: str, body: str, raw: bool = False) -> str:
    content = body if raw else f"<p>{html.escape(body)}</p>"
    return (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)} · Dilarion</title></head>"
        "<body style='margin:0;background:#0d0a0a;color:#f6f1f0;font-family:-apple-system,Segoe UI,Roboto,sans-serif'>"
        "<div style='max-width:480px;margin:48px auto;padding:28px 24px;background:#171212;border:1px solid #2e2424;border-radius:18px'>"
        f"<div style='color:#ff9b91;font-size:12px;font-weight:800;letter-spacing:.1em;text-transform:uppercase'>Dilarion security</div>"
        f"<h1 style='font-size:22px;margin:8px 0 14px'>{html.escape(title)}</h1>{content}</div></body></html>"
    )


# ── Location from IP (offline) ────────────────────────────────────────────────

_GEO_READER = None
_GEO_TRIED = False


def locate_ip(ip: Optional[str]) -> Optional[str]:
    """
    "City, Region, Country" for an IP from a local GeoLite2 City database, so
    no IP leaves the server. Path from GEOIP_DB_PATH (default
    ./GeoLite2-City.mmdb). Returns None when the database or the package is
    missing, or for private addresses.
    """
    global _GEO_READER, _GEO_TRIED
    if not ip:
        return None
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return None
    except ValueError:
        return None
    if not _GEO_TRIED:
        _GEO_TRIED = True
        path = os.getenv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")
        try:
            import geoip2.database
            if os.path.exists(path):
                _GEO_READER = geoip2.database.Reader(path)
            else:
                logger.warning("GeoLite2 database not found at %s; sign-in locations will be unknown", path)
        except ImportError:
            logger.warning("geoip2 is not installed; sign-in locations will be unknown")
    if _GEO_READER is None:
        return None
    try:
        r = _GEO_READER.city(ip)
    except Exception:
        return None
    parts: List[str] = []
    for part in (r.city.name, r.subdivisions.most_specific.name if r.subdivisions else None, r.country.name):
        if part and part not in parts:
            parts.append(part)
    return ", ".join(parts) or None


def two_fa_matches(user, password: str) -> bool:
    """Same scheme as the master-token 2FA endpoints: sha256(password + salt)."""
    salt = str(getattr(user, "mastertoken_2fa_salt", "") or "")
    stored = str(getattr(user, "mastertoken_2fa_hash", "") or "")
    if not salt or not stored:
        return False
    return hmac.compare_digest(hashlib.sha256((password + salt).encode()).hexdigest(), stored)
