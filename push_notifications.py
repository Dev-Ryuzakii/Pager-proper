"""
APNs push notification sender — HTTP/2 with token-based (p8 key) authentication.

Used as a fallback when a recipient has no active WebSocket connection so
messages and calls still alert the user when the iOS app is killed.

Configuration (environment variables):
    APNS_KEY_PATH     Path to the AuthKey_XXXXXXXXXX.p8 file from Apple
    APNS_KEY_ID       Key ID of the p8 key
    APNS_TEAM_ID      Apple Developer Team ID
    APNS_TOPIC        App bundle id (default: com.dilarion.Dilarion)
    APNS_USE_SANDBOX  "1" for the sandbox gateway (default), "0" for production

If APNS_KEY_PATH / APNS_KEY_ID / APNS_TEAM_ID are not set, pushes are
silently skipped so the backend runs unchanged without Apple credentials.
"""

import logging
import os
import time

import httpx
from jose import jwt

logger = logging.getLogger(__name__)

APNS_KEY_PATH = os.getenv("APNS_KEY_PATH", "")
APNS_KEY_ID = os.getenv("APNS_KEY_ID", "")
APNS_TEAM_ID = os.getenv("APNS_TEAM_ID", "")
APNS_TOPIC = os.getenv("APNS_TOPIC", "com.dilarion.Dilarion")
APNS_USE_SANDBOX = os.getenv("APNS_USE_SANDBOX", "1") == "1"

_APNS_HOST = "https://api.sandbox.push.apple.com" if APNS_USE_SANDBOX else "https://api.push.apple.com"
_JWT_REFRESH_SECONDS = 40 * 60  # APNs accepts tokens 20-60 min old; refresh at 40


class APNsClient:
    def __init__(self):
        self._auth_jwt: str | None = None
        self._jwt_issued_at: float = 0.0
        self._signing_key: str | None = None
        self._http: httpx.AsyncClient | None = None

    @property
    def enabled(self) -> bool:
        return bool(APNS_KEY_PATH and APNS_KEY_ID and APNS_TEAM_ID and os.path.exists(APNS_KEY_PATH))

    def _key(self) -> str:
        if self._signing_key is None:
            with open(APNS_KEY_PATH, "r") as f:
                self._signing_key = f.read()
        return self._signing_key

    def _auth_token(self) -> str:
        now = time.time()
        if self._auth_jwt is None or now - self._jwt_issued_at > _JWT_REFRESH_SECONDS:
            self._auth_jwt = jwt.encode(
                {"iss": APNS_TEAM_ID, "iat": int(now)},
                self._key(),
                algorithm="ES256",
                headers={"kid": APNS_KEY_ID},
            )
            self._jwt_issued_at = now
        return self._auth_jwt

    def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(http2=True, base_url=_APNS_HOST, timeout=10.0)
        return self._http

    async def send(
        self,
        device_token: str,
        title: str,
        body: str,
        sound: str = "beep.caf",
        badge: int = 1,
        thread_id: str | None = None,
    ) -> str:
        """Send one alert push. Returns 'sent', 'invalid_token' or 'error'."""
        if not self.enabled:
            return "error"
        payload = {
            "aps": {
                "alert": {"title": title, "body": body},
                "sound": sound,
                "badge": badge,
            }
        }
        if thread_id:
            payload["aps"]["thread-id"] = thread_id
        headers = {
            "authorization": f"bearer {self._auth_token()}",
            "apns-topic": APNS_TOPIC,
            "apns-push-type": "alert",
            "apns-priority": "10",
        }
        try:
            resp = await self._client().post(f"/3/device/{device_token}", json=payload, headers=headers)
            if resp.status_code == 200:
                return "sent"
            reason = ""
            try:
                reason = resp.json().get("reason", "")
            except Exception:
                pass
            if resp.status_code == 410 or reason in ("BadDeviceToken", "Unregistered", "DeviceTokenNotForTopic"):
                logger.info(f"APNs token invalid ({resp.status_code} {reason}), clearing")
                return "invalid_token"
            logger.warning(f"APNs push failed: {resp.status_code} {reason}")
            return "error"
        except Exception as e:
            logger.warning(f"APNs push error: {e}")
            return "error"


apns_client = APNsClient()


async def push_to_user(db, user_id: int, title: str, body: str, sound: str = "beep.caf") -> bool:
    """
    Send an APNs push to a user's registered device.

    push_token column stores '<platform>:<token>'; only iOS tokens are pushed
    (Android stays connected via its foreground service WebSocket).
    Clears the stored token if APNs reports it invalid.
    """
    if not apns_client.enabled:
        return False
    from database_models import User

    user = db.query(User).filter(User.id == user_id).first()
    stored = getattr(user, "push_token", None) if user else None
    if not stored or not stored.startswith("ios:"):
        return False
    result = await apns_client.send(stored[len("ios:"):], title, body, sound=sound)
    if result == "invalid_token":
        try:
            user.push_token = None
            db.commit()
        except Exception:
            db.rollback()
    return result == "sent"
