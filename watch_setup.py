"""Base1 Watch for the Dilarion backend: error reporting linked to app sessions.

Unhandled exceptions, error-level logs, failing outgoing httpx/requests calls
and slow requests go to Watch. The mobile and desktop Watch SDKs send an
X-Watch-Session header, so the dashboard links an app session replay to the
backend error it caused.

The abw_ ingest key is write-only. Environment variables:
  WATCH_DISABLED=1      turn Watch off (tests, local runs)
  WATCH_ENVIRONMENT     e.g. production / test (default production)
  WATCH_RELEASE         release name (default: current git commit, else the API version)
"""

from __future__ import annotations

import contextvars
import logging
import os
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

WATCH_KEY = "abw_n4RDZ32AuZ7_BpC4TWowBQFM57CitfmJ-XDGooIw-yc"
WATCH_ENDPOINT = "https://api.useafribase.app/watch/ingest"

# Username of the authenticated caller for the current request (hashed by Watch).
current_watch_user: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("current_watch_user", default=None)


def set_watch_user(username: Optional[str]) -> None:
    current_watch_user.set(username)


def _release(default: str) -> str:
    env = os.getenv("WATCH_RELEASE", "").strip()
    if env:
        return env
    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=os.path.dirname(os.path.abspath(__file__)),
                             capture_output=True, text=True, timeout=2).stdout.strip()
        if sha:
            return sha
    except Exception:
        pass
    return default


def install_watch(app, default_release: str) -> bool:
    """Start Watch and add its ASGI middleware. Returns False when off or unavailable."""
    if os.getenv("WATCH_DISABLED", "").strip().lower() in ("1", "true", "yes", "on"):
        logger.info("Base1 Watch disabled by WATCH_DISABLED")
        return False
    try:
        from afribase.watch import init_watch
        from afribase.watch.asgi import WatchMiddleware
    except ImportError:
        logger.warning("Base1 Watch not installed (pip install afribase>=0.4.0); error reporting is off")
        return False
    init_watch(
        WATCH_KEY,
        WATCH_ENDPOINT,
        release=_release(default_release),
        environment=os.getenv("WATCH_ENVIRONMENT", "production").strip() or "production",
        user=current_watch_user.get,
        log_event_level=logging.ERROR,
    )
    app.add_middleware(WatchMiddleware, framework="fastapi")
    logger.info("Base1 Watch error reporting on")
    return True
