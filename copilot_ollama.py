"""
Dilarion Copilot — natural-language meeting scheduling.

Deliberately the narrowest possible slice: this module never sees message
content, never picks attendees, never touches anything E2EE. It takes one
line of text the user typed directly into a "Ask Copilot" box (not pulled
from any chat) and asks the local Ollama model to turn it into
{title, scheduled_at, duration_minutes} — the exact fields
MeetingCreateRequest expects, so a client can drop the result straight into
the existing "New Meeting" flow's prefill and still requires the user to
review/pick attendees and confirm before anything is actually created.

Ollama runs on localhost on this same VPS — never exposed externally, no
network hop, no third-party API key.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

_SYSTEM_PROMPT = """You extract meeting-scheduling details from a short natural-language request.

You will be given the current date and time, then the user's request. Resolve relative dates ("tomorrow", "next Monday", "in 2 hours") against that current time.

Respond with ONLY a JSON object, no other text, no markdown fences, matching exactly this shape:
{"title": string, "scheduled_at": string, "duration_minutes": integer, "confidence": "high" or "low", "note": string}

Rules:
- "scheduled_at" must be an ISO 8601 date-time (e.g. "2026-09-07T15:00:00"), in the same local time as the current time you were given — no timezone suffix needed.
- Prefer a short, specific title drawn from what the meeting is actually about (e.g. "Dilarion & CGAS progress update") over a generic one — only fall back to "Meeting" or "Call" when the request gives no topic at all.
- If no duration is stated, default duration_minutes to 30.
- If a date is given but no time of day is stated, default to 09:00 (business hours) rather than midnight, set confidence to "low", and say so in "note" (e.g. "No time given — assumed 9:00 AM") so the app can flag it for the user to double-check.
- If the request has no discernible date/time at all, still give your best guess for scheduled_at, but set confidence to "low" and explain briefly in "note".
- If confidence is "high", "note" should be an empty string.
- Never invent attendee names or emails — this only extracts title/time/duration, nothing else.
"""


def _parse_iso(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return value.strip()


async def parse_schedule_text(text: str, current_time_iso: str) -> Optional[Dict[str, Any]]:
    """
    Turns a freeform scheduling request into structured
    {title, scheduled_at, duration_minutes, confidence, note} via the local
    Ollama model. Returns None on any failure (model unreachable, bad JSON,
    unparseable date) — callers should surface a clear "try again or enter
    manually" error rather than guessing at a fallback.
    """
    prompt = f"Current date and time: {current_time_iso}\n\nRequest: {text.strip()}"
    try:
        # 60s, not 30s — qwen2.5:7b on a CPU-shared VPS can occasionally be
        # slow to respond under load (e.g. a concurrent heavy pip
        # install/model download), and a spurious timeout here reads to the
        # user as copilot silently failing rather than just being slow.
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "system": _SYSTEM_PROMPT,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
            )
        if resp.status_code != 200:
            logger.warning(f"[copilot] Ollama returned {resp.status_code}: {resp.text[:200]}")
            return None
        raw = resp.json().get("response", "")
        parsed = json.loads(raw)
    except Exception as e:
        # str(e) can be empty for some httpx exceptions (e.g. a bare
        # ConnectError) — always log the exception type too, or a failure
        # like this one is undiagnosable from the log alone.
        logger.warning(f"[copilot] parse_schedule_text failed: {type(e).__name__}: {e}")
        return None

    scheduled_at = _parse_iso(parsed.get("scheduled_at"))
    if not scheduled_at:
        logger.warning(f"[copilot] model returned unparseable scheduled_at: {parsed.get('scheduled_at')!r}")
        return None

    title = str(parsed.get("title") or "Meeting").strip()[:200] or "Meeting"
    try:
        duration_minutes = max(5, min(480, int(parsed.get("duration_minutes"))))
    except (TypeError, ValueError):
        duration_minutes = 30
    confidence = parsed.get("confidence") if parsed.get("confidence") in ("high", "low") else "low"
    note = str(parsed.get("note") or "").strip()[:300]

    return {
        "title": title,
        "scheduled_at": scheduled_at,
        "duration_minutes": duration_minutes,
        "confidence": confidence,
        "note": note,
    }
