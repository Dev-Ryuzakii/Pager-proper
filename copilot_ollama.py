"""
Dilarion Copilot — Ollama-backed assistant features.

Every function here shares the same design rule: it only ever sees the exact
text a client explicitly hands it for THIS ONE request — never pulled from
chat history automatically, never stored, never logged in full. A client
decrypts locally and opts in per-call; nothing here changes that. Ollama
runs on localhost on this same VPS — never exposed externally, no network
hop, no third-party API key.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

# Generous but bounded — keeps prompt size (and CPU latency) predictable
# regardless of what a client sends, without silently truncating anything
# reasonable a person would actually paste in.
_MAX_INPUT_CHARS = 16000


async def _ollama_generate(
    system_prompt: str,
    user_prompt: str,
    *,
    json_mode: bool = False,
    timeout: float = 60.0,
) -> Optional[str]:
    """
    Shared low-level Ollama call. Returns the raw text response, or None on
    any failure (unreachable, non-200, timeout) — every caller below treats
    None as "surface a clear try-again error", never as license to guess.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "system": system_prompt,
                    "prompt": user_prompt,
                    "format": "json" if json_mode else "",
                    "stream": False,
                    "options": {"temperature": 0.2},
                },
            )
        if resp.status_code != 200:
            logger.warning(f"[copilot] Ollama returned {resp.status_code}: {resp.text[:200]}")
            return None
        return resp.json().get("response", "")
    except Exception as e:
        # str(e) can be empty for some httpx exceptions — always log the type
        # too, or a failure like that is undiagnosable from the log alone.
        logger.warning(f"[copilot] Ollama call failed: {type(e).__name__}: {e}")
        return None

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


_SUMMARIZE_PROMPT = """You summarize a chat conversation. You will be given the decrypted text of a thread, in chronological order, one message per line.

Write a short summary: 3-6 sentences, or a short bullet list if there are distinct topics. Call out any decisions made or action items mentioned. Do not invent anything not in the text. Respond with ONLY the summary — no preamble like "Here is a summary", no markdown headers."""


async def summarize_thread(text: str) -> Optional[str]:
    """
    Summarizes chat text the client has already decrypted and chosen to
    share for this one request. Returns None on failure.
    """
    trimmed = text.strip()[:_MAX_INPUT_CHARS]
    if not trimmed:
        return None
    result = await _ollama_generate(_SUMMARIZE_PROMPT, trimmed)
    return result.strip() if result else None


_COMPOSE_PROMPT = """You help draft a reply message in a chat. You will be given the message (or situation) being replied to, and optionally an instruction about tone or length.

Produce exactly 3 distinct, short reply options a person could send as-is. Vary them (e.g. one brief, one more detailed, one with a different tone) rather than giving 3 near-identical replies.

Respond with ONLY a JSON array of exactly 3 strings, no other text, no markdown fences. Example: ["Sounds good, see you then!", "Works for me — I'll bring the notes from last time.", "Can we push it 30 minutes? Running a bit behind."]"""


async def compose_reply(context: str, instruction: Optional[str] = None) -> Optional[List[str]]:
    """
    Drafts reply options for a message the client has decrypted and chosen
    to share. `instruction` is an optional free-form steer ("more formal",
    "shorter"). Returns a list of suggestion strings, or None on failure.
    """
    trimmed_context = context.strip()[:_MAX_INPUT_CHARS]
    if not trimmed_context:
        return None
    prompt = f"Message to reply to: {trimmed_context}"
    if instruction and instruction.strip():
        prompt += f"\n\nInstruction: {instruction.strip()[:200]}"
    raw = await _ollama_generate(_COMPOSE_PROMPT, prompt, json_mode=True)
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(f"[copilot] compose_reply got non-JSON response: {raw[:200]!r}")
        return None
    if not isinstance(parsed, list) or not parsed:
        return None
    suggestions = [str(s).strip() for s in parsed if str(s).strip()][:3]
    return suggestions or None


_DOCUMENT_QA_PROMPT = """You answer a question using ONLY the document text provided below. If the answer isn't in the document, say so plainly rather than guessing or using outside knowledge.

Respond with ONLY the answer — no preamble, no repeating the question."""


async def answer_document_question(document_text: str, question: str) -> Optional[str]:
    """
    Answers a question grounded in document text the client has already
    unlocked (master-token revealed) and chosen to share for this one
    question. Returns None on failure.
    """
    trimmed_doc = document_text.strip()[:_MAX_INPUT_CHARS]
    trimmed_q = question.strip()[:500]
    if not trimmed_doc or not trimmed_q:
        return None
    prompt = f"Document:\n{trimmed_doc}\n\nQuestion: {trimmed_q}"
    result = await _ollama_generate(_DOCUMENT_QA_PROMPT, prompt)
    return result.strip() if result else None


_TRANSLATE_PROMPT_TEMPLATE = """You translate text into {language}. Respond with ONLY the translation — no quotes, no explanation, no notes about the source language."""


async def translate_text(text: str, target_language: str) -> Optional[str]:
    """
    Translates text the client has decrypted and chosen to share.
    `target_language` is a free-form name ("French", "Yoruba", "es") — the
    model resolves it, no fixed language list to maintain. Returns None on
    failure.
    """
    trimmed = text.strip()[:_MAX_INPUT_CHARS]
    lang = target_language.strip()[:50]
    if not trimmed or not lang:
        return None
    system_prompt = _TRANSLATE_PROMPT_TEMPLATE.format(language=lang)
    result = await _ollama_generate(system_prompt, trimmed)
    return result.strip() if result else None
