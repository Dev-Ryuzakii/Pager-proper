"""
Meeting transcripts, summaries and action items.

Two interchangeable providers per stage, picked by env so the same feature
ships as a free self-hosted tier and a paid hosted tier:

    TRANSCRIBE_PROVIDER = local (default, faster-whisper) | deepgram
    SUMMARY_PROVIDER    = ollama (default, local)         | claude

Free tier: nothing leaves this server. Paid tier: the recording audio (deepgram)
and/or transcript text (claude) go to that third party — the caller (admin
endpoint) records which providers were used on the row so this is auditable.

All functions are synchronous/async-safe building blocks; the endpoint runs
`process_recording` in the background so a long meeting never blocks a request.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

TRANSCRIBE_PROVIDER = os.getenv("TRANSCRIBE_PROVIDER", "local").lower()
SUMMARY_PROVIDER = os.getenv("SUMMARY_PROVIDER", "ollama").lower()

DEEPGRAM_API_KEY = os.getenv("DEEPGRAM_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_SUMMARY_MODEL = os.getenv("CLAUDE_SUMMARY_MODEL", "claude-haiku-5-5")

# Transcript chunk size for the summary map step. Keeps local 7B models
# inside a comfortable context window; Claude just gets fewer, bigger calls.
_CHUNK_CHARS = 12000

_SYSTEM_PROMPT = """You turn a meeting transcript into structured notes.

Respond with ONLY a JSON object, no other text, no markdown fences, exactly:
{"summary": string, "key_points": [string], "decisions": [string], "action_items": [{"task": string, "owner": string, "due": string}]}

Rules:
- Use only what the transcript says. Never invent names, dates, or tasks.
- "owner" and "due" are empty strings when the transcript does not state them.
- "summary" is 2-4 sentences. Keep lists short; omit filler.
- Empty lists are fine if nothing qualifies."""

_MERGE_PROMPT = """You are given several partial JSON meeting notes (in order) from consecutive parts of one meeting.
Merge them into ONE JSON object of the same shape:
{"summary": string, "key_points": [string], "decisions": [string], "action_items": [{"task": string, "owner": string, "due": string}]}
Deduplicate. Write one coherent 2-4 sentence summary. Respond with ONLY the JSON object."""


# ── Transcription ────────────────────────────────────────────────────────────

def _transcribe_local(path: str) -> Optional[str]:
    # Reuses the lazily loaded faster-whisper model from voice notes. PyAV
    # (bundled with faster-whisper) demuxes the mp4's audio track directly.
    from voice_transcribe import _get_model
    model = _get_model()
    if model is None:
        return None
    segments, _info = model.transcribe(path, beam_size=5, vad_filter=True)
    text = " ".join(seg.text.strip() for seg in segments).strip()
    return text or None


def _transcribe_deepgram(path: str) -> Optional[str]:
    if not DEEPGRAM_API_KEY:
        logger.warning("[meeting_ai] TRANSCRIBE_PROVIDER=deepgram but DEEPGRAM_API_KEY is unset")
        return None
    # Streams the file from disk instead of loading a multi-hundred-MB mp4.
    with open(path, "rb") as f:
        resp = httpx.post(
            "https://api.deepgram.com/v1/listen",
            params={"model": "nova-2", "smart_format": "true"},
            headers={"Authorization": f"Token {DEEPGRAM_API_KEY}", "Content-Type": "video/mp4"},
            content=f,
            timeout=httpx.Timeout(600.0, connect=15.0),
        )
    if resp.status_code != 200:
        logger.warning(f"[meeting_ai] Deepgram returned {resp.status_code}: {resp.text[:200]}")
        return None
    try:
        text = resp.json()["results"]["channels"][0]["alternatives"][0]["transcript"]
    except (KeyError, IndexError, ValueError):
        return None
    return text.strip() or None


def transcribe_file(path: str, provider: Optional[str] = None) -> Optional[str]:
    """Blocking (CPU / network heavy). Returns None on any failure."""
    provider = (provider or TRANSCRIBE_PROVIDER).lower()
    try:
        if provider == "deepgram":
            return _transcribe_deepgram(path)
        return _transcribe_local(path)
    except Exception as e:
        logger.warning(f"[meeting_ai] transcribe({provider}) failed: {type(e).__name__}: {e}")
        return None


# ── Summarisation ────────────────────────────────────────────────────────────

async def _llm(system: str, user: str, provider: str) -> Optional[str]:
    try:
        if provider == "claude":
            if not ANTHROPIC_API_KEY:
                logger.warning("[meeting_ai] SUMMARY_PROVIDER=claude but ANTHROPIC_API_KEY is unset")
                return None
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": CLAUDE_SUMMARY_MODEL,
                        "max_tokens": 2000,
                        "temperature": 0.2,
                        "system": system,
                        "messages": [{"role": "user", "content": user}],
                    },
                )
            if resp.status_code != 200:
                logger.warning(f"[meeting_ai] Claude returned {resp.status_code}: {resp.text[:200]}")
                return None
            return "".join(b.get("text", "") for b in resp.json().get("content", []))

        from copilot_ollama import _ollama_generate
        return await _ollama_generate(system, user, json_mode=True, timeout=180.0)
    except Exception as e:
        logger.warning(f"[meeting_ai] llm({provider}) failed: {type(e).__name__}: {e}")
        return None


def _parse_notes(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    """Validates/normalises model output; None if it isn't usable JSON."""
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw[raw.find("{"):] if "{" in raw else raw
    try:
        data = json.loads(raw)
    except ValueError:
        start, end = raw.find("{"), raw.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            data = json.loads(raw[start:end + 1])
        except ValueError:
            return None
    if not isinstance(data, dict):
        return None

    def strs(v: Any) -> List[str]:
        return [str(x).strip() for x in v if str(x).strip()] if isinstance(v, list) else []

    items = []
    for it in data.get("action_items") or []:
        if isinstance(it, dict) and str(it.get("task", "")).strip():
            items.append({
                "task": str(it["task"]).strip(),
                "owner": str(it.get("owner", "") or "").strip(),
                "due": str(it.get("due", "") or "").strip(),
            })
    return {
        "summary": str(data.get("summary", "") or "").strip(),
        "key_points": strs(data.get("key_points")),
        "decisions": strs(data.get("decisions")),
        "action_items": items,
    }


def _chunks(text: str, size: int = _CHUNK_CHARS) -> List[str]:
    """Split on whitespace near the size boundary so words aren't cut."""
    out, i = [], 0
    while i < len(text):
        j = min(i + size, len(text))
        if j < len(text):
            k = text.rfind(" ", i, j)
            if k > i:
                j = k
        out.append(text[i:j].strip())
        i = j
    return [c for c in out if c]


async def summarize_transcript(transcript: str, provider: Optional[str] = None) -> Optional[Dict[str, Any]]:
    provider = (provider or SUMMARY_PROVIDER).lower()
    parts = _chunks(transcript)
    if not parts:
        return None
    notes: List[Dict[str, Any]] = []
    for part in parts:
        n = _parse_notes(await _llm(_SYSTEM_PROMPT, f"Transcript:\n{part}", provider))
        if n is None:
            return None
        notes.append(n)
    if len(notes) == 1:
        return notes[0]
    merged = _parse_notes(await _llm(_MERGE_PROMPT, json.dumps(notes), provider))
    return merged


# ── Pipeline ─────────────────────────────────────────────────────────────────

async def process_file(path: str) -> Dict[str, Any]:
    """
    Transcribe then summarise one recording. Always returns a dict:
    {"status": "done"|"failed", "error"?, "transcript"?, "notes"?,
     "transcribe_provider", "summary_provider"}
    """
    import asyncio
    result: Dict[str, Any] = {
        "transcribe_provider": TRANSCRIBE_PROVIDER,
        "summary_provider": SUMMARY_PROVIDER,
    }
    if not os.path.exists(path):
        return {**result, "status": "failed", "error": "Recording file not found"}

    loop = asyncio.get_running_loop()
    transcript = await loop.run_in_executor(None, transcribe_file, path)
    if not transcript:
        return {**result, "status": "failed", "error": "Transcription failed or no speech detected"}
    result["transcript"] = transcript

    notes = await summarize_transcript(transcript)
    if notes is None:
        return {**result, "status": "failed", "error": "Summary failed (transcript saved)"}
    return {**result, "status": "done", "notes": notes}
