"""Owner-scoped voice enrollment checks and generated-speech storage.

Inference stays in the existing Chatterbox Nano worker. This module does not
copy VoiceStudio. It only validates recordings and text, keeps files inside the
signed-in user's directory, and removes partial output when generation fails.
"""

import asyncio
import json
import logging
import operator
import os
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from voice_scrambler import _probe_duration, synthesize_cloned_speech

logger = logging.getLogger(__name__)


def voice_concurrency_limit(raw: Optional[str]) -> int:
    try:
        value = int(raw if raw is not None else "1")
    except (TypeError, ValueError):
        return 1
    return value if value > 0 else 1


_VOICE_SEM = None


def voice_semaphore():
    global _VOICE_SEM
    if _VOICE_SEM is None:
        _VOICE_SEM = asyncio.Semaphore(voice_concurrency_limit(os.environ.get("VOICE_CLONE_CONCURRENCY")))
    return _VOICE_SEM


async def acquire_voice(sem) -> bool:
    """False when the cap is full. The caller releases the semaphore."""
    if sem.locked():
        return False
    await sem.acquire()
    return True

MIN_ENROLLMENT_SECONDS = 5.0
MAX_SPEECH_CHARS = 400
MAX_CLIPS_PER_USER = 20
SILENCE_MEAN_DB = -45.0
_CLIP_ID = re.compile(r"^[a-f0-9]{32}$")
_MEAN_VOLUME = re.compile(r"mean_volume:\s*(-?\d+(?:\.\d+)?) dB")

Synthesizer = Callable[[str, str, str], bool]


class VoiceCloneError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class VoiceSpeechRequest(BaseModel):
    text: str = ""


def _http(exc: VoiceCloneError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


def user_directory(upload_dir: str, user_id: int) -> Path:
    """Return media_uploads/user_<id>, rejecting ids that could escape it."""
    if isinstance(user_id, bool):
        raise VoiceCloneError(400, "Invalid account")
    try:
        numeric = operator.index(user_id)
    except TypeError as exc:
        raise VoiceCloneError(400, "Invalid account") from exc
    if numeric < 1:
        raise VoiceCloneError(400, "Invalid account")
    root = Path(upload_dir).resolve()
    folder = (root / f"user_{numeric}").resolve()
    if folder.parent != root:
        raise VoiceCloneError(403, "Voice identity belongs to another user")
    return folder


def _contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def enrollment_problem(source_path: str) -> Optional[str]:
    """Reject audio that cannot be a speaker reference. None means usable."""
    duration = _probe_duration(source_path)
    if duration is None or duration <= 0:
        return "Voice sample is not valid audio"
    if duration < MIN_ENROLLMENT_SECONDS:
        return "Recording is too short. Speak for at least 5 seconds."
    mean_db = _mean_volume_db(source_path)
    if mean_db is None:
        return "Voice sample is not valid audio"
    if mean_db <= SILENCE_MEAN_DB:
        return "Recording is silent. Speak clearly and try again."
    return None


def _mean_volume_db(path: str) -> Optional[float]:
    try:
        result = subprocess.run(
            ["ffmpeg", "-i", path, "-af", "volumedetect", "-f", "null", "-"],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = _MEAN_VOLUME.search(result.stderr.decode(errors="replace"))
    if not match:
        return None
    return float(match.group(1))


def validate_speech_text(text: str) -> str:
    if not isinstance(text, str):
        raise VoiceCloneError(400, "Enter the words to speak")
    cleaned = " ".join(text.split())
    if not cleaned:
        raise VoiceCloneError(400, "Enter the words to speak")
    if len(cleaned) > MAX_SPEECH_CHARS:
        raise VoiceCloneError(400, f"Speech text must be {MAX_SPEECH_CHARS} characters or fewer")
    if any(ord(ch) < 32 for ch in cleaned):
        raise VoiceCloneError(400, "Speech text contains unsupported characters")
    return cleaned


def owned_identity_path(upload_dir: str, user_id: int, stored_path: Optional[str]) -> str:
    """Resolve an enrollment file only when it lives in this user's directory."""
    if not stored_path:
        raise VoiceCloneError(404, "Voice identity not found")
    root = user_directory(upload_dir, user_id)
    try:
        resolved = Path(stored_path).resolve()
    except OSError as exc:
        raise VoiceCloneError(404, "Voice file missing") from exc
    if not _contained(resolved, root):
        raise VoiceCloneError(403, "Voice identity belongs to another user")
    if not resolved.is_file():
        raise VoiceCloneError(404, "Voice file missing")
    return str(resolved)


def _speech_dir(upload_dir: str, user_id: int) -> Path:
    return user_directory(upload_dir, user_id) / "voice_speech"


def _clip_file(upload_dir: str, user_id: int, clip_id: str) -> Path:
    if not _CLIP_ID.fullmatch(clip_id or ""):
        raise VoiceCloneError(404, "Generated speech not found")
    root = user_directory(upload_dir, user_id)
    speech = (root / "voice_speech").resolve()
    audio = (speech / f"{clip_id}.m4a").resolve()
    if audio.parent != speech:
        raise VoiceCloneError(404, "Generated speech not found")
    return audio


def list_owned_clips(upload_dir: str, user_id: int) -> list:
    speech = _speech_dir(upload_dir, user_id)
    if not speech.is_dir():
        return []
    clips = []
    for meta_path in speech.glob("*.json"):
        clip_id = meta_path.stem
        audio = speech / f"{clip_id}.m4a"
        if not _CLIP_ID.fullmatch(clip_id) or not audio.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict):
            continue
        clips.append({
            "id": clip_id,
            "text": str(meta.get("text") or ""),
            "created_at": str(meta.get("created_at") or ""),
        })
    clips.sort(key=lambda item: item["created_at"], reverse=True)
    return clips


def generate_owned_speech(
    upload_dir: str,
    user_id: int,
    reference_path: Optional[str],
    text: str,
    synthesize: Optional[Synthesizer] = None,
) -> dict:
    """Synthesize speech and keep the clip only after the worker succeeds."""
    spoken = validate_speech_text(text)
    try:
        reference = owned_identity_path(upload_dir, user_id, reference_path)
    except VoiceCloneError as exc:
        if exc.status_code in (403, 404):
            raise VoiceCloneError(409, "Enroll a voice sample before generating speech") from exc
        raise
    root = user_directory(upload_dir, user_id)
    speech = root / "voice_speech"
    speech.mkdir(parents=True, exist_ok=True)
    if len(list_owned_clips(upload_dir, user_id)) >= MAX_CLIPS_PER_USER:
        raise VoiceCloneError(409, "Delete a generated clip before creating another")

    clip_id = uuid.uuid4().hex
    final_audio = speech / f"{clip_id}.m4a"
    final_meta = speech / f"{clip_id}.json"
    tmp_audio = speech / f".tmp_{clip_id}.m4a"
    synth = synthesize or synthesize_cloned_speech
    try:
        produced = False
        try:
            produced = bool(synth(reference, str(tmp_audio), spoken))
        except Exception:
            logger.exception("Voice clone synthesis failed")
            produced = False
        if not produced or not tmp_audio.is_file() or tmp_audio.stat().st_size <= 1024:
            raise VoiceCloneError(503, "Voice cloning is unavailable on the server")
        os.replace(tmp_audio, final_audio)
        meta = {
            "id": clip_id,
            "text": spoken,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            final_meta.write_text(json.dumps(meta), encoding="utf-8")
        except OSError as exc:
            final_audio.unlink(missing_ok=True)
            raise VoiceCloneError(503, "Voice cloning is unavailable on the server") from exc
        return meta
    finally:
        tmp_audio.unlink(missing_ok=True)


def delete_owned_clip(upload_dir: str, user_id: int, clip_id: str) -> None:
    audio = _clip_file(upload_dir, user_id, clip_id)
    meta = audio.with_suffix(".json")
    if not audio.is_file():
        raise VoiceCloneError(404, "Generated speech not found")
    audio.unlink(missing_ok=True)
    meta.unlink(missing_ok=True)


def delete_owned_enrollment(upload_dir: str, user_id: int, stored_path: Optional[str]) -> None:
    """Remove this user's sample and generated clips, never a path outside it."""
    root = user_directory(upload_dir, user_id)
    _unlink_inside(root / "voice_identity.wav", root)
    if stored_path:
        _unlink_inside(Path(stored_path), root)
    speech = root / "voice_speech"
    if speech.is_symlink():
        if _contained(speech.parent, root):
            speech.unlink(missing_ok=True)
        return
    if speech.exists() and _contained(speech, root) and speech.resolve() != root.resolve():
        shutil.rmtree(speech, ignore_errors=True)


def _unlink_inside(path: Path, root: Path) -> None:
    try:
        parent = path.parent.resolve()
    except OSError:
        return
    if not _contained(parent, root):
        return
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)


def install_voice_clone_routes(app: FastAPI, get_current_user, get_database_session, upload_dir, synthesize=None):
    """Register the owner speech routes. `upload_dir` is read on each request."""

    @app.get("/users/{username}/voice-identity")
    async def get_user_voice_identity(
        username: str,
        current_user=Depends(get_current_user),
    ):
        """Let a user check or play back only their own voice identity."""
        if current_user.username != username:
            raise HTTPException(status_code=403, detail="Voice identity belongs to another user")
        try:
            path = owned_identity_path(upload_dir(), int(current_user.id), current_user.voice_identity_path)
        except VoiceCloneError as exc:
            _http(exc)
        return FileResponse(path, media_type="audio/wav")

    @app.delete("/users/me/voice-identity")
    async def delete_voice_identity(
        current_user=Depends(get_current_user),
        db=Depends(get_database_session),
    ):
        """Delete the signed-in user's sample and every clip generated from it."""
        try:
            delete_owned_enrollment(upload_dir(), int(current_user.id), current_user.voice_identity_path)
        except VoiceCloneError as exc:
            _http(exc)
        current_user.voice_identity_path = None
        db.commit()
        return {"message": "Voice identity deleted"}

    @app.get("/users/me/voice-speech")
    async def list_voice_speech(current_user=Depends(get_current_user)):
        try:
            clips = list_owned_clips(upload_dir(), int(current_user.id))
        except VoiceCloneError as exc:
            _http(exc)
        return {"clips": clips}

    @app.post("/users/me/voice-speech")
    async def create_voice_speech(
        body: VoiceSpeechRequest,
        current_user=Depends(get_current_user),
    ):
        """Speak text in the signed-in user's enrolled voice."""
        if not await acquire_voice(voice_semaphore()):
            raise HTTPException(status_code=429, detail="Voice generation is busy")
        try:
            try:
                clip = await run_in_threadpool(
                    generate_owned_speech,
                    upload_dir(),
                    int(current_user.id),
                    current_user.voice_identity_path,
                    body.text,
                    synthesize,
                )
            except VoiceCloneError as exc:
                _http(exc)
            return clip
        finally:
            voice_semaphore().release()

    @app.get("/users/me/voice-speech/{clip_id}")
    async def get_voice_speech(clip_id: str, current_user=Depends(get_current_user)):
        try:
            path = _clip_file(upload_dir(), int(current_user.id), clip_id)
        except VoiceCloneError as exc:
            _http(exc)
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Generated speech not found")
        return FileResponse(path, media_type="audio/mp4")

    @app.delete("/users/me/voice-speech/{clip_id}")
    async def delete_voice_speech(clip_id: str, current_user=Depends(get_current_user)):
        try:
            delete_owned_clip(upload_dir(), int(current_user.id), clip_id)
        except VoiceCloneError as exc:
            _http(exc)
        return {"message": "Generated speech deleted"}
