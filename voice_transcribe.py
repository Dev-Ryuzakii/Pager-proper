"""
Voice note transcription.

Uses faster-whisper (CTranslate2 backend) deliberately instead of
openai-whisper: this server already hit a real wall installing PyTorch for
Coqui TTS (see voice_scrambler.py) — CTranslate2 has no such dependency and
is markedly faster on CPU besides.

The backend never has plaintext audio for a real E2EE voice note (only the
ciphertext) — this only ever transcribes audio a client has already
decrypted locally and chosen to upload for this one request, same opt-in,
ephemeral model as the rest of copilot. Nothing here is stored.

Model loads lazily on first use and stays resident — the first
transcription after a restart pays the load cost, every one after is fast.
"""

import logging
import os
import tempfile
from typing import Optional

logger = logging.getLogger(__name__)

WHISPER_MODEL_SIZE = os.getenv("WHISPER_MODEL_SIZE", "base")

_model = None
_model_unavailable = False


def _get_model():
    global _model, _model_unavailable
    if _model_unavailable:
        return None
    if _model is not None:
        return _model
    try:
        from faster_whisper import WhisperModel
        _model = WhisperModel(WHISPER_MODEL_SIZE, device="cpu", compute_type="int8")
        logger.info(f"[transcribe] faster-whisper '{WHISPER_MODEL_SIZE}' loaded")
        return _model
    except Exception as e:
        logger.warning(f"[transcribe] faster-whisper unavailable ({type(e).__name__}: {e}) — pip install faster-whisper to enable")
        _model_unavailable = True
        return None


def transcribe_audio(audio_bytes: bytes, suffix: str = ".m4a") -> Optional[str]:
    """
    Transcribes audio bytes to text, or returns None if the model isn't
    installed/loadable or transcription fails — callers should surface a
    clear "transcription isn't available" error, never a silent blank.

    CPU-bound and synchronous by design — call it via
    loop.run_in_executor() from an async route so a slow transcription
    doesn't block the event loop for other requests.
    """
    model = _get_model()
    if model is None:
        return None
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name
        segments, _info = model.transcribe(tmp_path, beam_size=5)
        text = " ".join(seg.text.strip() for seg in segments).strip()
        return text or None
    except Exception as e:
        logger.warning(f"[transcribe] transcription failed: {type(e).__name__}: {e}")
        return None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
