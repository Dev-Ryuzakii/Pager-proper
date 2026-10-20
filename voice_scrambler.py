"""
Voice decoy generator using Chatterbox Nano.

The enrollment recording is only a speaker reference. Never return or remix
its audio as a decoy; if synthesis is unavailable, report failure.

Two properties matter as much as the audio itself:

  * Determinism. The same voice note must always produce the same decoy. A note
    that says something different on each replay is an obvious tell.
  * Duration. Phrases are chosen to roughly fill the requested length.
"""

import hashlib
import logging
import os
import random
import subprocess
import tempfile
import threading
from typing import List, Optional

logger = logging.getLogger(__name__)
VOICE_DECOY_GENERATOR_VERSION = "chatterbox-nano-voice-v1"

# Pool of generic security-context phrases.
# Each decoy picks one at random — caller hears a convincingly voiced fake message.
_DECOY_PHRASES = [
    "I'll be there in ten minutes, copy?",
    "Copy that. Standing by at the checkpoint.",
    "Sector is clear. No contacts. Over.",
    "Moving to the rendezvous point now.",
    "Base, this is Alpha. Status is normal.",
    "ETA approximately twenty minutes. Keep the line open.",
    "Confirm receipt. Will report back shortly.",
    "I'm at the position, awaiting orders.",
    "Nothing to report on my end. All clear.",
    "Understood. Will link up at the secondary point.",
    "Position secured. Awaiting further instructions.",
    "On my way. Stay at current location.",
    "Package is safe. Proceeding as planned.",
    "All units acknowledge. Maintain radio silence.",
    "Perimeter check complete. No anomalies detected.",
]

# Roughly how long one phrase takes to speak, for filling a target duration.
_SECONDS_PER_PHRASE = 3.5

_tts_lock = threading.Lock()


def _rng(seed: Optional[str]) -> random.Random:
    """Deterministic RNG per media id, so replays never disagree."""
    if seed is None:
        return random.Random()
    return random.Random(int(hashlib.sha256(seed.encode()).hexdigest()[:16], 16))


def _probe_duration(path: str) -> Optional[float]:
    try:
        out = subprocess.check_output([
            "ffprobe", "-v", "error", "-show_entries", "format=duration",
            "-of", "default=noprint_wrappers=1:nokey=1", path
        ], stderr=subprocess.DEVNULL, timeout=15)
        return float(out.decode().strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _pick_phrases(rng: random.Random, target_duration: Optional[float]) -> List[str]:
    """Enough phrases to cover the original note's length."""
    count = 1
    if target_duration and target_duration > 0:
        count = max(1, min(12, round(target_duration / _SECONDS_PER_PHRASE)))
    pool = _DECOY_PHRASES[:]
    rng.shuffle(pool)
    # Repeat the pool if the note is longer than the phrase list.
    while len(pool) < count:
        pool = pool + pool
    return pool[:count]


def normalize_voice_sample(source_path: str, wav_path: str) -> bool:
    """Decode Android AAC or desktop WebM into a mono WAV for cloning."""
    try:
        # Nano requires a reference longer than five seconds. Repeating a
        # short enrollment clip keeps previously enrolled users functional.
        duration = _probe_duration(source_path)
        input_args = ["-stream_loop", "-1"] if duration and duration < 6 else []
        result = subprocess.run(
            ["ffmpeg", "-y", "-v", "error", *input_args, "-i", source_path, "-vn", "-t", "30" if not input_args else "6",
             "-ac", "1", "-ar", "24000", "-c:a", "pcm_s16le", wav_path],
            capture_output=True, timeout=45,
        )
        if result.returncode == 0 and os.path.getsize(wav_path) > 1024:
            return True
        logger.error("[voice_decoy] Sample conversion failed: %s", result.stderr.decode(errors="replace")[-500:])
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("[voice_decoy] Sample conversion failed: %s", exc)
    return False


def _to_m4a(wav_path: str, output_path: str) -> bool:
    try:
        result = subprocess.run(
            ["ffmpeg", "-y", "-v", "error", "-i", wav_path, "-c:a", "aac",
             "-b:a", "64k", output_path],
            capture_output=True, timeout=45,
        )
        return result.returncode == 0 and os.path.getsize(output_path) > 1024
    except (OSError, subprocess.SubprocessError):
        return False


def _run_voice_worker(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, timeout=600)


def _generate_tts_decoy(source_path: str, output_path: str, text: str) -> bool:
    """Generate new speech in an isolated Chatterbox Python environment."""
    with _tts_lock:
        with tempfile.TemporaryDirectory(prefix="dilarion_voice_") as temp_dir:
            reference_wav = os.path.join(temp_dir, "reference.wav")
            generated_wav = os.path.join(temp_dir, "generated.wav")
            if not normalize_voice_sample(source_path, reference_wav):
                return False
            try:
                voice_python = os.environ.get(
                    "VOICE_CLONE_PYTHON",
                    os.path.join(os.path.dirname(__file__), "voice_venv", "bin", "python"),
                )
                worker = os.path.join(os.path.dirname(__file__), "voice_decoy_worker.py")
                result = _run_voice_worker([voice_python, worker, reference_wav, generated_wav, text])
                if result.returncode != 0:
                    logger.error("[voice_decoy] Chatterbox worker failed: %s", result.stderr.decode(errors="replace")[-2000:])
                    return False
                if not os.path.exists(generated_wav) or os.path.getsize(generated_wav) <= 1024:
                    return False
                return _to_m4a(generated_wav, output_path)
            except (OSError, subprocess.SubprocessError) as e:
                logger.error("[voice_decoy] Chatterbox synthesis failed: %s", e)
                return False


def generate_voice_decoy(
    source_path: str,
    output_path: str,
    seed: Optional[str] = None,
    target_duration: Optional[float] = None,
) -> bool:
    """
    Generate a decoy voice note.

    `seed` (pass the media_id) makes the result reproducible: the same note must
    always decoy to the same words. When `target_duration` is omitted, the
    enrollment sample length is used as an approximation.

    Returns True if `output_path` now holds playable audio.
    """
    if not os.path.exists(source_path):
        logger.error(f"[voice_decoy] Source not found: {source_path}")
        return False

    rng = _rng(seed)
    if target_duration is None:
        target_duration = _probe_duration(source_path)
    text = " ".join(_pick_phrases(rng, target_duration))

    generated = _generate_tts_decoy(source_path, output_path, text)
    if not generated and os.path.exists(output_path):
        os.remove(output_path)
    return generated
