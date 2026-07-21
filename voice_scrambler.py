"""
Voice decoy generator.

Three tiers, best first:
  1. Coqui XTTS-v2 — clones the sender's voice, speaks a fake phrase.
  2. Piper        — coherent speech in a generic voice, ~50 MB model, CPU real-time.
  3. ffmpeg       — shuffles/pitch-shifts the original. Incoherent; last resort.

Two properties matter as much as the audio itself:

  * Determinism. The same voice note must always produce the same decoy. A note
    that says something different on each replay is an obvious tell.
  * Duration. A 4-second decoy standing in for a 40-second note is equally
    obvious, so phrases are chosen to fill the original's length.
"""

import hashlib
import logging
import os
import random
import shutil
import subprocess
import uuid
from typing import List, Optional

logger = logging.getLogger(__name__)

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

# Lazy-loaded TTS engine — first call takes ~30s to download model
_tts_engine: Optional[object] = None
_tts_available = True  # set False on first import failure
_piper_voice: Optional[str] = None  # path to a .onnx voice model, if found


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
        ], stderr=subprocess.DEVNULL)
        return float(out.decode().strip())
    except Exception:
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


def _get_tts():
    global _tts_engine, _tts_available
    if not _tts_available:
        return None
    if _tts_engine is not None:
        return _tts_engine
    try:
        from TTS.api import TTS  # type: ignore
        # XTTS-v2 is multilingual and clones voice from a single sample
        _tts_engine = TTS("tts_models/multilingual/multi-dataset/xtts_v2", gpu=False)
        logger.info("[voice_decoy] XTTS-v2 model loaded")
        return _tts_engine
    except Exception as e:
        logger.warning(f"[voice_decoy] TTS unavailable ({e}), trying piper")
        _tts_available = False
        return None


def _to_m4a(wav_path: str, output_path: str) -> bool:
    subprocess.run(
        ["ffmpeg", "-y", "-i", wav_path, "-c:a", "aac", "-b:a", "64k", output_path],
        capture_output=True,
    )
    if os.path.exists(wav_path):
        os.remove(wav_path)
    return os.path.exists(output_path)


def _generate_tts_decoy(source_path: str, output_path: str, text: str) -> bool:
    """XTTS-v2: synthesise the fake phrases in the sender's cloned voice."""
    tts = _get_tts()
    if tts is None:
        return False
    try:
        wav_path = output_path.replace(".m4a", ".wav")
        tts.tts_to_file(
            text=text,
            speaker_wav=source_path,
            language="en",
            file_path=wav_path,
        )
        if not os.path.exists(wav_path):
            return False
        return _to_m4a(wav_path, output_path)
    except Exception as e:
        logger.error(f"[voice_decoy] TTS synthesis failed: {e}")
        return False


def _find_piper_voice() -> Optional[str]:
    """Locate a piper .onnx voice model, if one is installed."""
    global _piper_voice
    if _piper_voice is not None:
        return _piper_voice or None
    search = [
        os.getenv("PIPER_VOICE", ""),
        "/usr/share/piper-voices",
        "/opt/piper/voices",
        os.path.expanduser("~/.local/share/piper-voices"),
        "piper_voices",
    ]
    for entry in search:
        if not entry:
            continue
        if entry.endswith(".onnx") and os.path.exists(entry):
            _piper_voice = entry
            return entry
        if os.path.isdir(entry):
            for root, _, files in os.walk(entry):
                for f in files:
                    if f.endswith(".onnx"):
                        _piper_voice = os.path.join(root, f)
                        return _piper_voice
    _piper_voice = ""
    return None


def _generate_piper_decoy(output_path: str, text: str) -> bool:
    """
    Piper: coherent speech in a generic voice. Not the sender's voice, but a
    listener hears real sentences rather than scrambled noise — which is the
    whole point of a decoy.
    """
    if not shutil.which("piper"):
        return False
    voice = _find_piper_voice()
    if not voice:
        logger.warning("[voice_decoy] piper installed but no .onnx voice found")
        return False
    wav_path = output_path.replace(".m4a", ".wav")
    try:
        subprocess.run(
            ["piper", "--model", voice, "--output_file", wav_path],
            input=text.encode(), capture_output=True, timeout=60,
        )
        if not os.path.exists(wav_path):
            return False
        return _to_m4a(wav_path, output_path)
    except Exception as e:
        logger.error(f"[voice_decoy] piper synthesis failed: {e}")
        return False


def _generate_ffmpeg_decoy(source_path: str, output_path: str, rng: random.Random) -> bool:
    """Fallback: slice + shuffle + pitch-shift segments of the source file."""
    temp_prefix = f"temp_{uuid.uuid4().hex}"
    segments = []
    try:
        duration = _probe_duration(source_path)
        if not duration:
            return False

        num_segments = rng.randint(4, 6)
        seg_duration = duration / num_segments

        for i in range(num_segments):
            seg_file = f"{temp_prefix}_seg_{i}.m4a"
            start = i * seg_duration
            tempo = rng.uniform(0.85, 1.25)
            filter_chain = f"atempo={tempo}"
            if rng.random() > 0.5:
                filter_chain += ",asetrate=44100*1.2,atempo=0.83"

            cmd = [
                "ffmpeg", "-y", "-i", source_path,
                "-ss", str(start), "-t", str(seg_duration),
                "-filter:a", filter_chain,
                "-vn", seg_file
            ]
            subprocess.run(cmd, capture_output=True)
            if os.path.exists(seg_file):
                segments.append(seg_file)

        if not segments:
            return False

        rng.shuffle(segments)

        concat_list = f"{temp_prefix}_list.txt"
        with open(concat_list, "w") as f:
            for s in segments:
                f.write(f"file '{os.path.abspath(s)}'\n")

        cmd = [
            "ffmpeg", "-y", "-f", "concat", "-safe", "0",
            "-i", concat_list, "-c", "copy", output_path
        ]
        subprocess.run(cmd, capture_output=True)

        for s in segments:
            os.remove(s)
        os.remove(concat_list)

        return os.path.exists(output_path)

    except Exception as e:
        logger.error(f"[voice_decoy] ffmpeg fallback failed: {e}")
        for i in range(10):
            p = f"{temp_prefix}_seg_{i}.m4a"
            if os.path.exists(p):
                os.remove(p)
        concat = f"{temp_prefix}_list.txt"
        if os.path.exists(concat):
            os.remove(concat)
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
    always decoy to the same words. `target_duration` matches the original's
    length; when omitted it is probed from `source_path`.

    Returns True if `output_path` now holds playable audio.
    """
    if not os.path.exists(source_path):
        logger.error(f"[voice_decoy] Source not found: {source_path}")
        return False

    rng = _rng(seed)
    if target_duration is None:
        target_duration = _probe_duration(source_path)
    text = " ".join(_pick_phrases(rng, target_duration))

    # Tier 1: cloned voice, real sentences.
    if _generate_tts_decoy(source_path, output_path, text):
        logger.info("[voice_decoy] AI-cloned decoy generated")
        return True

    # Tier 2: generic voice, real sentences.
    if _generate_piper_decoy(output_path, text):
        logger.info("[voice_decoy] piper decoy generated")
        return True

    # Tier 3: sender's voice, no meaning.
    logger.info("[voice_decoy] Using ffmpeg scramble fallback")
    return _generate_ffmpeg_decoy(source_path, output_path, rng)
