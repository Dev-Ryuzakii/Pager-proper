"""
Voice decoy generator.
Primary: Coqui TTS XTTS-v2 — clones sender voice, synthesises a random fake phrase.
Fallback: ffmpeg shuffle/pitch-shift (used when TTS library unavailable or model not loaded).
"""

import logging
import os
import random
import subprocess
import uuid
from typing import Optional

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

# Lazy-loaded TTS engine — first call takes ~30s to download model
_tts_engine: Optional[object] = None
_tts_available = True  # set False on first import failure


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
        logger.warning(f"[voice_decoy] TTS unavailable ({e}), falling back to ffmpeg scramble")
        _tts_available = False
        return None


def _generate_tts_decoy(source_path: str, output_path: str) -> bool:
    """Use XTTS-v2 to synthesise a random fake phrase in the sender's cloned voice."""
    tts = _get_tts()
    if tts is None:
        return False
    try:
        phrase = random.choice(_DECOY_PHRASES)
        wav_path = output_path.replace(".m4a", ".wav")
        tts.tts_to_file(
            text=phrase,
            speaker_wav=source_path,
            language="en",
            file_path=wav_path,
        )
        if not os.path.exists(wav_path):
            return False
        # Convert wav → m4a to match expected output format
        cmd = [
            "ffmpeg", "-y", "-i", wav_path,
            "-c:a", "aac", "-b:a", "64k", output_path
        ]
        subprocess.run(cmd, capture_output=True)
        os.remove(wav_path)
        return os.path.exists(output_path)
    except Exception as e:
        logger.error(f"[voice_decoy] TTS synthesis failed: {e}")
        return False


def _generate_ffmpeg_decoy(source_path: str, output_path: str) -> bool:
    """Fallback: slice + shuffle + pitch-shift segments of the source file."""
    temp_prefix = f"temp_{uuid.uuid4().hex}"
    segments = []
    try:
        cmd = [
            "ffprobe", "-v", "error", "-show_entries", "format=duration",
            "-of", "default=noprint_wrappers=1:nokey=1", source_path
        ]
        duration = float(subprocess.check_output(cmd).decode().strip())

        num_segments = random.randint(4, 6)
        seg_duration = duration / num_segments

        for i in range(num_segments):
            seg_file = f"{temp_prefix}_seg_{i}.m4a"
            start = i * seg_duration
            tempo = random.uniform(0.85, 1.25)
            filter_chain = f"atempo={tempo}"
            if random.random() > 0.5:
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

        random.shuffle(segments)

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


def generate_voice_decoy(source_path: str, output_path: str) -> bool:
    """
    Generate a decoy voice note using the sender's voice identity.
    Tries XTTS-v2 voice cloning first; falls back to ffmpeg scramble.
    """
    if not os.path.exists(source_path):
        logger.error(f"[voice_decoy] Source not found: {source_path}")
        return False

    # Try AI cloning first
    if _generate_tts_decoy(source_path, output_path):
        logger.info("[voice_decoy] AI-cloned decoy generated")
        return True

    # Fallback to scramble
    logger.info("[voice_decoy] Using ffmpeg scramble fallback")
    return _generate_ffmpeg_decoy(source_path, output_path)
