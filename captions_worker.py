#!/usr/bin/env python3
"""Live transcript worker.

Runs as its own process next to the API (see deploy notes at the bottom):

    python captions_worker.py

For every meeting where the host turned the live transcript on, it joins the
LiveKit room as a hidden participant, listens to each speaker's audio track,
cuts it into utterances with a simple energy detector, transcribes each one on
this machine with faster-whisper, stores the text and asks the API to push it
to everyone in the meeting. No audio or text leaves the server.

Environment:
    DATABASE_URL, LIVEKIT_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET   same as the API
    CAPTIONS_WORKER_SECRET     shared with the API's /internal/captions/broadcast
    CAPTIONS_API_URL           default http://127.0.0.1:8000
    CAPTIONS_MODEL             faster-whisper size, default "small"
    CAPTIONS_LANGUAGE          default when the host picks "detect automatically",
                               e.g. "en"; empty = detect per utterance
    CAPTIONS_MAX_WORKERS       parallel transcriptions, default 2
    CAPTIONS_VAD_RMS           speech threshold (0..1 float RMS), default 0.012
"""

import asyncio
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("captions_worker")


def load_env_file(path: str = ".env") -> None:
    """Fill os.environ from .env without overriding what the process already has."""
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.removeprefix("export ").strip()
            os.environ.setdefault(key, value.strip().strip('"').strip("'"))


# Settings below are read at import, so .env has to be loaded first.
if __name__ == "__main__":
    load_env_file()

SAMPLE_RATE = 16000
FRAME_MS = 20
FRAME_SAMPLES = SAMPLE_RATE * FRAME_MS // 1000

API_URL = os.getenv("CAPTIONS_API_URL", "http://127.0.0.1:8000").rstrip("/")
MODEL_SIZE = os.getenv("CAPTIONS_MODEL", "small")
LANGUAGE = os.getenv("CAPTIONS_LANGUAGE", "").strip() or None
MAX_WORKERS = max(1, int(os.getenv("CAPTIONS_MAX_WORKERS", "2") or 2))
VAD_RMS = float(os.getenv("CAPTIONS_VAD_RMS", "0.012") or 0.012)
POLL_SECONDS = 2.0
MAX_BACKLOG = 8

# Whisper invents these on near-silent or very short clips.
_HALLUCINATIONS = {
    "thank you.", "thank you", "thanks for watching.", "thanks for watching!", "you", "bye.",
    "subtitles by the amara.org community", ".", "...",
}


# ── Pure pieces (unit tested without LiveKit or a model) ──────────────────────

@dataclass
class Utterance:
    audio: np.ndarray          # float32 mono 16 kHz in [-1, 1]
    started_at: datetime       # naive UTC
    ended_at: datetime


@dataclass
class Segmenter:
    """Energy-based utterance cutter for one speaker's stream.

    Feed 16 kHz mono int16 samples with the wall-clock time they arrived; it
    returns finished utterances. Speech starts when a 20 ms frame's RMS goes
    over the threshold (keeping 200 ms of lead-in), and ends after 700 ms of
    quiet or 12 s of continuous speech so captions never lag far behind.
    """
    threshold: float = VAD_RMS
    preroll_ms: int = 200
    silence_ms: int = 700
    max_ms: int = 12000
    min_speech_ms: int = 400
    _pending: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.float32))
    _preroll: List[np.ndarray] = field(default_factory=list)
    _frames: List[np.ndarray] = field(default_factory=list)
    _speech_frames: int = 0
    _quiet_frames: int = 0
    _start: Optional[datetime] = None

    def feed(self, samples: np.ndarray, arrived_at: datetime) -> List[Utterance]:
        audio = samples.astype(np.float32) / 32768.0 if samples.dtype == np.int16 else samples.astype(np.float32)
        self._pending = np.concatenate([self._pending, audio])
        done: List[Utterance] = []
        n_frames = len(self._pending) // FRAME_SAMPLES
        # Time of the first unprocessed frame, assuming samples arrive in real time.
        first_at = arrived_at - timedelta(milliseconds=len(self._pending) * 1000 / SAMPLE_RATE)
        for i in range(n_frames):
            frame = self._pending[i * FRAME_SAMPLES:(i + 1) * FRAME_SAMPLES]
            frame_at = first_at + timedelta(milliseconds=i * FRAME_MS)
            utt = self._step(frame, frame_at)
            if utt is not None:
                done.append(utt)
        self._pending = self._pending[n_frames * FRAME_SAMPLES:]
        return done

    def flush(self, now: datetime) -> Optional[Utterance]:
        return self._finish(now) if self._frames else None

    def _step(self, frame: np.ndarray, frame_at: datetime) -> Optional[Utterance]:
        loud = float(np.sqrt(np.mean(frame * frame))) >= self.threshold
        if not self._frames:
            if loud:
                lead = sum(len(f) for f in self._preroll) * 1000 / SAMPLE_RATE
                self._start = frame_at - timedelta(milliseconds=lead)
                self._frames = list(self._preroll) + [frame]
                self._preroll = []
                self._speech_frames = 1
                self._quiet_frames = 0
            else:
                self._preroll.append(frame)
                keep = self.preroll_ms // FRAME_MS
                if len(self._preroll) > keep:
                    self._preroll = self._preroll[-keep:]
            return None

        self._frames.append(frame)
        if loud:
            self._speech_frames += 1
            self._quiet_frames = 0
        else:
            self._quiet_frames += 1
        length_ms = len(self._frames) * FRAME_MS
        if self._quiet_frames * FRAME_MS >= self.silence_ms or length_ms >= self.max_ms:
            return self._finish(frame_at + timedelta(milliseconds=FRAME_MS))
        return None

    def _finish(self, end_at: datetime) -> Optional[Utterance]:
        frames, start = self._frames, self._start
        speech_ms = self._speech_frames * FRAME_MS
        self._frames, self._speech_frames, self._quiet_frames, self._start = [], 0, 0, None
        if speech_ms < self.min_speech_ms or start is None:
            return None
        return Utterance(audio=np.concatenate(frames), started_at=start, ended_at=end_at)


def clean_text(text: str, seconds: float) -> Optional[str]:
    """Collapse whitespace and drop Whisper's stock filler on short clips."""
    text = " ".join((text or "").split())
    if not text:
        return None
    if seconds < 2.5 and text.lower() in _HALLUCINATIONS:
        return None
    return text


def naive_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── Transcription ─────────────────────────────────────────────────────────────

class Transcriber:
    def __init__(self):
        self._model = None
        self._pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="captions-asr")
        self._inflight = 0

    def _load(self):
        if self._model is None:
            from faster_whisper import WhisperModel
            logger.info("loading faster-whisper model=%s", MODEL_SIZE)
            self._model = WhisperModel(MODEL_SIZE, device="cpu", compute_type="int8")
        return self._model

    def _run(self, audio: np.ndarray, language: Optional[str]) -> str:
        model = self._load()
        segments, _info = model.transcribe(
            audio,
            language=language or LANGUAGE,
            beam_size=1,
            vad_filter=False,
            condition_on_previous_text=False,
            without_timestamps=True,
        )
        return " ".join(seg.text.strip() for seg in segments)

    @property
    def busy(self) -> bool:
        return self._inflight >= MAX_WORKERS + MAX_BACKLOG

    async def transcribe(self, audio: np.ndarray, language: Optional[str] = None) -> str:
        self._inflight += 1
        try:
            return await asyncio.get_running_loop().run_in_executor(self._pool, self._run, audio, language)
        finally:
            self._inflight -= 1


# ── Database and API ──────────────────────────────────────────────────────────

def db_session():
    from database_models import SessionLocal
    return SessionLocal()


async def broadcast(payload: dict) -> None:
    import httpx
    secret = os.getenv("CAPTIONS_WORKER_SECRET", "")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.post(f"{API_URL}/internal/captions/broadcast", json=payload,
                                    headers={"X-Captions-Secret": secret})
            if res.status_code >= 300:
                logger.warning("broadcast %s -> %s", payload, res.status_code)
    except Exception as e:
        logger.warning("broadcast failed: %s", type(e).__name__)


def set_session(session_id: int, **fields) -> Optional[str]:
    """Update the session row; returns its status after the update."""
    from live_captions import MeetingCaptionSession
    db = db_session()
    try:
        row = db.query(MeetingCaptionSession).filter(MeetingCaptionSession.id == session_id).first()
        if not row:
            return None
        for key, value in fields.items():
            setattr(row, key, value)
        db.commit()
        return row.status
    finally:
        db.close()


def session_should_run(session_id: int) -> tuple:
    """(keep running?, language the host picked or None for automatic)."""
    from database_models import ConferenceSession
    from live_captions import ACTIVE_STATUSES, MeetingCaptionSession
    db = db_session()
    try:
        row = db.query(MeetingCaptionSession).filter(MeetingCaptionSession.id == session_id).first()
        if not row or row.status not in ACTIVE_STATUSES:
            return False, None
        conf = db.query(ConferenceSession).filter(ConferenceSession.id == row.conference_id).first()
        if not conf or not bool(conf.is_active):
            row.status = "stopped"
            row.stopped_at = naive_utc()
            db.commit()
            return False, None
        row.heartbeat_at = naive_utc()
        language = getattr(row, "language", None) or None
        db.commit()
        return True, language
    finally:
        db.close()


def save_segment(session_id: int, conference_id: int, username: str, name: str, text: str,
                 started_at: datetime, ended_at: datetime) -> int:
    from live_captions import MeetingCaptionSegment
    db = db_session()
    try:
        row = MeetingCaptionSegment(
            session_id=session_id, conference_id=conference_id,
            speaker_username=username[:120], speaker_name=(name or username)[:200],
            text=text, started_at=started_at, ended_at=ended_at,
        )
        db.add(row)
        db.commit()
        return int(row.id)
    finally:
        db.close()


def pending_sessions() -> List[tuple]:
    from live_captions import ACTIVE_STATUSES, MeetingCaptionSession
    db = db_session()
    try:
        rows = db.query(MeetingCaptionSession).filter(MeetingCaptionSession.status.in_(ACTIVE_STATUSES)).all()
        return [(int(r.id), int(r.conference_id)) for r in rows]
    finally:
        db.close()


# ── One room ──────────────────────────────────────────────────────────────────

class RoomCaptioner:
    def __init__(self, session_id: int, conference_id: int, transcriber: Transcriber):
        self.session_id = session_id
        self.language: Optional[str] = None
        self.conference_id = conference_id
        self.transcriber = transcriber
        self.room = None
        self.tasks: Dict[str, asyncio.Task] = {}

    def token(self) -> str:
        from livekit import api
        return (
            api.AccessToken(os.environ["LIVEKIT_API_KEY"], os.environ["LIVEKIT_API_SECRET"])
            .with_identity(f"captions-bot-{self.session_id}")
            .with_name("Live transcript")
            .with_grants(api.VideoGrants(
                room_join=True, room=f"conf-{self.conference_id}",
                can_subscribe=True, can_publish=False, can_publish_data=False, hidden=True,
            ))
            .to_jwt()
        )

    async def run(self) -> None:
        from livekit import rtc
        self.room = rtc.Room()

        @self.room.on("track_subscribed")
        def _on_track(track, publication, participant):
            if track.kind != rtc.TrackKind.KIND_AUDIO:
                return
            key = f"{participant.identity}:{publication.sid}"
            if key not in self.tasks:
                self.tasks[key] = asyncio.create_task(self.listen(track, participant, publication))

        @self.room.on("track_unsubscribed")
        def _on_untrack(track, publication, participant):
            task = self.tasks.pop(f"{participant.identity}:{publication.sid}", None)
            if task:
                task.cancel()

        await self.room.connect(os.environ["LIVEKIT_URL"], self.token(),
                                options=rtc.RoomOptions(auto_subscribe=True))
        set_session(self.session_id, status="running", started_at=naive_utc(), heartbeat_at=naive_utc(), error=None)
        await broadcast({"session_id": self.session_id})
        logger.info("captions running conference=%s", self.conference_id)
        try:
            while True:
                keep, self.language = session_should_run(self.session_id)
                if not keep:
                    break
                await asyncio.sleep(3)
        finally:
            for task in list(self.tasks.values()):
                task.cancel()
            try:
                await self.room.disconnect()
            except Exception:
                pass
            await broadcast({"session_id": self.session_id})
            logger.info("captions stopped conference=%s", self.conference_id)

    async def listen(self, track, participant, publication) -> None:
        from livekit import rtc
        username = participant.identity
        name = participant.name or username
        if getattr(publication, "source", None) == rtc.TrackSource.SOURCE_SCREENSHARE_AUDIO:
            name = f"{name} (screen)"
        seg = Segmenter()
        stream = rtc.AudioStream(track, sample_rate=SAMPLE_RATE, num_channels=1)
        try:
            async for event in stream:
                samples = np.frombuffer(event.frame.data, dtype=np.int16)
                for utt in seg.feed(samples, naive_utc()):
                    asyncio.create_task(self.emit(utt, username, name))
        except asyncio.CancelledError:
            pass
        finally:
            last = seg.flush(naive_utc())
            if last is not None:
                asyncio.create_task(self.emit(last, username, name))
            try:
                await stream.aclose()
            except Exception:
                pass

    async def emit(self, utt: Utterance, username: str, name: str) -> None:
        if self.transcriber.busy:
            logger.warning("captions backlog full; dropping %.1fs of %s", len(utt.audio) / SAMPLE_RATE, username)
            return
        try:
            text = clean_text(await self.transcriber.transcribe(utt.audio, self.language), len(utt.audio) / SAMPLE_RATE)
        except Exception as e:
            logger.warning("transcribe failed: %s", type(e).__name__)
            return
        if not text:
            return
        segment_id = await asyncio.get_running_loop().run_in_executor(
            None, save_segment, self.session_id, self.conference_id, username, name, text, utt.started_at, utt.ended_at,
        )
        await broadcast({"segment_id": segment_id})


# ── Main loop ─────────────────────────────────────────────────────────────────

async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for key in ("LIVEKIT_URL", "LIVEKIT_API_KEY", "LIVEKIT_API_SECRET", "CAPTIONS_WORKER_SECRET"):
        if not os.getenv(key):
            raise SystemExit(f"{key} is not set")
    transcriber = Transcriber()
    await asyncio.get_running_loop().run_in_executor(None, transcriber._load)  # load once up front
    running: Dict[int, asyncio.Task] = {}
    logger.info("captions worker ready (model=%s, workers=%s)", MODEL_SIZE, MAX_WORKERS)
    while True:
        try:
            for session_id, conference_id in pending_sessions():
                task = running.get(session_id)
                if task is None or task.done():
                    running[session_id] = asyncio.create_task(_guarded(session_id, conference_id, transcriber))
        except Exception as e:
            logger.error("poll failed: %s", type(e).__name__)
        for sid in [s for s, t in running.items() if t.done()]:
            running.pop(sid, None)
        await asyncio.sleep(POLL_SECONDS)


async def _guarded(session_id: int, conference_id: int, transcriber: Transcriber) -> None:
    try:
        await RoomCaptioner(session_id, conference_id, transcriber).run()
    except Exception as e:
        logger.error("captions failed conference=%s: %s", conference_id, type(e).__name__)
        set_session(session_id, status="failed", error="The live transcript stopped unexpectedly", stopped_at=naive_utc())
        await broadcast({"session_id": session_id})


if __name__ == "__main__":
    asyncio.run(main())

# Deploy notes
# - pip install "livekit>=1.0" faster-whisper numpy httpx  (in the API venv, or a separate one)
# - API env: CAPTIONS_ENABLED=1 and CAPTIONS_WORKER_SECRET=<random 32+ chars>; worker gets the same secret.
# - nginx must not expose /internal/: `location /internal/ { deny all; }` — the worker calls 127.0.0.1 directly.
# - systemd unit: ExecStart=<venv>/bin/python captions_worker.py, WorkingDirectory=<repo>, Restart=always.
# - CPU budget: "small" int8 transcribes about 4-6x faster than real time per core; two parallel
#   jobs comfortably cover a few active speakers. Use CAPTIONS_MODEL=base on a small VPS.
