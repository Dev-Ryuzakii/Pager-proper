"""Owner-only voice enrollment, speech generation, and cleanup."""

import os
import subprocess
import unittest
import wave
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

import voice_clone
import voice_scrambler


def tone(path: str, seconds: float, silent: bool = False) -> None:
    source = "anullsrc=r=24000:cl=mono" if silent else f"sine=frequency=440:duration={seconds}"
    command = ["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i", source]
    if silent:
        command += ["-t", str(seconds)]
    if path.endswith(".m4a"):
        command += ["-c:a", "aac", "-b:a", "64k", path]
    else:
        command += ["-ac", "1", "-ar", "24000", "-c:a", "pcm_s16le", path]
    subprocess.run(command, check=True, capture_output=True)


def speak_m4a(reference: str, output: str, text: str) -> bool:
    assert text
    assert os.path.isfile(reference)
    tone(output, 1)
    return True


class Account:
    def __init__(self, user_id: int, username: str, path: str = None):
        self.id = user_id
        self.username = username
        self.voice_identity_path = path


class MemoryDB:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1


class VoiceCloneTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.upload = self._dir.name
        self.owner = Account(1, "owner")
        self.other = Account(2, "other")
        self.db = MemoryDB()
        self.holder = {"user": self.owner}
        app = FastAPI()
        voice_clone.install_voice_clone_routes(
            app,
            lambda: self.holder["user"],
            lambda: self.db,
            lambda: self.upload,
            synthesize=speak_m4a,
        )
        self.client = TestClient(app)
        self.sample = self._enroll(self.owner)

    def _enroll(self, account: Account) -> str:
        folder = Path(self.upload) / f"user_{account.id}"
        folder.mkdir(parents=True)
        path = str(folder / "voice_identity.wav")
        tone(path, 6)
        account.voice_identity_path = path
        return path

    def test_rejects_short_silent_and_undecodable_recordings(self):
        short = str(Path(self.upload) / "short.wav")
        silent = str(Path(self.upload) / "silent.wav")
        junk = str(Path(self.upload) / "notes.txt")
        tone(short, 2)
        tone(silent, 6, silent=True)
        Path(junk).write_text("not audio", encoding="utf-8")
        self.assertIn("too short", voice_clone.enrollment_problem(short))
        self.assertIn("silent", voice_clone.enrollment_problem(silent))
        self.assertIn("not valid audio", voice_clone.enrollment_problem(junk))
        self.assertIsNone(voice_clone.enrollment_problem(self.sample))

    def test_accepts_browser_webm_without_a_duration_header(self):
        # MediaRecorder streams WebM, so the header never records a duration
        # and ffprobe reports "N/A". Writing to a pipe reproduces that.
        path = Path(self.upload) / "browser.webm"
        recorded = subprocess.run(
            ["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "sine=frequency=300:duration=7",
             "-c:a", "libopus", "-f", "webm", "-live", "1", "-"],
            check=True, capture_output=True,
        )
        path.write_bytes(recorded.stdout)
        self.assertAlmostEqual(voice_scrambler._probe_duration(str(path)), 7, delta=0.2)
        self.assertIsNone(voice_clone.enrollment_problem(str(path)))

    def test_owner_can_preview_generated_speech_and_a_stranger_cannot(self):
        created = self.client.post("/users/me/voice-speech", json={"text": "Hello from the owner"})
        self.assertEqual(created.status_code, 200, created.text)
        clip_id = created.json()["id"]
        self.assertEqual(created.json()["text"], "Hello from the owner")

        own_audio = self.client.get(f"/users/me/voice-speech/{clip_id}")
        own_sample = self.client.get("/users/owner/voice-identity")
        self.assertEqual(own_audio.status_code, 200)
        self.assertEqual(own_sample.status_code, 200)
        self.assertGreater(len(own_audio.content), 1024)
        self.assertTrue(own_sample.content.startswith(b"RIFF"))

        self.holder["user"] = self.other
        stolen_audio = self.client.get(f"/users/me/voice-speech/{clip_id}")
        stolen_sample = self.client.get("/users/owner/voice-identity")
        escaped = self.client.get("/users/me/voice-speech/../user_1/voice_speech/" + clip_id)
        self.assertEqual(stolen_audio.status_code, 404)
        self.assertEqual(stolen_sample.status_code, 403)
        self.assertEqual(escaped.status_code, 404)
        self.assertNotIn(b"ftyp", stolen_audio.content)
        self.assertFalse(stolen_sample.content.startswith(b"RIFF"))
        self.assertTrue((Path(self.upload) / "user_1" / "voice_speech" / f"{clip_id}.m4a").is_file())

        removed = self.client.delete(f"/users/me/voice-speech/{clip_id}")
        self.assertEqual(removed.status_code, 404)
        self.assertTrue((Path(self.upload) / "user_1" / "voice_speech" / f"{clip_id}.m4a").is_file())

    def test_poisoned_path_cannot_read_or_delete_another_users_sample(self):
        sentinel = Path(self.upload) / "sentinel.wav"
        tone(str(sentinel), 6)
        self.other.voice_identity_path = self.sample
        self.holder["user"] = self.other
        denied = self.client.get("/users/other/voice-identity")
        self.assertEqual(denied.status_code, 403)
        self.assertFalse(denied.content.startswith(b"RIFF"))

        deleted = self.client.delete("/users/me/voice-identity")
        self.assertEqual(deleted.status_code, 200)
        self.assertIsNone(self.other.voice_identity_path)
        self.assertTrue(Path(self.sample).is_file())
        self.assertTrue(sentinel.is_file())
        self.assertEqual(self.db.commits, 1)

    def test_generation_failure_leaves_no_clip_and_delete_removes_audio(self):
        def fail(reference, output, text):
            Path(output).write_bytes(b"partial")
            raise FileNotFoundError("worker missing")

        with self.assertRaises(voice_clone.VoiceCloneError) as caught:
            voice_clone.generate_owned_speech(self.upload, 1, self.sample, "Hello", synthesize=fail)
        self.assertEqual(caught.exception.status_code, 503)
        speech = Path(self.upload) / "user_1" / "voice_speech"
        self.assertEqual(list(speech.glob("*.m4a")), [])
        self.assertEqual(list(speech.glob(".tmp_*")), [])

        created = self.client.post("/users/me/voice-speech", json={"text": "Keep this clip"})
        clip_id = created.json()["id"]
        self.holder["user"] = self.owner
        gone = self.client.delete("/users/me/voice-identity")
        self.assertEqual(gone.status_code, 200)
        self.assertFalse(Path(self.sample).is_file())
        self.assertFalse((speech / f"{clip_id}.m4a").exists())
        self.assertIsNone(self.owner.voice_identity_path)

    def test_invalid_text_and_missing_enrollment_do_not_call_the_model(self):
        calls = []

        def spy(reference, output, text):
            calls.append(text)
            return speak_m4a(reference, output, text)

        self.owner.voice_identity_path = None
        missing = self.client.post("/users/me/voice-speech", json={"text": "Hello"})
        self.assertEqual(missing.status_code, 409)
        blank = voice_clone.generate_owned_speech
        self.owner.voice_identity_path = self.sample
        with self.assertRaises(voice_clone.VoiceCloneError) as caught:
            blank(self.upload, 1, self.sample, "   ", synthesize=spy)
        self.assertEqual(caught.exception.status_code, 400)
        self.assertEqual(calls, [])

    def test_decoy_phrases_stay_separate_from_owner_text(self):
        seen = {}

        def record(command, **kwargs):
            seen["text"] = command[4]
            output = command[3]
            import math
            import struct
            with wave.open(output, "wb") as handle:
                handle.setnchannels(1)
                handle.setsampwidth(2)
                handle.setframerate(24000)
                handle.writeframes(b"".join(
                    struct.pack("<h", int(8000 * math.sin(2 * math.pi * 880 * i / 24000)))
                    for i in range(24000)
                ))
            return subprocess.CompletedProcess(command, 0, b"", b"")

        from unittest.mock import patch
        output = str(Path(self.upload) / "spoken.m4a")
        with patch.object(voice_scrambler, "_run_voice_worker", side_effect=record):
            self.assertTrue(voice_scrambler.synthesize_cloned_speech(self.sample, output, "Hello from the owner"))
        self.assertEqual(seen["text"], "Hello from the owner")
        decoy = str(Path(self.upload) / "decoy.m4a")
        with patch.object(voice_scrambler, "_run_voice_worker", side_effect=record):
            self.assertTrue(voice_scrambler.generate_voice_decoy(self.sample, decoy, seed="same", target_duration=8))
        self.assertTrue(any(phrase in seen["text"] for phrase in voice_scrambler._DECOY_PHRASES))
        self.assertNotIn("Hello from the owner", seen["text"])


class VoiceSlotTests(unittest.TestCase):
    def test_second_generation_is_busy(self):
        import asyncio
        sem = asyncio.Semaphore(1)

        async def check():
            self.assertTrue(await voice_clone.acquire_voice(sem))
            self.assertFalse(await voice_clone.acquire_voice(sem))
            sem.release()
            self.assertTrue(await voice_clone.acquire_voice(sem))
            sem.release()

        asyncio.run(check())
        self.assertEqual(voice_clone.voice_concurrency_limit(None), 1)
        self.assertEqual(voice_clone.voice_concurrency_limit("0"), 1)


if __name__ == "__main__":
    unittest.main()
