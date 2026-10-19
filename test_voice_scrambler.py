"""Regression checks for voice enrollment decoding and decoy fallback safety."""

import math
import os
import struct
import subprocess
import tempfile
import unittest
import wave
from pathlib import Path
from unittest.mock import patch

import voice_scrambler


class FakeTts:
    def tts_to_file(self, *, text, speaker_wav, language, file_path):
        assert text and language == "en"
        with wave.open(speaker_wav, "rb") as reference:
            assert reference.getnchannels() == 1
            assert reference.getframerate() == 24000
        with wave.open(file_path, "wb") as output:
            output.setnchannels(1)
            output.setsampwidth(2)
            output.setframerate(24000)
            output.writeframes(b"".join(
                struct.pack("<h", int(8000 * math.sin(2 * math.pi * 880 * i / 24000)))
                for i in range(24000)
            ))


class VoiceScramblerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # Desktop uploads WebM bytes, even though the old backend saved them
        # under a .m4a filename. ffmpeg must decode by content.
        self.source = str(Path(self.temp.name) / "voice_identity.m4a")
        subprocess.run(
            ["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i",
             "sine=frequency=440:duration=2", "-c:a", "libopus", "-f", "webm", self.source],
            check=True, capture_output=True,
        )

    def test_normalizes_mislabeled_webm_sample(self):
        wav_path = str(Path(self.temp.name) / "reference.wav")
        self.assertTrue(voice_scrambler.normalize_voice_sample(self.source, wav_path))
        with wave.open(wav_path, "rb") as converted:
            self.assertEqual(converted.getnchannels(), 1)
            self.assertEqual(converted.getframerate(), 24000)

    def test_missing_clone_engine_never_replays_enrollment_audio(self):
        output = str(Path(self.temp.name) / "decoy.m4a")
        with patch.object(voice_scrambler, "_get_tts", return_value=None):
            self.assertFalse(voice_scrambler.generate_voice_decoy(
                self.source, output, seed="voice-1", target_duration=8,
            ))
        self.assertFalse(os.path.exists(output))

    def test_synthesized_speech_is_encoded_as_new_audio(self):
        output = str(Path(self.temp.name) / "decoy.m4a")
        with patch.object(voice_scrambler, "_get_tts", return_value=FakeTts()):
            self.assertTrue(voice_scrambler.generate_voice_decoy(
                self.source, output, seed="voice-2", target_duration=8,
            ))
        self.assertGreater(os.path.getsize(output), 1024)
        self.assertAlmostEqual(voice_scrambler._probe_duration(output), 1.0, delta=0.1)


if __name__ == "__main__":
    unittest.main()
