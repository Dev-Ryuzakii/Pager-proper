# Voice decoy cloning on the backend

Voice decoys use [Chatterbox Nano](https://huggingface.co/ResembleAI/chatterbox-nano)
to synthesize new English speech from the sender's enrolled voice. The model
is MIT licensed. The enrollment recording is used only as a speaker reference.
If synthesis fails, the endpoint returns HTTP 503. Existing scrambled decoys
are bypassed by the updated cache key.

The voice model requires dependencies that conflict with the backend's pinned
FastAPI dependencies. Install it in its own virtual environment. On the VPS:

```bash
cd ~/Pager-proper
git pull --ff-only origin main
sudo apt-get update
sudo apt-get install -y ffmpeg
python3 -m venv voice_venv
voice_venv/bin/python -m pip install --upgrade pip
voice_venv/bin/python -m pip install -r requirements_voice_clone.txt
voice_venv/bin/python -m pip check
```

Preload the model once to download it and verify imports:

```bash
voice_venv/bin/python -c 'from chatterbox.tts_turbo import ChatterboxTurboTTS; ChatterboxTurboTTS.from_pretrained(device="cpu", nano=True); print("Nano model ready")'
```

Then test actual cloning before restarting the backend. Use a real enrolled
sample as the reference, substituting its path:

```bash
voice_venv/bin/python voice_decoy_worker.py /path/to/enrolled-sample.wav /tmp/voice-decoy-test.wav 'This is a voice cloning test.'
ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 /tmp/voice-decoy-test.wav
sudo systemctl restart pager_backend
```

The worker expects a WAV sample. If the enrolled sample is AAC or WebM,
convert it first with `ffmpeg -i SAMPLE -ac 1 -ar 24000 /tmp/reference.wav`.
The backend performs this conversion automatically for normal requests.

If the earlier Coqui installation changed the backend virtual environment,
remove its packages and restore the backend dependencies independently:

```bash
venv/bin/python -m pip uninstall -y coqui-tts httpx2 httpcore2
venv/bin/python -m pip check
```

The first request may be slow because the CPU model loads for each generated
decoy. Subsequent requests for the same voice note use the cached audio. If
generation returns 503, inspect `sudo journalctl -u pager_backend -n 100
--no-pager` for the worker error. Ensure the service user can read `voice_venv`
and write the decoy cache.
