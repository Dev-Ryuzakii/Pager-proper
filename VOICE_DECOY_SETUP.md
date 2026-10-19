# Voice decoy cloning on the backend

The voice decoy endpoint uses XTTS-v2 to speak new text in the sender's
enrolled voice. The enrollment recording is only a speaker reference. A
missing or failing model now returns HTTP 503 instead of replaying pieces of
the recording. Android AAC and desktop WebM samples are normalized to WAV.

On the VPS, from `~/Pager-proper`:

```bash
sudo apt-get update
sudo apt-get install -y ffmpeg
source venv/bin/activate
python -m pip install -r requirements_voice_clone.txt
python - <<'PY'
from TTS.api import TTS
TTS("tts_models/multilingual/multi-dataset/xtts_v2", progress_bar=False).to("cpu")
print("XTTS-v2 model ready")
PY
sudo systemctl restart pager_backend
```

The model's first download may ask for acceptance of its terms. Review and
accept them in the interactive preflight above before restarting the service.
The requirements pin Transformers 4.57.5 because Coqui 0.27.5 imports an API
removed in Transformers 5. Run the install again after pulling this fix if an
earlier install selected Transformers 5.
They also restore the AnyIO and h11 versions required by this backend's
existing FastAPI and httpcore packages. Check `python -m pip check` after the
install before restarting the service.
The model and PyTorch need substantial free disk space and memory; provision
the VPS accordingly. After deployment, request a voice decoy and inspect
`sudo journalctl -u pager_backend -n 100 --no-pager` if it returns 503.

Previously cached scrambled decoys are bypassed automatically by the new
versioned cache key. Existing enrolled samples can be decoded on demand, so
users do not need to record again unless the original upload was corrupt.
