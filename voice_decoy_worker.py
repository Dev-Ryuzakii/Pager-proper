"""Run Chatterbox Nano in its own Python environment to avoid backend conflicts.

Decoy phrases and speech the account owner typed both arrive as the text
argument. The reference wav is only a speaker prompt, never the output.
"""

import os
import sys


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: voice_decoy_worker.py REFERENCE.wav OUTPUT.wav TEXT")
    reference_path, output_path, text = sys.argv[1:]

    import torch
    import torchaudio
    from chatterbox.tts_turbo import ChatterboxTurboTTS

    # A fixed seed keeps output reproducible if the cache must be rebuilt.
    torch.manual_seed(0)
    local_dir = os.environ.get("CHATTERBOX_NANO_DIR")
    if local_dir:
        model = ChatterboxTurboTTS.from_local(local_dir, device="cpu", nano=True)
    else:
        model = ChatterboxTurboTTS.from_pretrained(device="cpu", nano=True)
    with torch.inference_mode():
        audio = model.generate(text, audio_prompt_path=reference_path)
    torchaudio.save(output_path, audio.cpu(), model.sr)


if __name__ == "__main__":
    main()
