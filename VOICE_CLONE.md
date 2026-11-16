# Voice cloning in Dilarion

Typed speech uses the same Chatterbox Nano worker as voice decoys. The account
owner enrolls a sample, types English text, previews the clip, and can delete
the sample and every clip made from it. Decoy notes still pick their own
phrases in `voice_scrambler.generate_voice_decoy`. They do not speak the text
from this feature.

## Architecture

VoiceStudio is the technical reference for the product shape: a reference clip,
text in, audio out, and a way to discard both. It is not part of Dilarion's
runtime.

Dilarion does not run VoiceStudio as a backend service and does not copy its
code. VoiceStudio is AGPL-3.0-only. Serving a modified copy over the network
would require offering that server's source to the people who use it. Dilarion's
API is not being relicensed, so the AGPL program stays outside this repository.
Its default OmniVoice weights are also CC-BY-NC, and those weights are not used
here.

The implementation that ships is the one already in this repo:

- `voice_decoy_worker.py` loads Chatterbox Nano in `voice_venv`.
- `voice_scrambler.py` turns an owner recording into a 24 kHz reference and
  encodes the worker's wav as new m4a. A missing worker deletes partial output
  and does not return the enrollment audio.
- `voice_clone.py` stores clips under `media_uploads/user_<id>/voice_speech/`
  and refuses paths that resolve outside that directory.

Inference, files, and authorization all stay in Pager-proper. The Android, iOS,
and desktop clients only call the HTTP API.

## API

| Method | Path | Who |
| --- | --- | --- |
| POST | `/users/me/voice-identity` | Save the signed-in user's sample |
| GET | `/users/{username}/voice-identity` | That same user, or 403 |
| DELETE | `/users/me/voice-identity` | Deletes the sample and that user's clips |
| POST | `/users/me/voice-speech` | Body `{"text": "..."}` |
| GET | `/users/me/voice-speech` | Lists that user's clips |
| GET | `/users/me/voice-speech/{id}` | That user's m4a, or 404 |
| DELETE | `/users/me/voice-speech/{id}` | Deletes one clip |

A clip id is only looked up inside the caller's directory. Another account gets
404 for the audio and 403 for the enrollment sample, including when a stored
path points at someone else's file. New uploads must be real audio, at least 5
seconds, and not silent. The decoy worker still repeats an older short sample
so enrollments saved before that check keep working. Empty text is 400. If the
worker is missing or synthesis fails, the API returns 503 and leaves no clip
behind.

## Model and license evidence

Checked 16 November 2026. The worker is pinned to chatterbox commit
`5de7a54aa4e5e2baadb0182dde554908b48b85c2`.

- Code: the LICENSE at that repository is MIT, copyright Resemble AI 2025.
  https://github.com/resemble-ai/chatterbox/blob/5de7a54aa4e5e2baadb0182dde554908b48b85c2/LICENSE
- Weights: `ResembleAI/chatterbox-nano` reports `cardData.license = mit` and the
  tag `license:mit`. It is not gated. Nano's `from_local` loads
  `t3_nano_v1.safetensors` (about 830 MB), `s3gen_meanflow.safetensors` (about
  1.0 GB), `ve.safetensors`, and the tokenizer files. It does not load
  `s3gen.safetensors`. The library's `from_pretrained` still asks the hub for
  every `*.safetensors` file, including that unused one.
  https://huggingface.co/api/models/ResembleAI/chatterbox-nano
- `t3_nano_v1.yaml` sets `base_model: null`. The T3 code builds a Llama-shaped
  network with `vocab_size` 8 and its own text and speech embeddings. This
  checkout does not download Meta's Llama weights, and the Nano repo does not
  include Meta's license. The published grant for the checkpoint we load is MIT.
- Dependencies on the worker's install list, from their installed metadata:
  torch and torchaudio (BSD-3-Clause), diffusers (Apache-2.0), s3tokenizer
  (Apache-2.0), resemble-perth 1.1.0 (MIT), spacy-pkuseg (MIT). Perth's
  watermark stays in the audio. It is not stripped.
- `pykakasi` 2.3.0 is GPL-3.0-or-later. Chatterbox imports it only inside the
  Japanese text branch (`chatterbox/models/tokenizers/tokenizer.py`) and skips
  that branch when the package is missing. English Nano speech does not need
  it. A production image that does not ship Japanese text can leave `pykakasi`
  uninstalled. GPL-3.0 has no network clause, but do not distribute that
  package inside an on-prem voice environment without treating the combination
  under GPL-3.0.
- Not used: OmniVoice / `k2-fsa/OmniVoice` pretrained weights (CC-BY-NC), and
  any file copied from VoiceStudio (AGPL-3.0).

Resemble retired Chatterbox as a maintained product in August 2026. The MIT
grant remains. There is no vendor support channel behind this pin.

## Production notes

Install the isolated environment with `VOICE_DECOY_SETUP.md` before enabling
the feature. Until `voice_venv` can import Chatterbox Nano and the MIT weights
are on disk, both decoys and typed speech fail closed with HTTP 503. The first
successful load downloads about 3 GB if it uses `from_pretrained`, because that
call also fetches the unused `s3gen.safetensors`. Set `CHATTERBOX_NANO_DIR` to
a directory that already contains the files `from_local` reads
(`t3_nano_v1.safetensors`, `s3gen_meanflow.safetensors`, `ve.safetensors`,
`conds.pt`, and the tokenizer files) to skip that extra download. Preload
before serving: the worker timeout is 600 seconds and is too short for a cold
weight download. Speech is English, and each generation loads the CPU model
inside the worker. The pinned Chatterbox package still installs
`resemble-perth` from the `master` branch, so a production host should record
the resolved Perth commit next to the Chatterbox pin.
