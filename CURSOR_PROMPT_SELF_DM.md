# Cursor prompt — personal "(You)" DM + meeting recordings delivered to it

Paste everything below the line into Cursor, opened on the `Pager-proper` repo (FastAPI backend).
The desktop and Android clients are being built against the **API contract** in this file at the
same time, so keep every route, field name and value exactly as written. If something in the
contract is impossible, stop and say so instead of changing it quietly.

---

## Goal

Every user gets a personal chat with themselves, shown in their DM list as **"You"** (like
Telegram's Saved Messages). Two things land there:

1. **Notes to self** — the user can send ordinary messages to their own username.
2. **Meeting recordings** — when a meeting recording finishes, every person who was admitted to
   that meeting gets a recording card in their "You" chat. When the AI notes for that recording
   finish, they get a second card with the notes summary.

Decisions already made (do not reopen):
- **Who gets recording cards:** the user who started the recording plus every participant who was
  admitted to the conference (reuse `meeting_notes.participant_was_admitted` / `_participant_ids`
  logic). Deduplicate. Same organization only.
- **Not end-to-end encrypted:** egress already writes a plain MP4 on the server. The card is a
  plain system message (same precedent as `_send_meeting_card`, `content_type="meeting"`), and it
  links to a new authenticated download route. Do not try to encrypt the file.

## Codebase facts you'll need

- `database_models.Message`: `sender_id`, `recipient_id`, `encrypted_content` (Text),
  `content_type` (String 50), `decoy_content`, `expires_at`, `auto_delete`, `message_hash`.
- `MessageService.send_message_by_username(...)` builds a DM `Message`. It currently assumes
  sender ≠ recipient in places (decoy context, `_same_organization`). A self-message has
  `sender_id == recipient_id`.
- `_send_meeting_card(...)` (around line 8764 of `fastapi_mobile_backend_postgresql.py`) is the
  pattern for plain system cards: JSON in `encrypted_content`, a non-"encrypted" `content_type`,
  a WS `new_message` event, and a push when the user is offline.
- `stop_conference_recording` (around line 8700) is the **only** place that sets a
  `MeetingRecording` to `completed`. Check whether conferences that end while recording (host
  leaves / room finishes / conference ended endpoint) ever stop the egress. If they don't, add
  that so a recording can't be left in `recording` forever, and deliver cards from that path too.
- `_run_meeting_ai(recording_id)` (around line 19760) writes `notes_json` / `ai_status` when the
  AI job ends.
- `meeting_notes._require_reader` decides who can read a recording's notes. Reuse the same rule for
  the file download.
- Recording files resolve with `meeting_ai.resolve_recording_path(rec.file_path, RECORDINGS_DIR)`.
  Egress finishes writing **after** `StopEgress` returns, so the file may be missing or still
  growing for a short while after stop.
- Routes: `GET /messages/conversations` (around line 11470), `GET /messages/conversation/{partner_username}`
  (around line 11297), `POST /messages/send` (around line 7459).

## API contract (clients depend on this exactly)

### 1. Conversation list — `GET /messages/conversations`
Always include the self conversation, **first in the list**, even when it has no messages yet.
Keep the existing item shape and add one field to every item:

```jsonc
{
  "partner_username": "<my own username>",
  "is_self": true,            // NEW on every item; false for normal DMs
  "display_name": "You",      // NEW; for normal DMs keep whatever name field you already return, and set display_name to it too
  "last_message": ...,        // existing fields unchanged; null/empty when the self chat is empty
  "unread_count": 0           // self messages never count as unread
  // ...all existing fields unchanged
}
```

### 2. Self chat history — `GET /messages/conversation/{my_username}`
Returns messages where `sender_id == recipient_id == me`, same item shape as any DM, newest-last
ordering exactly like other conversations. Must not return messages where only one side is me.

### 3. Sending a note to self — `POST /messages/send`
Allow `recipient_username == my own username`. Everything else is the same as a normal DM (the
client encrypts with the user's own public key). Self messages:
- never expire (ignore any disappearing-message timer: `expires_at=None`, `auto_delete=False`);
- are created already `delivered=True, read=True`;
- emit the normal `new_message` WS event to the user's other devices.

### 4. Recording card — sent into the self chat of each recipient
One `Message` per recipient with `sender_id = recipient_id = that user`, no expiry, read=True,
`content_type="meeting_recording"`, `decoy_content="Meeting recording"`, and
`encrypted_content` = this JSON string:

```jsonc
{
  "kind": "meeting_recording",
  "recording_id": 123,
  "conference_id": 45,
  "meeting_title": "Weekly sync",      // conference/meeting title, or "Meeting" if none
  "host_username": "amaka",            // user who started the recording
  "started_at": "2026-11-17T10:00:00Z", // ISO UTC with Z
  "ended_at": "2026-11-17T10:42:10Z",
  "duration_seconds": 2530,
  "file_size": null,                    // bytes, null if not known yet
  "download_path": "/meetings/recordings/123/file",
  "notes_path": "/meetings/recordings/123/notes"
}
```

Send it **once per (recording, user)**: make delivery idempotent (e.g. `message_hash =
f"rec:{recording_id}:{user_id}"` and skip if a message with that hash exists). WS event to each
recipient:

```json
{ "type": "new_message", "data": { "message_id": 1, "sender_username": "<me>", "recipient_username": "<me>", "content_type": "meeting_recording", "is_self": true, "timestamp": "..." } }
```

Push when offline: title `"Meeting recording"`, body `"Your recording of <title> is ready"`.

### 5. Notes card — when the AI job ends
After `_run_meeting_ai` finishes with `ai_status == "done"`, send one more self message per
recipient (same recipients, same idempotency pattern with `message_hash = f"notes:{recording_id}:{user_id}"`),
`content_type="meeting_notes"`, `decoy_content="Meeting notes"`, `encrypted_content`:

```jsonc
{
  "kind": "meeting_notes",
  "recording_id": 123,
  "meeting_title": "Weekly sync",
  "summary": "First 400 characters of the notes summary…",
  "key_points": ["…", "…", "…"],          // at most 5
  "action_item_count": 4,
  "notes_path": "/meetings/recordings/123/notes"
}
```
Do not send it when `ai_status` is `failed`. Same WS event shape with `"content_type": "meeting_notes"`.

### 6. Recording file — `GET /meetings/recordings/{recording_id}/file`

Auth is `Authorization: Bearer`, or a short `?sig=` from `POST /meetings/recordings/{recording_id}/file-link`. A session token in the query is not accepted.

`POST /meetings/recordings/{recording_id}/file-link` uses the same bearer auth and the same reader rule as the file. It returns the same 404, 409, 410, and 403 answers. On success:

```json
{"url": "/meetings/recordings/123/file?sig=<token>", "expires_at": "2026-11-17T10:15:00Z"}
```

`sig` is an HMAC of `recording_id`, `user_id`, and an expiry 15 minutes ahead, signed with the app secret. It only works for that recording. Every request checks the reader rule again, so removing someone takes effect immediately. Signatures are compared in constant time. An expired or invalid `sig` is 401. A `sig` minted for a different recording is 403.

- 404 if the recording does not exist, or `{"detail": "This recording failed"}` when the status is `failed`.
- 409 `{"detail": "Recording is still being processed"}` while the status is `recording` or `processing`, or the file is missing or empty. That is never a 410.
- 410 `{"detail": "This recording has expired"}` when retention has expired, or the status is `completed` and the file was later deleted.
- 200: stream the MP4 with `Content-Type: video/mp4`, support HTTP `Range` requests (so the clients can seek in a `<video>` tag), `Content-Disposition: inline; filename="<safe title>-<date>.mp4"`.

The access log for this route does not include the query string.

### 7. My recordings — `GET /meetings/recordings/mine` (new)
List every recording the caller can read, newest first:
```jsonc
{ "recordings": [ { "recording_id": 123, "meeting_title": "…", "host_username": "…", "started_at": "…", "ended_at": "…", "duration_seconds": 2530, "status": "completed", "ai_status": "done", "download_path": "/meetings/recordings/123/file", "notes_path": "/meetings/recordings/123/notes" } ] }
```

## Rules
- No new table is required; if you do add one (e.g. for delivery idempotency), add a
  `migrate_add_*.py` script like the existing ones and register it wherever the other migrations run.
- Deliver cards from a background task so stopping a recording stays fast. Wrap delivery in
  try/except and log; a delivery failure must never fail the stop request.
- Self chat must not appear twice, must not show in other users' lists, and must survive the
  conversation-hiding / clear-chat features the same way other DMs do.
- Timestamps: naive UTC in the DB, serialized with `Z` (same as the rest of the codebase).
- Add tests in a new `test_self_dm.py` covering: the self conversation is listed first and present
  when empty; sending to self works and never expires; the recording card is delivered once per
  admitted participant (not to people who were never admitted, not twice on a retry); the notes card
  is sent only on success; the file route returns 403 / 409 / 200 with Range support.
- Run the full existing test suite before you finish and report the result.
- Commit with a clear message. **Do not push.**

## When you're done, report
- Every route/field you added or changed, confirming each matches the contract above.
- Where recordings are stopped (including any auto-stop path you added).
- Test results.
