# Cursor prompt: Topic Channels + Meeting Transcription/Notes for Dilarion

Paste everything below the line into Cursor (Agent mode). Work in this repo
(`Pager-proper`, FastAPI backend) and the client repo `dilarion-app`
(Kotlin Multiplatform: `app/` Android, `desktop/`, `ios/`, `web/`).

---

You are working on **Dilarion**, a secure (E2E-encrypted) team messaging app.
Backend: one large FastAPI file `fastapi_mobile_backend_postgresql.py`, SQLAlchemy
models in `database_models.py`, Postgres, idempotent migration scripts named
`migrate_*.py` (pattern: `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`). Clients live in
`dilarion-app`. Read the existing code before writing; reuse existing patterns,
auth dependencies, WebSocket broadcast helpers and E2E message flow. Do not
break any existing endpoint or client. Build two features.

## Feature 1: Topic channels (with threads)

Roadmap Phase 2: "public and private topic channels, channel descriptions,
ownership, member controls and searchable channel history" plus threaded replies.

What exists today (reuse, do not duplicate):
- `Group` / `GroupMember` models (`database_models.py` ~line 608). Group has
  `name`, `description`, `created_by`, `avatar_path`, `invite_code`,
  `disappear_after_hours`. GroupMember `role` is `admin` | `member`.
- ~20 `/groups/...` endpoints (~line 11535): create, list, update, delete,
  members add/remove/promote/demote, invite link, join, leave, messages, read, call.
- `Message.reply_to_message_id` already exists (single-level reply quote).
- Org admin layer: orgs run the company in-app (privileges, broadcast, mute).
  Channels belong to an organization.

Design: a channel is a Group with extra fields, so messaging, encryption,
calls, reactions, pins and read receipts keep working for free.
1. Model changes (+ `migrate_add_channels.py`, idempotent):
   - `groups.kind` VARCHAR(20) default `'group'` (`'group'` | `'channel'`).
   - `groups.visibility` (`'public'` | `'private'`), `groups.organization_id` FK,
     `groups.topic` (short line), `groups.is_archived` bool, `groups.posting_policy`
     (`'everyone'` | `'admins'` for announcement-style channels).
   - `group_members.role` adds `'owner'`. Creator becomes owner; ownership transferable.
   - `messages.thread_root_id` FK messages.id (nullable), `messages.thread_reply_count`
     int default 0, `messages.thread_last_reply_at`.
2. Endpoints (new prefix `/channels`, thin wrappers over group logic where possible):
   - `POST /channels` create (org members only; name unique per org, slug-style).
   - `GET /channels/browse?q=` public channels in caller's org not yet joined.
   - `GET /channels` caller's joined channels with unread counts.
   - `POST /channels/{id}/join` (public only), `POST /channels/{id}/leave`.
   - `PATCH /channels/{id}` name/topic/description/visibility/posting_policy (owner/admin).
   - `POST /channels/{id}/archive` + unarchive (owner/admin; archived = read-only).
   - `POST /channels/{id}/transfer-ownership`.
   - Members: invite to private, remove, promote/demote (reuse group handlers).
   - Threads: `POST /channels/{id}/messages` accepts `thread_root_id`;
     `GET /channels/{id}/threads/{root_id}` paged replies; root's
     `thread_reply_count`/`thread_last_reply_at` updated in same transaction;
     WS event `thread_reply` to channel members; follow/unfollow a thread for notifications.
   - Enforce `posting_policy` and archived state server-side.
   - Org admins can see and manage all channels in their org (respect org privileges).
3. Search: message bodies are E2E, so the server cannot search content. Server
   search covers channel names/topics/descriptions; clients index decrypted channel
   history locally (same approach as existing DM search). Extend `/search` to return channels.
4. Audit-log every create/archive/delete/ownership change using existing audit helper.
5. Clients (`dilarion-app`): sidebar section "Channels" separate from groups and DMs,
   `#name` display, browse/join screen, channel header with topic + member count,
   settings sheet (owner/admin), thread side panel on desktop / full screen on mobile,
   "N replies" chip under root messages, read-only banner for archived channels,
   composer disabled with hint when posting is admins-only.
6. Tests: add `test_channels.py` (offline-runnable where possible) covering
   permissions (non-member, member, admin, owner, org admin), private vs public join,
   posting_policy, archive, thread counts.

## Feature 2: Meeting transcription + AI notes

Backend is already done (uncommitted work now committed): `meeting_ai.py`,
`migrate_add_meeting_ai.py`, `test_meeting_ai.py`, plus columns on `MeetingRecording`
(`ai_status`, `ai_error`, `transcript`, `notes_json`, `ai_providers`, `ai_processed_at`)
and endpoints:
- `POST /admin/drive/recordings/{recording_id}/notes` → 202, runs pipeline in background.
- `GET  /admin/drive/recordings/{recording_id}/notes` → status, transcript, notes.

Pipeline: transcribe (`TRANSCRIBE_PROVIDER=local` faster-whisper | `deepgram`)
→ summarise in chunks + merge (`SUMMARY_PROVIDER=ollama` | `claude`, model
`CLAUDE_SUMMARY_MODEL`, default `claude-haiku-5-5`). Notes JSON shape:
`{summary, key_points[], decisions[], action_items[{task, owner, due}]}`.
Free tier keeps everything on-server; paid tier sends audio/text to the third party,
recorded in `ai_providers` for audit.

Build the rest:
1. Participant access: `GET/POST /meetings/recordings/{id}/notes` for users who were
   participants of that conference (not only admins). Same response shape.
2. Auto-run: org setting `auto_meeting_notes` (bool). When a recording finishes
   uploading and the setting is on, queue the pipeline automatically.
3. Consent: when recording/transcription starts, broadcast a WS event so every
   client shows a visible "Recording and transcribing" banner. Store consent in audit log.
4. Action items → tasks: `POST /meetings/recordings/{id}/notes/action-items/{index}/task`
   creates a `Task` (existing model) with title from the item, assignee matched by
   name/username among participants when unambiguous, otherwise unassigned.
5. Post notes to chat: optional "Share notes" that sends the summary into the meeting's
   group/channel as a normal (client-encrypted) message. The client encrypts it, never the server.
6. Speaker labels (stretch): enable Deepgram `diarize=true` in paid tier; local tier
   leaves speakers unlabeled. Store segments with timestamps in a new `transcript_segments`
   JSON column so clients can click a line to seek playback.
7. Retention: transcripts and notes follow the org `RetentionPolicy` and get deleted with
   the recording (account deletion path near line ~4276 already removes recordings; extend it).
8. Clients: on the recording detail screen show status (processing spinner, failed + retry),
   tabs Summary / Action items / Transcript, copy and export (Markdown), "Create task"
   button per action item, transcript search.
9. Tests: extend `test_meeting_ai.py`; add endpoint permission tests (participant ok,
   non-participant 403, admin ok, double-run while processing → 409).

## Rules
- Small, reviewable commits per step. Run existing tests before and after.
- Every new column via an idempotent `migrate_*.py`; never edit old migrations.
- Never log message plaintext, transcript text or API keys.
- Keep comments short and explain why, matching the existing comment style.
