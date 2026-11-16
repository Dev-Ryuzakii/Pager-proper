# Cursor prompt: fixes for channels, meeting notes and calls

Paste everything below the line into Cursor (Agent mode), in `Pager-proper`.

---

Review found bugs in commits `09d049f` (meeting AI, voice clone, call token) and
`0120266` (channels, threads, participant meeting notes). Fix them in this order,
one small commit each. Read the cited code first. Do not change behaviour that is
not listed here. Add or extend offline tests (`test_channels.py`,
`test_meeting_ai.py`) for every fix where a pure function can cover it.

## P0: security and data leaks

1. **Org "viewer" accounts get channel admin power.**
   `channels.py` `is_org_channel_admin` returns True for any
   `organization_role == "viewer"`. Viewers are portal-only read accounts; only
   the org account itself (`user_type == "organization"`) and site admins are
   implicit org admins. Remove the bare `viewer` check. Keep `manage_groups` / `*`
   privileges. Reuse the existing `_has_org_privilege` / `_is_org_account` helpers in
   the main file instead of re-implementing them, so the rules cannot drift. Apply
   the same fix to `meeting_notes._can_edit_org` (and require the org account or
   `manage_staff`, not `manage_groups`, to toggle auto transcription).

2. **Anyone invited to a meeting can read its transcript.**
   `meeting_notes._participant_ids` takes every `ConferenceParticipant` row, which
   includes invitees who never joined, people still `waiting`, and people the host
   `denied`. Only count rows that were actually admitted to the call
   (`status == "admitted"`, and joined at some point). Keep the recording starter
   and site admins. Add tests for waiting, denied and never-joined users (403).

3. **Action item → task bypasses the `assign_tasks` privilege.**
   `POST /meetings/recordings/{id}/notes/action-items/{index}/task` lets any
   participant create a task assigned to someone else. Run the same permission
   check the normal task-create endpoint uses (org-scoped `assign_tasks`, or group
   admin when `group_id` is set). If the caller lacks it, create the task unassigned
   or assigned to the caller. Also stop duplicates: store the created `task_id` on
   the action item (or a small mapping table) and return the existing task on a
   second click (200, not 201).

4. **Private channel history readable by org admins with no audit.**
   `get_group_messages` lets an org admin read any channel they are not a member of.
   Content is E2E so they get ciphertext, but this is still compliance access.
   Write an audit log entry (`channel_history_viewed_by_org_admin`) each time, and
   do not include it in unread/read-receipt side effects.

5. **Stranded participants re-admitted after being denied** (`conference_livekit_token`).
   The "put the original two callers back" branch reactivates any original caller
   whose row is inactive, and it overwrites `status` to `admitted` even when the
   host set it to `denied`. Only revive rows whose status is not `denied` (or any
   future `removed` status), and only for `kind == "call"` conferences.

## P1: correctness

6. **Thread replies leak into the main channel timeline.**
   `get_group_messages` does not filter `Message.thread_root_id IS NULL`, so every
   thread reply also shows in the timeline. Filter them out there (only for
   channels, `Group.kind == "channel"`), and include `thread_root_id` in the
   `new_group_message` WebSocket payload so clients route live replies to the thread
   panel instead of the timeline.

7. **Two send paths for channel messages.**
   `POST /channels/{id}/messages` (channels.py) duplicates `send_group_message` but
   skips the disappearing-message timer (`_resolve_group_disappear_hours`), push
   notifications, @mention notifications, webhooks and `_exclude_hidden` handling.
   Delete the channel-specific send logic and make that route call the same internal
   function `send_group_message` uses (extract it if needed). One send path only.
   `guard_channel_post` already protects the group path; keep it.

8. **Thread reply count loses updates under concurrency.**
   `apply_thread_reply` does `count = count + 1` in Python. Two replies at once lose
   one. Use an atomic SQL update:
   `UPDATE messages SET thread_reply_count = thread_reply_count + 1, thread_last_reply_at = now() WHERE id = :root`.
   Keep the pure function for tests only if still useful.

9. **Thread listing ignores deletes, hides and expiry.**
   `GET /channels/{id}/threads/{root_id}` returns deleted replies' ciphertext and
   ignores `_exclude_hidden` and `expires_at`. Apply the same filters and the same
   deleted-message scrubbing `get_group_messages` does. Reuse that serializer so the
   reply shape matches `MessageResponse` (reactions, edited, deleted flags).

10. **Channel `owner` fails every existing group-admin check.**
    Group code checks `role == "admin"` in about 12 places (for example
    `fastapi_mobile_backend_postgresql.py` around lines 1932, 1985, 9798, 11550).
    A channel owner is `role == "owner"`, so they cannot pin, edit the group, run
    group calls or manage the disappear timer. Add one helper
    `_is_group_admin_role(role)` returning True for `admin` and `owner`, and use it
    everywhere. The "last admin leaving" check at ~1985 must count owners too.

11. **Old `/groups/...` endpoints bypass channel rules.**
    These still work on channels: join by invite code (joins a private channel),
    leave (owner can leave and orphan the channel), delete, member add/remove/promote
    and demote (can overwrite `owner`), PUT update (skips slug and posting rules).
    For `kind == "channel"`, either reject with 409 "Use /channels endpoints" or route
    to the channel logic. Pick reject unless a client already depends on them; grep
    `dilarion-app` first.

12. **Channel role management too loose.** A channel `admin` can demote or remove
    other admins. Only the owner or an org admin may promote, demote or remove an
    admin. Admins may still add/remove plain members.

13. **`reply_to_message_id` not checked.** In the channel send path, a reply can point
    at a message from another conversation. Require the target to be in the same
    `group_id` (this goes away if fix 7 reuses the group path and that path already
    checks; verify).

14. **Archived and membership edge cases.**
    - `can_join` allows joining an archived public channel by id. Block it.
    - `invite_member` works on archived channels and has a dead `if ... pass` block.
      Remove the dead block, block invites on archived channels, notify the invitee
      over WebSocket (`channel_updated`, event `added`) and audit it.
    - `remove_member` sends no WebSocket event to the removed user and leaves their
      `ThreadFollow` rows. Send `channel_updated` (event `removed`) and delete the
      follows.
    - `create_channel` does not notify the initial members. Notify them.

15. **Thread follows do nothing.** `ThreadFollow` rows are stored but never read.
    Send `thread_reply` push notifications to followers (and the root author by
    default), excluding the sender and muted chats. WebSocket can stay
    "all members".

16. **Slug race.** No unique constraint on `(organization_id, slug)` for channels.
    Add a partial unique index in `migrate_add_channels.py`
    (`WHERE kind = 'channel'`) and retry with the next suffix on `IntegrityError`.

17. **Meeting notes stuck in `processing` forever.** If the server restarts while a
    background job runs, `ai_status` stays `processing` and every retry gets 409.
    Treat `processing` older than 2 hours (use a new `ai_started_at` column, set when
    queued) as failed in `start_block`, and on startup mark stale rows failed.

18. **Unbounded transcription jobs.** Any participant can now start the pipeline,
    and re-run it after it finishes. Each run loads Whisper on CPU or costs Deepgram
    and Claude money. Add:
    - a process-wide `asyncio.Semaphore` (env `MEETING_AI_CONCURRENCY`, default 1)
      around `process_file`;
    - re-run of a `done` recording allowed only for the host or an admin;
    - a per-user rate limit using the existing rate-limit helper if there is one.
    Also make the `/admin/drive/recordings/{id}/notes` POST use the same
    `start_block` and atomic claim (`UPDATE ... SET ai_status='processing' WHERE id=:id AND (ai_status IS NULL OR ai_status <> 'processing')`, check rowcount) so two clicks cannot start two jobs.

19. **Deepgram diarized call is not wrapped.** `_transcribe_deepgram_diarized` can
    raise (network, file errors) and, unlike `transcribe_file`, has no try/except.
    Wrap it the same way and return `(None, None)` with a logged warning so the row
    gets a real error message instead of "Internal error".

20. **Recording file path.** LiveKit Egress writes `meeting_recordings/<file>.mp4`
    relative to the Egress process. Confirm the backend sees the same file (shared
    volume or absolute path from env `RECORDINGS_DIR`). If not, `process_file` always
    fails with "Recording file not found". Make `RECORDINGS_DIR` configurable and
    absolute, and resolve `rec.file_path` against it.

21. **Late joiners miss the consent banner.** `meeting_transcription` is only sent to
    people in the call when recording starts. Include
    `{"recording": true, "banner": "Recording and transcribing"}` in the conference
    join/token response while a recording is active, so clients show it on join.

## P2: performance and cleanup

22. `channel_dict` runs two count queries per channel (members, unread with a
    subquery). `list_channels` and `search_channel_rows` call it in a loop, and
    `list_channels` runs `query.all()` twice. Batch the counts with one grouped
    query each and drop the duplicate query.
23. `apply_thread_reply` uses naive `datetime.utcnow()`. Use the same UTC style as
    the rest of the file (recent commits moved to UTC-aware timestamps).
24. Voice clone: `POST /users/me/voice-speech` runs CPU TTS in the threadpool with no
    concurrency cap. Add a semaphore (env `VOICE_CLONE_CONCURRENCY`, default 1) and
    return 429 when busy, so one user cannot block the server.

## Done when
- All tests pass: `python3 -I test_channels.py`-style runners and the existing test files.
- New tests cover fixes 1, 2, 3, 6, 10, 12, 14, 17 and 18 at minimum.
- No transcript text, message content or API keys appear in logs.
- Each fix is its own commit with a clear message.
