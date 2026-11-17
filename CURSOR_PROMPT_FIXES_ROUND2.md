# Cursor prompt: round 2 fixes (after commits 88a347b..f8b222b)

Paste everything below the line into Cursor (Agent mode), in `Pager-proper`.

---

The 20 fixes from `CURSOR_PROMPT_FIXES_CHANNELS_MEETING_NOTES.md` are in and the
tests pass (`venv/bin/python -m pytest -q test_channels.py test_meeting_ai.py test_voice_clone.py`).
A re-review found these remaining problems. Fix them one commit each, with tests.

## 1. Bad `thread_root_id` leaves a stray message in the timeline (bug)

`deliver_group_message` in `fastapi_mobile_backend_postgresql.py` calls
`MessageService.send_message_to_group`, which commits the message, and only then
looks up the thread root. If the root is missing, is in another group, or is
itself a reply, it raises 404, but the message is already saved as a normal
timeline message and the sender sees an error.

Fix: validate `thread_root_id` before calling `send_message_to_group`, and pass
`thread_root_id` into the insert so the row is never visible without it. Also
reject `thread_root_id` (400) when the group is not a channel (`kind != "channel"`),
because plain groups have no thread UI and the reply would show twice.
Test: bad root id → 404 and no new `Message` row.

## 2. Old recordings resolve to a doubled path (bug)

`RECORDINGS_DIR` is now absolute, but rows recorded before this change store a
relative path like `meeting_recordings/conf-1-1.mp4`.
`meeting_ai.resolve_recording_path("meeting_recordings/conf-1-1.mp4", "/srv/app/meeting_recordings")`
returns `/srv/app/meeting_recordings/meeting_recordings/conf-1-1.mp4`, so notes,
download and file size fail with "not found" for every older recording.

Fix: for a relative path, try in order `os.path.abspath(file_path)` (old cwd-relative
form) and `os.path.join(recordings_dir, os.path.basename(file_path))`; return the
first that exists, else the second. Use the same helper in the retention purge
(~line 4903) and the account-deletion cleanup (~line 4280), which still use the raw
`file_path`. Test both legacy and absolute forms.

Also note in `LIVE_SERVER_SETUP.md` (or the deploy doc you find): Egress now gets
an absolute `RECORDINGS_DIR` path, so the Egress container must mount that same
path, or recordings are written somewhere the API cannot read.

## 3. Mentions in thread replies no longer push (regression)

Offline members get no push for a thread reply unless they follow the thread or
wrote the root (`if not ws_sent and not root`). A user @mentioned in a thread
reply gets nothing. Add mentioned members (minus muted, minus sender) to the
thread push recipients, with the "You were mentioned" title.

## 4. Timezone mismatch on `ai_started_at` (low)

`ai_started_at` is `TIMESTAMP` without time zone but is written with an aware
UTC datetime, and `processing_is_stale` treats a naive value read back as UTC.
If the Postgres session `TimeZone` is not UTC, stale detection is off by the
offset. Write `datetime.now(timezone.utc).replace(tzinfo=None)` to match how the
rest of the file stores naive UTC, in `claim_notes_job`, `queue_if_enabled` and the
cutoff comparison.

## 5. Small cleanups (low)

- `_channel_stats` unread count ignores expired (`expires_at`) and hidden messages,
  so the badge can count messages the user cannot see. Apply the same filters as
  the thread listing.
- `get_group_messages` writes an audit row on every page an org admin loads.
  Log once per admin per channel per hour (simple in-memory throttle is fine).
- The rate limit in `meeting_notes._notes_hits` is per process. Fine for one worker;
  add a comment saying so, or move it to the existing rate-limit store if one exists.

## Check before deploy (no code change unless it finds rows)

`_is_org_account` no longer treats `organization_role == "viewer"` alone as the org
account. New org accounts get both `viewer` and `user_type = "organization"`
(~line 6044). Confirm old ones do too:

```sql
SELECT id, username FROM users
WHERE organization_role = 'viewer' AND user_type IS DISTINCT FROM 'organization';
```

If this returns org accounts, add a migration setting `user_type = 'organization'`
for them, or they lose their privileges.

Run migrations `migrate_add_channels.py` and `migrate_add_meeting_ai_started.py`
on the server before deploying the code.
