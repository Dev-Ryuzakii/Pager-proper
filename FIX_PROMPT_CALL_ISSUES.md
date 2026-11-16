# Prompt for the fixing agent: two Dilarion call bugs

You are fixing two bugs in Dilarion's calling feature. The code has been read but nothing has been run, so reproduce each bug first, confirm the root cause listed here, then fix it. If a root cause turns out wrong, say so and follow the evidence.

## Repos and key files

| What | Path |
|---|---|
| Backend (FastAPI, one big file) | `/Users/ryuzakii/Downloads/Pager-proper/fastapi_mobile_backend_postgresql.py` |
| DB models | `/Users/ryuzakii/Downloads/Pager-proper/database_models.py` (`ConferenceSession` ~line 953) |
| Android app (Kotlin/Compose) | `/Users/ryuzakii/dilarion-app/app/src/main/kotlin/com/dilarion/app/` |
| Desktop app (Tauri + React) | `/Users/ryuzakii/dilarion-app/desktop/src/` |

Backend call paths:
- `POST /calls/conference/create` (~line 7829): upgrades a live 1:1 call into a conference. It sends `conference_upgraded` to the other party.
- `POST /calls/conference/{id}/invite` (~line 7900): invites the third person. It sends `conference_invite`.
- `POST /calls/conference/{id}/accept`: the invitee joins.
- `CallService.forward_ice_candidate` (~line 2865) and `_buffer_ice` / `flush_pending_ice` (~line 2653): ICE relay.

---

## Bug 1: a normal call turns into a "meeting" when a third person joins

### Expected behavior
A 1:1 call stays a call. When a third person is added it becomes a **group call**. It must not look like or behave like a **Meeting**. A Meeting is the scheduled or instant-meeting feature, with a lobby, waiting room, breakout rooms, host controls, meeting chat, whiteboard and recording. Voice stays voice and video stays video.

### How it works today
Adding a participant to a 1:1 call creates a `ConferenceSession`. Group calls and meetings both run on the same LiveKit SFU room, `conf-<id>`. The UI decides call vs meeting only through a **client-side flag, `isAdHocCall` / `isAdHoc`**. That flag is never stored on the server, so every entry path has to remember to pass it. Some don't.

Paths that set it (correct):
- Desktop `desktop/src/screens/HomeScreen.tsx` lines ~2506-2520 (`conference_upgraded`) and ~2546/2553 (upgrade from call window or web).
- Android `ui/navigation/AppNavigation.kt` lines ~100 and ~367 (`isAdHoc = true`).

### Root causes (confirm each)

1. **The third person never gets the ad-hoc flag.**
   - Desktop: `HomeScreen.tsx` `joinConferenceCall()` (~line 2246) calls `setActiveGalleryCall({ conferenceId, initialCamOn })` with no `isAdHocCall`.
   - Android: `AppNavigation.kt` ~line 149 calls `Screen.Gallery.route(confId)` with no `isAdHoc`.
   - Result: the invitee lands in `GalleryView`/`GalleryScreen` with the meeting UI. The title reads "Group Video", the host sees waiting-room and breakout controls, and the waiting-room fetch runs (`GalleryView.tsx` ~343, `GalleryViewModel.kt` ~269).

2. **`/invite` posts a literal Meeting card into the DM.** Near the end of `conference_invite`, the backend calls `_send_meeting_card(... {"kind": "instant", "conference_id": ..., "title": None} ...)`. So adding a person to a call drops a "meeting" card in the chat. For an ad-hoc call this must not happen. Posting a call-style card is fine, but it must not be a Meeting.

3. **`conference_invite` has no `call_type` for ad-hoc invites.** `conference_invite` omits `call_type` (it is only sent for group-chat calls). The invitee's camera state then falls back to a default, and the desktop overlay says "Group call" rather than video or voice.

4. **The flag isn't authoritative.** It lives only in client navigation state. A late joiner, a second device, a reconnect or the minimize/restore flow can lose it. `ConferenceSession` already has `original_call_id`, which is non-null for calls upgraded from a 1:1.

### Fix requirements
- Make the server the source of truth.
  - Add `kind` to `ConferenceSession`: `"call"` (upgraded from a 1:1 or started ad hoc), `"group_call"` (started from a group chat) or `"meeting"` (scheduled or instant meeting).
  - Add an idempotent migration in the style of `migrate_add_meeting_ai.py`.
  - Derive the default from `original_call_id IS NOT NULL` for existing rows.
- Include `kind` and `call_type` in every payload that puts someone into a conference:
  - `conference_upgraded`
  - `conference_invite`
  - the accept response
  - the LiveKit token / join response
  - the waiting-room admit response
- Make both clients derive `isAdHocCall` from `kind != "meeting"` instead of hard-coding it per path. Fix at least:
  - desktop `joinConferenceCall`
  - Android `AppNavigation.kt` ~149
  - the Android `IncomingConferenceOverlay` accept path
  - any minimize/restore or rejoin path
- In `/invite`, send the meeting card only when `kind == "meeting"`. For calls, send nothing or a plain call-style system message.
- Carry the call type through. A video call must stay video for the invitee, with the camera on by default. A voice call must stay voice, with the camera off.
- For `kind != "meeting"`, hide the meeting-only UI on both clients:
  - waiting room
  - breakouts
  - meeting chat panel
  - whiteboard
  - recording controls
  - the "Meeting" / "Group Video" title (use "Video call" or "Voice call", plus the participant count)
- Confirm the host/admin gating (`canModerate`, `isHost`) still behaves sensibly for calls. Any participant in a call may leave. Only the initiator may end it for everyone, if that is the current rule.

### Acceptance tests (manual)
1. A and B on a video call, A adds C. All three see a call UI, titled as a call, with cameras on. No meeting card in any DM. No waiting-room or breakout controls.
2. Repeat with voice. Cameras stay off.
3. Test B on Android and desktop, and C on Android and desktop, across all pairings.
4. Create a real meeting from the meetings feature. It must still show the full meeting UI, with the card in chat.
5. Kill and relaunch the app mid-call, or join from a second device. It must still show the call UI.

---

## Bug 2: Android calls desktop; Android says Connected (timer running) but desktop stays on "Connecting…"

### Context
Commit `10f2cbb` (Nov 7) already fixed Android showing Connected too early. It now flips to CONNECTED only on the real ICE state (`WebRtcManager.iceConnected`). That fix was cosmetic: it didn't make the call connect. The user still reports desktop stuck on "Connecting…" while Android sits connected. Check which APK version they have, but also fix the underlying signaling bug below.

### Root cause (confirmed by reading; verify at runtime)

**The desktop callee drops every ICE candidate that arrives before its RTCPeerConnection exists.**

Flow when Android (caller) dials the desktop (callee):
1. Android creates a PeerConnection and trickles ICE. It sends each candidate via `POST /calls/ice_candidate`, which the backend relays over WebSocket (or buffers if the recipient's socket is down).
2. The desktop main window is only ringing. The call window (`CallWindowApp` -> `CallModal`) does not exist yet. `desktop/src/services/presence.ts` (~line 132) buffers call events in `callEventBuffer` and replays them to the call window when it opens. That part is fine.
3. The call window opens when the user answers. `CallModal` creates the RTCPeerConnection **inside `acceptCall()`** (`desktop/src/screens/CallModal.tsx` ~line 397, `createPc()`), after `startLocalMedia()`, and only then sets the remote offer.
4. The replayed `ice_candidate` events hit the handler at `CallModal.tsx` ~lines 474-483:
   ```ts
   const pc = pcRef.current;
   if (!pc || !data.candidate) return;      // <-- drops the candidate
   if (!remoteDescSetRef.current) { remoteIceBufRef.current.push(data.candidate); } else { ... }
   ```
   `pcRef.current` is still `null`, so the function returns **before** the candidate is queued. `remoteIceBufRef` (flushed at ~lines 404-407, "Flush ICE candidates that arrived before we accepted") never receives them.
5. The desktop therefore never learns Android's candidates. Its answer SDP does include its own candidates (`waitForIceGathering` runs before the answer), so Android can still reach it. The result is a half-open ICE negotiation:
   - Android reaches ICE connected, so its UI shows Connected and the timer runs.
   - The desktop sits in "connecting", or gets stuck or fails when the path needs Android's candidates (symmetric or carrier NAT, TURN relay).

### Fix requirements
1. In `CallModal.tsx`, queue first and gate only the apply step. Replace the early return with:
   ```ts
   if (!data.candidate) return;
   const pc = pcRef.current;
   if (!pc || !remoteDescSetRef.current) { remoteIceBufRef.current.push(data.candidate); return; }
   try { await pc.addIceCandidate(new RTCIceCandidate(data.candidate)); } catch {}
   ```
   Check that every code path that sets the remote description also flushes `remoteIceBufRef`: `acceptCall` (~404), `applyAnswer` (~329) and any conference/mesh path.
2. Candidates must be filtered by `call_id` against `callIdRef.current`. Make sure that ref is set from the `callId` prop **before** the replay arrives. Otherwise the replayed candidates are discarded by the `Number(data.call_id) === callIdRef.current` check.
3. Do not swallow `addIceCandidate` errors silently. Log them with `console.warn`, including the candidate. Log `pc.iceConnectionState` / `connectionState` transitions on both platforms so this class of bug is diagnosable.
4. Android side, `CallViewModel.kt`:
   - `sendIceCandidate` and `flushPendingCandidates` wrap the API call in `runCatching` and ignore failures. Retry a failed send once or twice with short backoff, and log it.
   - `pendingCandidates` is a plain `mutableListOf` mutated from multiple coroutines and iterated while network calls suspend (a `ConcurrentModificationException` and lost-candidate hazard). Make it thread-safe, for example by snapshotting and clearing under a `Mutex`, or by using a `Channel`.
5. Add a **connection watchdog** on both sides. If ICE hasn't reached connected within ~15 s, trigger an ICE restart or show a clear "couldn't connect" error with a retry. Today the desktop sits on "Connecting…" indefinitely.
6. Check the backend relay too. `forward_ice_candidate` always returns True and buffers in `_pending_ice` (in-memory). `flush_pending_ice` runs only on WS (re)connect (~line 5546). Confirm that buffered candidates for a callee who is connected but not yet in the call window aren't left stranded. They are covered by the desktop replay buffer, but verify `_PENDING_ICE_MAX` isn't truncating real calls. Add a debug log when a candidate is buffered or dropped.
7. Also test the reverse direction (desktop -> Android), Android -> Android and desktop -> desktop, to confirm nothing regressed.

### Acceptance tests (manual)
1. Android (mobile data) -> desktop (Wi-Fi). Let it ring about 10 s, then answer. Both sides must show Connected within a few seconds, with audio and video both ways. Repeat with Android on Wi-Fi.
2. Answer immediately vs after a long ring. Both must work.
3. Open `chrome://webrtc-internals` on desktop (or the Tauri devtools console). Confirm all of Android's candidates are added and the selected candidate pair is succeeded. Check Android logcat for `iceConnectionState=CONNECTED`.
4. Force a bad network (disable TURN). The watchdog must show a clear failure, not hang.

---

## Deliverables
- Code changes in all three places (backend, Android, desktop) plus the migration.
- Short notes on what you confirmed or disproved about each root cause.
- A list of manual tests you ran and their results. Don't claim a fix works unless you ran it.
- Do not commit unless asked. Keep changes minimal and match the surrounding code style.
