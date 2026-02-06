# Frontend Update Required

This document lists the frontend changes needed to work with the updated backend.

---

## 1. One-Time View (Media Auto-Delete)

Media is deleted from the server after the user opens/downloads it. Users cannot access it again.

### Handle 410 Gone

When the user tries to open or download media that was already viewed:

- **Status:** `410 Gone`
- **Response body:** `{ "detail": "Media was deleted after viewing. Cannot access again." }`

**Action:** Detect 410 and show a user-friendly message instead of a generic error.

**Example (fetch):**
```javascript
const res = await fetch(`/media/download/${mediaId}`, { headers: { Authorization: `Bearer ${token}` } });
if (res.status === 410) {
  // Show: "Already viewed – media is no longer available"
  return;
}
```

### Use `downloaded` Flag from Inbox

`GET /media/inbox` returns `downloaded: true` for media the user has already viewed.

**Action:** Use this to:
- Show "Already viewed" on the media item
- Disable or gray out the download/open button
- Optionally avoid calling the download endpoint for already-viewed items

---

## 2. Auth Token Uniqueness

### Registration / Create User – Token Already in Use

When registering (TLS) or when an admin creates a user with a token that is already assigned to another user:

- **Status:** `400 Bad Request`
- **Response body:** `{ "detail": "Token already in use by another user" }`

**Action:** Show a clear message and ask the user to choose a different token or generate a new one.

---

## 3. Master Token Validation

### Invalid Master Token on Confirm

When the user confirms their master token and it does not match what was stored:

- **Status:** `401 Unauthorized`
- **Response body:** `{ "detail": "Invalid master token" }`

**Action:** Show "Invalid master token" and let the user re-enter it.

### Invalid Master Token on Decrypt

When decrypting a message with an invalid or expired master token:

- **Status:** `401 Unauthorized`
- **Response body:** `{ "detail": "Invalid master token. Master token is required for message decryption." }` (or similar)

**Action:** Show an error and prompt the user to re-enter or re-confirm their master token.

---

## 4. No Changes Required

| Feature | Notes |
|---------|-------|
| **Watermarking** | Same upload endpoints and payloads; server applies watermarks automatically |
| **Upload endpoints** | `/media/simple_upload` and `/media/upload_raw` – no request/response changes |
| **Download request format** | Same URL patterns and headers |

---

## 5. Error Handling Summary

| Status | Scenario | Suggested UI Message |
|--------|----------|----------------------|
| 400 | Token already in use | "This token is already in use. Please use a different token." |
| 401 | Invalid master token | "Invalid master token. Please try again." |
| 410 | Media already viewed | "Already viewed – media is no longer available." |
| 404 | Media or file not found | "Media not found." |
| 403 | Access denied | "You don't have access to this media." |

---

## 6. Checklist

- [ ] Handle 410 when opening/downloading media (show "Already viewed" or similar)
- [ ] Use `downloaded` from inbox to mark viewed media and optionally disable re-download
- [ ] Handle 400 "Token already in use by another user" on registration/admin create user
- [ ] Handle 401 "Invalid master token" on master token confirm and decrypt flows
- [ ] Add user-friendly messages for 400, 401, and 410 errors
