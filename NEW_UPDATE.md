# Frontend Usage Breakdown — New Update

This guide explains how the frontend should use the updated auth and media APIs. No new endpoints; existing ones behave slightly differently and return new error cases.

---

## 1. Auth & Tokens (User / Master Token)

### What changed for the frontend
- **One token per user.** A given auth token can only belong to one account. Reusing a token for another user will be rejected.
- **Master token** is now validated against the server. Create and confirm must be called correctly for decryption to work.

### Registration / user creation
- When **registering** (TLS) or when an **admin creates a user**, the app sends a **safetoken** (auth token) for that user.
- If that token is already used by another user, the server returns an error.

**Handle this in the UI:**
- **TLS registration:** If the server returns an error like `"Token already in use by another user"`, ask the user to choose a different token or generate a new one.
- **Admin create user:** Same message in the API response. Show a clear error (e.g. “This token is already assigned to another user. Use a unique token.”) and do not create the user until a unique token is provided.

**Example error response (e.g. 400):**
```json
{
  "detail": "Token already in use by another user"
}
```

### Master token (decryption)
- **Create:** `POST /mastertoken/create` with body `{ "mastertoken": "<user's master token>" }`.  
  The server stores it securely. Call this when the user sets or changes their master token.
- **Confirm:** `POST /mastertoken/confirm` with body `{ "mastertoken": "<same token>" }`.  
  The server validates it. If invalid, you get `401` and should ask the user to re-enter.
- **Decryption:** Endpoints that require a master token (e.g. decrypt message) now validate it properly. Send the same `mastertoken` in the request body. If the server returns invalid master token, prompt the user to re-enter or re-confirm.

**Example confirm error (401):**
```json
{
  "detail": "Invalid master token"
}
```

**Frontend flow suggestion:**
1. User enters master token → call **create** then **confirm**.
2. If **confirm** returns 401, show “Invalid master token” and let the user try again.
3. When calling decrypt APIs, always send the current master token; handle 401 by asking the user to confirm again.

---

## 2. Media Upload (Leak-Detection Watermarks)

### What the frontend needs to know
- **No new endpoints.** Use the same upload endpoints as before.
- **Images and PDFs** are automatically watermarked on the server (for leak detection). The file the recipient downloads will contain up to 5 subtle marks. You do not need to do anything extra in the request.
- **Other file types** (e.g. video, generic binary) are stored as-is; no watermarking.

### Endpoints to use (unchanged)

#### Option A: Simple upload (base64)
**`POST /media/simple_upload`**

- **Headers:** `Authorization: Bearer <user token>`
- **Body (JSON):** e.g.
  - `username` — recipient username  
  - `content` — base64-encoded file content  
  - `filename` — original filename (e.g. `photo.jpg`, `report.pdf`)  
  - `media_type` — `"photo"` | `"video"` | `"document"`  
  - `content_type` — MIME type (e.g. `image/jpeg`, `application/pdf`)  
  - `file_size` — size in bytes  
  - `disappear_after_hours` — optional

**Frontend usage:** Same as before. For images and PDFs, the server will watermark before saving. Response still returns `media_id` and metadata; use them to show or download the media later.

#### Option B: Raw file upload (multipart)
**`POST /media/upload_raw`**

- **Headers:** `Authorization: Bearer <user token>`
- **Body (form):**
  - `username` — recipient username  
  - `file` — the file (multipart)  
  - `disappear_after_hours` — optional

**Frontend usage:** Same as before. Send the file; for images and PDFs the server watermarks automatically. Response includes `media_id`, `filename`, `file_size`, `content_type`; use `media_id` for download.

### Download
- **By integer id (encrypted media):** `GET /media/{media_id}` (e.g. from inbox list).
- **By string media_id (raw uploads):** `GET /media/download/{media_id}`.

No changes to request/response from the frontend; the file returned may just contain the leak-detection watermark (images/PDFs).

### What to show in the UI
- **Upload:** No extra steps. “Send image/document” works as before; watermarks are applied server-side.
- **Download / open:** Same as before. Recipients see the same image or PDF, with subtle watermarking they may not notice unless they look for it.
- **Errors:** Use the same error handling as today (e.g. 404, 403, 500). No new error codes for watermarking; if watermarking fails on the server, the original file is still stored.

---

## 3. Quick Reference for Frontend

| Action | Method / Endpoint | Frontend notes |
|--------|-------------------|-----------------|
| Register / create user with token | TLS register or admin create user | Handle **“Token already in use by another user”**; ask for a unique token. |
| Set master token | `POST /mastertoken/create` then `POST /mastertoken/confirm` | Handle **401 Invalid master token** on confirm; ask user to re-enter. |
| Decrypt (message, etc.) | Existing decrypt endpoints with `mastertoken` in body | On 401 invalid master token, prompt to re-enter / re-confirm. |
| Upload image/PDF | `POST /media/simple_upload` or `POST /media/upload_raw` | No change. Server adds watermarks automatically. |
| Download media | `GET /media/{id}` or `GET /media/download/{media_id}` | No change. |

---

## 4. Error Handling Summary

| Scenario | HTTP | Response / action in UI |
|----------|------|-------------------------|
| Token already used by another user | 400 | Show: “This token is already in use. Please use a different token.” |
| Invalid master token (confirm or decrypt) | 401 | Show: “Invalid master token.” and allow re-entry. |
| Other auth/validation errors | 4xx / 5xx | Use existing error handling. |

This document is the **frontend usage breakdown** for the new update; backend implementation details are not required for integrating the app.
