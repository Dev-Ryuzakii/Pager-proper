# Watermarks and File/PDF Sending — Comprehensive Guide

This document describes how media (images, PDFs, documents, videos) are uploaded, stored, watermarked for leak detection, and delivered in the Pager secure messaging system.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Upload Methods and Watermarking](#2-upload-methods-and-watermarking)
3. [Watermark System](#3-watermark-system)
4. [File Storage and Database](#4-file-storage-and-database)
5. [Download and Retrieval](#5-download-and-retrieval)
6. [API Reference](#6-api-reference)
7. [Leak Detection and Forensics](#7-leak-detection-and-forensics)

---

## 1. Overview

The system supports three ways to send media:

| Method | Endpoint | Watermarked? | Use Case |
|--------|----------|--------------|----------|
| **Encrypted upload** | `POST /media/upload` | No | Client encrypts before upload; server never sees plaintext |
| **Simple upload** | `POST /media/simple_upload` | Yes | Unencrypted base64; server watermarks images & PDFs |
| **Raw upload** | `POST /media/upload_raw` | Yes | Multipart file upload; server watermarks images & PDFs |

**Watermarking** is applied automatically for **images** and **PDFs** in simple and raw uploads. It embeds a traceable payload so that if media is leaked, administrators can identify which recipient received that copy.

---

## 2. Upload Methods and Watermarking

### 2.1 Encrypted Upload (`POST /media/upload`)

- **Content:** Client encrypts the file (e.g. AES) before sending.
- **Server:** Stores the encrypted blob as-is. No watermarking (server cannot see plaintext).
- **Watermarking:** If leak detection is needed, the client must watermark the file before encrypting and uploading.

**Request body:**
```json
{
  "username": "recipient_username",
  "media_type": "photo",
  "encrypted_content": "<base64-encoded encrypted bytes>",
  "filename": "photo.jpg",
  "file_size": 102400
}
```

**Response:**
```json
{
  "media_id": "uuid-string",
  "filename": "photo.jpg",
  "media_type": "photo",
  "message": "Media uploaded successfully"
}
```

---

### 2.2 Simple Upload (`POST /media/simple_upload`)

- **Content:** Unencrypted base64. Server receives plain bytes.
- **Watermarking:** Applied to images (JPEG, PNG, GIF, WebP, BMP) and PDFs before saving. Up to 5 watermarks per file.
- **Storage:** File is saved to `media_uploads/{media_id}` (no `.enc` extension).

**Request body:**
```json
{
  "username": "recipient_username",
  "media_type": "photo",
  "content": "<base64-encoded file bytes>",
  "filename": "report.pdf",
  "file_size": 50000,
  "content_type": "application/pdf",
  "disappear_after_hours": null
}
```

**Flow:**
1. Server decodes base64 → raw bytes
2. Server calls `apply_watermark(bytes, content_type, filename, recipient_id, media_id)`
3. For images/PDFs: watermark is embedded; other types pass through unchanged
4. Watermarked (or original) bytes are written to disk
5. `Message` and `Media` records are created in the database

**Response:**
```json
{
  "media_id": "uuid-string",
  "filename": "report.pdf",
  "media_type": "document",
  "message": "Simple media uploaded successfully"
}
```

---

### 2.3 Raw Upload (`POST /media/upload_raw`)

- **Content:** Multipart form with file binary (no base64).
- **Watermarking:** Same as simple upload—images and PDFs are watermarked before saving.
- **Storage:** File saved as `media_uploads/{uuid}{original_extension}` (e.g. `a1b2c3d4-....pdf`).

**Request:** `multipart/form-data`
- `username` (form field): recipient username
- `file` (file): the file to upload
- `disappear_after_hours` (optional): hours until auto-delete

**Flow:**
1. Server reads file bytes with `await file.read()`
2. Server calls `apply_watermark(bytes, content_type, filename, recipient_id, unique_filename)`
3. Watermarked (or original) bytes are written to disk
4. `Message` and `Media` records are created

**Response:**
```json
{
  "media_id": "uuid-with-extension.pdf",
  "filename": "report.pdf",
  "file_size": 50000,
  "content_type": "application/pdf",
  "message": "File uploaded successfully",
  "uploaded_for": "recipient_username",
  "disappear_after_hours": null
}
```

---

## 3. Watermark System

### 3.1 Purpose

If a user forwards or screenshots media and shares it outside the app, the embedded watermark allows administrators to identify:
- **Who** received that copy (recipient)
- **Which** media item it was (media_id)

### 3.2 Payload Format

The watermark text follows this pattern:
```
R{recipient_id}#{short_media_id}
```
- `recipient_id`: numeric user ID in the database
- `short_media_id`: first 8 characters of the media UUID (hyphens removed)

**Example:** `R42#a1b2c3d4` → recipient user ID 42, media_id prefix `a1b2c3d4`.

### 3.3 Watermark Count

Up to **5 watermarks** per file:
- **Images:** 5 positions—top-left, top-right, center, bottom-left, bottom-right (as proportions of width/height)
- **PDFs:** First 5 pages receive the overlay; remaining pages are unchanged

### 3.4 Supported File Types

| Type | Extensions / MIME | Watermarked? |
|------|-------------------|--------------|
| Images | `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.bmp` or `image/*` | Yes |
| PDF | `.pdf` or `application/pdf` | Yes |
| Video, other | e.g. `.mp4`, `.docx`, etc. | No (stored as-is) |

### 3.5 Implementation Details

- **Images:** Pillow (PIL) overlays semi-transparent gray text (alpha 80) at 5 positions. Font size scales with image size. Output format: PNG for `image/png`, JPEG for others (quality 92).
- **PDFs:** pypdf merges a small watermark PDF (text rendered as image) onto the first 5 pages, scaled to 30%.
- **Fallback:** If Pillow or pypdf is missing, or watermarking fails, the original bytes are returned unchanged. Upload still succeeds.

### 3.6 Dependencies

- `Pillow` (PIL) for image handling
- `pypdf` for PDF manipulation

---

## 4. File Storage and Database

### 4.1 Storage Layout

All media files are stored under `media_uploads/`:

| Upload Type | Path Example |
|-------------|--------------|
| Encrypted | `media_uploads/{uuid}.enc` |
| Simple | `media_uploads/{uuid}` (no extension) |
| Raw | `media_uploads/{uuid}{original_extension}` |

### 4.2 Database Schema (Media Table)

| Column | Description |
|--------|-------------|
| `id` | Integer primary key |
| `media_id` | Unique string (UUID or `{uuid}.ext`) |
| `filename` | Original filename |
| `file_size` | Size in bytes (may change after watermarking) |
| `media_type` | `photo`, `video`, `document`, or `raw` |
| `content_type` | MIME type |
| `encrypted_file_path` | Path on disk (used for both encrypted and unencrypted) |
| `message_id` | FK to `messages` |
| `sender_id` | FK to `users` |
| `recipient_id` | FK to `users` |
| `expires_at` | Optional expiration |
| `auto_delete` | Whether to delete when expired |
| `uploaded_at` | Creation time |
| `downloaded_at` | When recipient first downloaded (nullable) |

Each upload creates:
1. A `Message` row (sender, recipient, content ref, expiration)
2. A `Media` row (file metadata, path, ownership)

---

## 5. Download and Retrieval

### 5.1 Media Inbox

**`GET /media/inbox`**

Returns the current user’s received media. Each item includes `id` (integer) and `media_id` (string), plus metadata.

**Response:**
```json
{
  "media_files": [
    {
      "id": 123,
      "media_id": "uuid-string",
      "filename": "report.pdf",
      "media_type": "document",
      "content_type": "application/pdf",
      "file_size": 50000,
      "sender": "alice",
      "recipient": "bob",
      "timestamp": "2025-02-06T12:00:00",
      "expires_at": null,
      "auto_delete": false,
      "downloaded": false
    }
  ],
  "count": 1
}
```

### 5.2 Download by Integer ID (Encrypted / Simple Uploads)

**`GET /media/{media_id}`**

- `media_id` is the **integer** `id` from the inbox (e.g. `123`), not the UUID string.
- Used for media uploaded via `/media/upload` or `/media/simple_upload`.

**Response (encrypted upload):**
```json
{
  "media_id": "uuid-string",
  "filename": "photo.jpg",
  "media_type": "photo",
  "content_type": "image/jpeg",
  "file_size": 102400,
  "encrypted_content": "<base64>",
  "encryption_metadata": { ... }
}
```

**Response (simple upload):** Same shape; `encrypted_content` contains base64 of the stored file (watermarked if image/PDF). Client can display or save directly.

### 5.3 Download by String media_id (Raw Uploads)

**`GET /media/download/{media_id}`**

- `media_id` is the **string** identifier (e.g. `a1b2c3d4-5678-90ab-cdef-1234567890ab.pdf`).
- Returns the file as binary with `Content-Disposition: attachment`.

---

## 6. API Reference Summary

| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| POST | `/media/upload` | Bearer | Upload encrypted media (no watermark) |
| POST | `/media/simple_upload` | Bearer | Upload unencrypted base64 (watermarked) |
| POST | `/media/upload_raw` | Bearer | Upload raw file multipart (watermarked) |
| GET | `/media/inbox` | Bearer | List received media |
| GET | `/media/{id}` | Bearer | Download by integer id (encrypted/simple) |
| GET | `/media/download/{media_id}` | Bearer | Download by string media_id (raw) |

---

## 7. Leak Detection and Forensics

### 7.1 Finding the Watermark

Watermarks appear as semi-transparent text on:
- **Images:** Corners and center
- **PDFs:** First 5 pages (small overlay)

They may be faint; zoom or adjust contrast if needed.

### 7.2 Decoding the Payload

Format: `R{recipient_id}#{short_media_id}`

**Example:** `R42#a1b2c3d4`

1. **recipient_id = 42** → Look up in `users` table to get the recipient’s username/phone.
2. **short_media_id = a1b2c3d4** → Search `media` table for `media_id` containing this prefix (e.g. `a1b2c3d4-5678-...`) to get full message and metadata.

### 7.3 Admin Lookup Example

```sql
-- Find recipient
SELECT id, username, phone_number FROM users WHERE id = 42;

-- Find media
SELECT * FROM media WHERE media_id LIKE 'a1b2c3d4%';
```

### 7.4 Limitations

- **Encrypted uploads:** No server-side watermark; client would need to watermark before encrypting.
- **Videos and non-image/PDF files:** Not watermarked; stored as-is.
- **Cropping/editing:** Heavy editing might remove or obscure watermarks.
