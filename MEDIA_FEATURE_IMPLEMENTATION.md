# Media Feature Implementation

## Overview

This document describes the implementation of the media gallery feature for the secure messaging system. The feature allows users to:
1. Select photos and videos from their device gallery
2. Encrypt them locally on the device
3. Upload the encrypted media to the server
4. Send the encrypted media to other users
5. Recipients can download and decrypt the media using their master token

## Architecture

### Backend Components

1. **Database Model**: Added [Media](file:///c:/Users/gbenl/Pager-proper/database_models.py#L142-L182) table to store media metadata
2. **API Endpoints**: Added new endpoints for media upload, retrieval, and cleanup
3. **Service Layer**: Added [MediaService](file:///c:/Users/gbenl/Pager-proper/fastapi_mobile_backend_postgresql.py#L788-L917) for handling media operations
4. **File Storage**: Encrypted media files are stored on the server filesystem

### Frontend Integration

The React Native example demonstrates how to:
1. Access device gallery using `react-native-image-picker`
2. Encrypt media files locally using AES-256
3. Upload encrypted media to the backend
4. Download and decrypt media using master token authentication

## Database Schema

### Media Table

```sql
CREATE TABLE media (
    id SERIAL PRIMARY KEY,
    media_id VARCHAR(255) UNIQUE NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_size INTEGER NOT NULL,
    media_type VARCHAR(50) NOT NULL, -- photo, video
    content_type VARCHAR(100) NOT NULL, -- MIME type
    encryption_metadata JSON,
    encrypted_file_path VARCHAR(512) NOT NULL,
    message_id INTEGER NOT NULL REFERENCES messages(id),
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    expires_at TIMESTAMP,
    auto_delete BOOLEAN DEFAULT FALSE,
    uploaded_at TIMESTAMP DEFAULT NOW(),
    downloaded_at TIMESTAMP
);
```

## API Endpoints

### POST /media/upload
Upload an encrypted media file.

**Request Body:**
```json
{
  "username": "string",
  "media_type": "string", // "photo" or "video"
  "encrypted_content": "string", // Base64 encoded encrypted media content
  "filename": "string",
  "file_size": "integer",
  "disappear_after_hours": "integer (optional)"
}
```

**Response:**
```json
{
  "media_id": "string",
  "filename": "string",
  "media_type": "string",
  "message": "Media uploaded successfully"
}
```

### GET /media/inbox
Get the user's media inbox.

**Response:**
```json
{
  "media_files": [
    {
      "id": "integer",
      "media_id": "string",
      "filename": "string",
      "media_type": "string",
      "content_type": "string",
      "file_size": "integer",
      "sender": "string",
      "recipient": "string",
      "timestamp": "string (ISO 8601 format)",
      "expires_at": "string (ISO 8601 format or null)",
      "auto_delete": "boolean",
      "downloaded": "boolean"
    }
  ],
  "count": "integer"
}
```

### GET /media/{media_id}
Download an encrypted media file.

**Response:**
```json
{
  "media_id": "string",
  "filename": "string",
  "media_type": "string",
  "content_type": "string",
  "file_size": "integer",
  "encrypted_content": "string", // Base64 encoded encrypted content
  "encryption_metadata": "object or null"
}
```

### POST /media/cleanup
Manually trigger cleanup of expired media files.

**Response:**
```json
{
  "message": "Cleanup completed. X expired media files deleted.",
  "deleted_count": "integer"
}
```

## Security Features

1. **End-to-End Encryption**: Media files are encrypted locally on the device before upload
2. **Zero-Knowledge Architecture**: Server never sees unencrypted media content
3. **Master Token Authentication**: Required for media decryption
4. **Automatic Cleanup**: Disappearing media feature for enhanced privacy
5. **Secure File Storage**: Encrypted files stored with unique identifiers

## Implementation Details

### 1. Media Upload Process

1. User selects media from device gallery
2. Client app encrypts media with AES-256
3. AES key is encrypted with recipient's RSA public key
4. Encrypted media is uploaded as base64 string
5. Server stores encrypted file and metadata in database
6. Associated message is created for notification

### 2. Media Download Process

1. Recipient requests media using media ID
2. Server verifies user authorization
3. Encrypted file is retrieved from storage
4. Encrypted content is sent to client
5. Client decrypts using master token and private key
6. Decrypted media is displayed to user

### 3. Disappearing Media

1. When uploading, user can specify `disappear_after_hours`
2. Media is marked with expiration timestamp
3. Background cleanup process runs periodically
4. Expired media files are deleted from storage and database

## Client-Side Implementation

The React Native example demonstrates:

1. **Gallery Access**: Using `react-native-image-picker` to select media
2. **Local Encryption**: Using `crypto-js` for AES encryption
3. **API Integration**: Uploading encrypted media to backend
4. **Decryption**: Downloading and decrypting media with master token

## Testing

The [test_media_feature.py](file:///c:/Users/gbenl/Pager-proper/test_media_feature.py) script provides automated testing for:
1. Media upload functionality
2. File storage and retrieval
3. Database operations
4. Cleanup processes

## Deployment

1. Ensure `media_uploads` directory exists and is writable
2. Update database schema with new Media table
3. Deploy updated FastAPI backend
4. Integrate client-side components in mobile app

## Future Enhancements

1. **Progressive Upload**: Support for large media files with progress tracking
2. **Thumbnail Generation**: Server-side thumbnail creation for previews
3. **Streaming Support**: For large video files
4. **Compression**: Optional media compression before encryption
5. **Batch Operations**: Upload multiple media files in a single request