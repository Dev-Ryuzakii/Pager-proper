# Secure Messaging API Documentation

## Overview

This document provides documentation for the Secure Messaging API with PostgreSQL backend.

## API Endpoints

### Authentication

#### POST /auth/register
Register a new user.

**Request Body:**
```json
{
  "username": "string",
  "token": "string",
  "public_key": "string (optional)"
}
```

**Response:**
```json
{
  "username": "string",
  "token": "string"
}
```

#### POST /auth/login
Login an existing user.

**Request Body:**
```json
{
  "username": "string",
  "token": "string"
}
```

**Response:**
```json
{
  "username": "string",
  "token": "string"
}
```

#### POST /auth/logout
Logout the current user.

**Response:**
```json
{
  "message": "Logout successful"
}
```

### Messages

#### POST /messages/send
Send a message to another user.

**Request Body:**
```json
{
  "username": "string",
  "message": "string",
  "disappear_after_hours": "integer (optional)"
}
```

**Response:**
```json
{
  "username": "string",
  "message": "sent",
  "expires_at": "string (ISO 8601 format, only if disappear_after_hours is specified)",
  "auto_delete": "boolean (only if disappear_after_hours is specified)"
}
```

**Note:** If `disappear_after_hours` is provided and greater than 0, the message will automatically be deleted after the specified number of hours.

#### GET /messages/inbox
Get the user's inbox messages.

**Response:**
```json
{
  "messages": [
    {
      "id": "integer",
      "sender": "string",
      "recipient": "string",
      "content": "string",
      "content_type": "string",
      "timestamp": "string (ISO 8601 format)",
      "delivered": "boolean",
      "read": "boolean"
    }
  ],
  "count": "integer"
}
```

#### GET /messages/offline
Get offline messages for the user.

**Response:**
```json
{
  "messages": [
    {
      "id": "integer",
      "sender": "string",
      "recipient": "string",
      "content": "string",
      "content_type": "string",
      "timestamp": "string (ISO 8601 format)"
    }
  ],
  "count": "integer"
}
```

#### PUT /messages/{message_id}/read
Mark a message as read.

**Response:**
``json
{
  "message": "Message marked as read"
}
```

#### POST /messages/cleanup
Manually trigger cleanup of expired messages.

**Response:**
```json
{
  "message": "Cleanup completed. X expired messages deleted.",
  "deleted_count": "integer"
}
```

### Users

#### GET /users
Get a list of all users.

**Response:**
```json
{
  "users": [
    {
      "username": "string",
      "registered": "string (ISO 8601 format)",
      "last_login": "string (ISO 8601 format or null)"
    }
  ],
  "count": "integer"
}
```

#### GET /users/{username}/public_key
Get a user's public key.

**Response:**
```json
{
  "username": "string",
  "public_key": "string or null"
}
```

### Master Tokens

#### POST /mastertoken/create
Create a master token.

**Request Body:**
```json
{
  "mastertoken": "string"
}
```

**Response:**
```json
{
  "mastertoken": "created"
}
```

#### POST /mastertoken/confirm
Confirm a master token.

**Request Body:**
```json
{
  "mastertoken": "string"
}
```

**Response:**
```json
{
  "mastertoken": "confirmed"
}
```

### System

#### GET /
Get API information.

**Response:**
```json
{
  "message": "Secure Messaging API with PostgreSQL",
  "version": "string",
  "status": "string",
  "database": "string"
}
```

#### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "string (ISO 8601 format)"
}
```

#### GET /status
Get system status.

**Response:**
```json
{
  "status": "string",
  "version": "string",
  "database": "string",
  "users_count": "integer",
  "messages_count": "integer",
  "active_sessions": "integer",
  "timestamp": "string (ISO 8601 format)"
}
```

## Disappearing Messages

The API supports disappearing messages that automatically delete themselves after a specified time period.

### How it works

1. When sending a message, you can optionally specify the `disappear_after_hours` parameter
2. If provided, the message will be marked for automatic deletion
3. A background cleanup process runs periodically to delete expired messages
4. Expired messages are permanently deleted from the database

### Usage

To send a disappearing message that will be deleted after 12 hours:

```json
{
  "username": "recipient_username",
  "message": "This message will disappear after 12 hours",
  "disappear_after_hours": 12
}
```

The response will include expiration information:

```json
{
  "username": "recipient_username",
  "message": "sent",
  "expires_at": "2023-10-31T20:00:00Z",
  "auto_delete": "true"
}
```

### Automatic Cleanup

A background worker runs periodically to clean up expired messages. The cleanup process:

1. Runs every hour by default
2. Finds all messages marked for auto-deletion that have expired
3. Permanently deletes those messages from the database
4. Logs the number of deleted messages

### Manual Cleanup

You can also manually trigger cleanup by calling the `/messages/cleanup` endpoint.

## Media Handling

The API supports secure handling of encrypted media files (photos and videos) and document files from user devices.

### Media Upload

#### POST /media/upload
Upload an encrypted media or document file.

**Request Body:**
```json
{
  "username": "string",
  "media_type": "string", // "photo", "video", or "document"
  "encrypted_content": "string", // Base64 encoded encrypted file content
  "filename": "string", // Original filename
  "file_size": "integer", // File size in bytes
  "disappear_after_hours": "integer (optional)" // Hours after which file should disappear
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

### Media Retrieval

#### GET /media/inbox
Get the user's media and document inbox.

**Response:**
``json
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

#### GET /media/{media_id}
Download an encrypted media or document file.

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

### Disappearing Media and Documents

Media and document files support the same disappearing functionality as text messages:

1. When uploading, you can optionally specify the `disappear_after_hours` parameter
2. If provided, the file will be marked for automatic deletion
3. A background cleanup process runs periodically to delete expired files
4. Expired files are permanently deleted from the server

### Manual Media Cleanup

You can manually trigger cleanup of expired media by calling the `/media/cleanup` endpoint.
