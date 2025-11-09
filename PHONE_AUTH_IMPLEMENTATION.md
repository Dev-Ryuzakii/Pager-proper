# Phone Number Authentication Implementation Summary

## Overview
This document summarizes the implementation of phone number-based authentication and admin-only user management for the Pager secure messaging system.

## Key Changes

### 1. Database Schema Updates

#### User Table
- **Added**: `phone_number` column (VARCHAR(20), UNIQUE, NOT NULL)
- **Removed**: `email` column (phone number is now the only contact method)
- **Modified**: `username` kept for backward compatibility but phone_number is now primary identifier
- Phone number is now the unique identifier for user accounts

### 2. Authentication System Changes

#### Removed Public Registration
- `/auth/register` endpoint now returns HTTP 403
- Users can NO LONGER self-register
- Only administrators can create user accounts

#### Updated Login
- Login now uses `phone_number` instead of `username`
- Request format: `{"phone_number": "+1234567890", "token": "user_token"}`
- Response includes both phone_number and username (for backward compatibility)

### 3. Admin-Only User Management

#### Admin Can Create Users
- **Endpoint**: `POST /admin/users`
- **Request**: `{"phone_number": "+1234567890", "token": "user_token", "public_key": "optional"}`
- System auto-generates username from phone number (e.g., `user_1234567890`)
- Only admins with valid session can create users

#### Admin Can Delete Users
- **Endpoint**: `DELETE /admin/users/{phone_number}`
- Deletes user by phone number instead of username
- Removes all associated data (messages, media, sessions, keys)

#### Admin Can View All Users
- **Endpoint**: `GET /admin/users`
- Returns list with both phone_number and username
- Shows registration date, last login, user type, admin status

### 4. Messaging Updates

#### Send Messages
- Now uses `phone_number` instead of `username`
- Request format: `{"phone_number": "+1234567890", "message": "encrypted_content"}`
- All message endpoints updated (text, decoy image, decoy document)

#### Media Upload
- Media upload endpoints use `phone_number`
- Request format: `{"phone_number": "+1234567890", "media_type": "photo", ...}`

### 5. Updated Service Classes

#### UserService
- `authenticate_user()` uses phone_number
- `get_user_by_phone()` added for lookups
- `create_user()` disabled (returns 403)
- `delete_user()` disabled (admin only via AdminService)

#### MessageService
- `send_message()` accepts recipient_phone instead of recipient_username
- All message creation uses phone number for recipient lookup

#### MediaService  
- `upload_media()` uses recipient_phone
- `upload_simple_media()` uses recipient_phone

#### AdminService
- `create_user()` requires phone_number, auto-generates username
- `delete_user()` accepts phone_number parameter

## Migration Guide

### 1. Run Database Migration
```bash
python migrate_add_phone_number.py
```

This script:
- Adds phone_number column to users table
- Populates existing users with placeholder phone numbers (based on user ID)
- Creates unique constraints and indexes
- **Removes email column** (phone number is the only contact method)

### 2. Update Existing Users
After migration, update users with real phone numbers:
```sql
UPDATE users SET phone_number = '+1234567890' WHERE id = 1;
```

Or use the admin interface to update phone numbers.

### 3. Create Admin Account (if needed)
Ensure you have at least one admin account:
```python
python create_admin_user.py
```

### 4. Update Mobile Apps
Mobile applications must be updated to:
- Remove registration forms (users contact admin instead)
- Use phone_number in login requests
- Use phone_number when sending messages/media
- Display phone numbers instead of usernames in UI

## API Changes Summary

### Authentication Endpoints

#### ❌ REMOVED: Public Registration
```
POST /auth/register - Now returns HTTP 403
```

#### ✅ UPDATED: Login
```json
POST /auth/login
Request: {"phone_number": "+1234567890", "token": "user_token"}
Response: {"phone_number": "+1234567890", "username": "user_1234567890", "token": "session_token"}
```

### Admin Endpoints

#### ✅ NEW: Admin Create User
```json
POST /admin/users
Request: {"phone_number": "+1234567890", "token": "user_token"}
Response: {"username": "user_1234567890", "message": "User created successfully"}
```

#### ✅ UPDATED: Admin Delete User
```json
DELETE /admin/users/{phone_number}
Response: {"message": "User account with phone number '+1234567890' deleted successfully", "deleted": true}
```

#### ✅ UPDATED: Admin List Users
```json
GET /admin/users
Response: {
  "users": [
    {
      "phone_number": "+1234567890",
      "username": "user_1234567890",
      "registered": "2025-01-01T00:00:00Z",
      "last_login": "2025-01-02T12:00:00Z",
      "is_active": true,
      "is_admin": false,
      "user_type": "mobile"
    }
  ],
  "count": 1
}
```

### Messaging Endpoints

#### ✅ UPDATED: Send Message
```json
POST /messages/send
Request: {"phone_number": "+1234567890", "message": "encrypted_content"}
Response: {"phone_number": "+1234567890", "message": "sent"}
```

#### ✅ UPDATED: Send Decoy Image
```json
POST /messages/send_decoy_image
Request: {"phone_number": "+1234567890", "image_content": "base64_data", ...}
```

#### ✅ UPDATED: Send Decoy Document
```json
POST /messages/send_decoy_document
Request: {"phone_number": "+1234567890", "document_content": "base64_data", ...}
```

### Media Endpoints

#### ✅ UPDATED: Upload Media
```json
POST /media/upload
Request: {"phone_number": "+1234567890", "media_type": "photo", ...}
```

#### ✅ UPDATED: Simple Media Upload
```json
POST /media/simple_upload
Request: {"phone_number": "+1234567890", "media_type": "photo", ...}
```

#### ✅ UPDATED: Raw Media Upload
```
POST /media/upload_raw
Form data: phone_number=+1234567890, file=<binary>
```

## Security Considerations

### Enhanced Security
1. **Centralized User Management**: Only admins can create/delete users
2. **Phone Number Verification**: Phone numbers can be verified by admin before account creation
3. **Audit Trail**: All admin actions (user creation/deletion) are logged
4. **Single Contact Method**: Phone number only - no email addresses stored

### Phone Number Privacy
1. Phone numbers are stored securely in database
2. Only authenticated users can see phone numbers in their contacts
3. Phone numbers can be used for 2FA implementation in future

## Backward Compatibility

### Username Field Retained
- Username field still exists in database
- Auto-generated from phone number (e.g., `user_1234567890`)
- Kept for backward compatibility with existing code
- Can be displayed in UI if needed

### API Responses
- Login response includes both `phone_number` and `username`
- User list includes both fields
- Gradual migration supported

## Testing

### Test Admin Account
Default admin credentials:
- Username: `admin`
- Password: `adminuser@123`
- Must change password on first login

### Test User Creation
```bash
# Login as admin
curl -X POST http://localhost:8001/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "adminuser@123"}'

# Create user
curl -X POST http://localhost:8001/admin/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"phone_number": "+1234567890", "token": "user_token_123"}'
```

### Test User Login
```bash
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"phone_number": "+1234567890", "token": "user_token_123"}'
```

## Future Enhancements

1. **Phone Number Verification**: Add SMS verification for new users
2. **Country Code Validation**: Validate phone number format by country
3. **Phone Number Formatting**: Auto-format phone numbers for consistency
4. **Contact Import**: Allow users to find contacts by phone number
5. **2FA**: Use phone number for two-factor authentication
6. **Invite System**: Admin can send invite links via SMS

## Rollback Plan

If issues occur, rollback procedure:

1. **Database**: Keep username as primary identifier temporarily
2. **Code**: Revert to username-based authentication
3. **Migration**: Add script to remove phone_number column if needed

```sql
-- Rollback migration (use with caution)
ALTER TABLE users ALTER COLUMN phone_number DROP NOT NULL;
DROP INDEX IF EXISTS idx_users_phone_number;
DROP INDEX IF EXISTS idx_users_phone_number_lookup;
-- Optional: ALTER TABLE users DROP COLUMN phone_number;
-- Note: Email column was removed and would need to be recreated if needed
-- ALTER TABLE users ADD COLUMN email VARCHAR(255);
```

## Support

For questions or issues:
1. Check application logs: `tail -f fastapi_mobile_backend_postgresql.log`
2. Check database: `psql -d secure_messaging -U user`
3. Review audit logs: `SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50;`
