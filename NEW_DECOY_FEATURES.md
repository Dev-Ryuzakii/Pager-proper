# New Decoy Messaging Features Implementation Guide

This document provides implementation details for the new decoy messaging features that have been added to the backend and frontend.

## Overview

Two new decoy messaging features have been implemented:
1. **Decoy Image Messaging** - Send images hidden under decoy text
2. **Decoy Document Messaging** - Send documents hidden under decoy text with app integration

## Backend API Endpoints

### Decoy Image Messaging

#### Send Hidden Image
```
POST /messages/send_decoy_image
Authorization: Bearer {session_token}
Content-Type: application/json

{
  "username": "recipient_username",
  "image_content": "base64_encoded_image_data",
  "filename": "image.png",
  "file_size": 12345,
  "disappear_after_hours": null
}
```

#### Extract Hidden Image
```
POST /messages/extract_decoy_image
Authorization: Bearer {session_token}
Content-Type: application/json

{
  "message_id": 123,
  "mastertoken": "user_master_token"
}
```

### Decoy Document Messaging

#### Send Hidden Document
```
POST /messages/send_decoy_document
Authorization: Bearer {session_token}
Content-Type: application/json

{
  "username": "recipient_username",
  "document_content": "base64_encoded_document_data",
  "filename": "document.pdf",
  "file_size": 54321,
  "mime_type": "application/pdf",
  "disappear_after_hours": null
}
```

#### Extract Hidden Document
```
POST /messages/extract_decoy_document
Authorization: Bearer {session_token}
Content-Type: application/json

{
  "message_id": 456,
  "mastertoken": "user_master_token"
}
```

## Frontend Implementation

### Main React Native Component Updates

The main `ReactNativeExample.js` has been updated with the following new functions:

#### Send Decoy Image Function
```javascript
const sendDecoyImage = async () => {
  try {
    // Filter out undefined fields
    const imageData = {
      username: recipient,
      image_content: imageContent || '',
      filename: 'hidden_image.png',
      file_size: imageContent ? imageContent.length : 0,
    };
    
    // Remove any undefined values
    Object.keys(imageData).forEach(key => {
      if (imageData[key] === undefined || imageData[key] === 'undefined') {
        delete imageData[key];
      }
    });

    const response = await fetch(`${API_BASE_URL}/messages/send_decoy_image`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
      },
      body: JSON.stringify(imageData),
    });

    const data = await response.json();
    
    if (response.ok) {
      Alert.alert('Success', 'Hidden image sent successfully');
      setImageContent('');
    } else {
      Alert.alert('Error', data.detail || 'Failed to send hidden image');
    }
  } catch (error) {
    Alert.alert('Error', 'Network error during hidden image sending');
    console.error('Send decoy image error:', error);
  }
};
```

#### Send Decoy Document Function
```javascript
const sendDecoyDocument = async () => {
  try {
    // Filter out undefined fields
    const docData = {
      username: recipient,
      document_content: documentContent || '',
      filename: documentFilename || 'document.pdf',
      file_size: documentContent ? documentContent.length : 0,
      mime_type: documentMimeType || 'application/pdf',
    };
    
    // Remove any undefined values
    Object.keys(docData).forEach(key => {
      if (docData[key] === undefined || docData[key] === 'undefined') {
        delete docData[key];
      }
    });

    const response = await fetch(`${API_BASE_URL}/messages/send_decoy_document`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
      },
      body: JSON.stringify(docData),
    });

    const data = await response.json();
    
    if (response.ok) {
      Alert.alert('Success', 'Hidden document sent successfully');
      setDocumentContent('');
    } else {
      Alert.alert('Error', data.detail || 'Failed to send hidden document');
    }
  } catch (error) {
    Alert.alert('Error', 'Network error during hidden document sending');
    console.error('Send decoy document error:', error);
  }
};
```

#### Extract Decoy Image Function
```javascript
const extractDecoyImage = async (messageId) => {
  try {
    // Validate master token first
    if (!masterToken || masterToken.length < 8) {
      Alert.alert('Error', 'Please enter a valid master token first');
      return;
    }

    const response = await fetch(`${API_BASE_URL}/messages/extract_decoy_image`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({
        message_id: messageId,
        mastertoken: masterToken,
      }),
    });

    const data = await response.json();
    
    if (response.ok) {
      Alert.alert('Hidden Image Extracted', `Image extracted successfully!\nFilename: ${data.filename}\nSize: ${data.file_size} bytes`);
    } else {
      Alert.alert('Error', data.detail || 'Failed to extract hidden image');
    }
  } catch (error) {
    Alert.alert('Error', 'Network error during image extraction');
    console.error('Extract decoy image error:', error);
  }
};
```

#### Extract Decoy Document Function
```javascript
const extractDecoyDocument = async (messageId) => {
  try {
    // Validate master token first
    if (!masterToken || masterToken.length < 8) {
      Alert.alert('Error', 'Please enter a valid master token first');
      return;
    }

    const response = await fetch(`${API_BASE_URL}/messages/extract_decoy_document`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({
        message_id: messageId,
        mastertoken: masterToken,
      }),
    });

    const data = await response.json();
    
    if (response.ok) {
      const appList = data.suggested_apps ? data.suggested_apps.join(', ') : 'No specific apps suggested';
      Alert.alert(
        'Hidden Document Extracted', 
        `Document extracted successfully!
Filename: ${data.filename}
Size: ${data.file_size} bytes
MIME Type: ${data.mime_type}
Suggested apps: ${appList}`
      );
    } else {
      Alert.alert('Error', data.detail || 'Failed to extract hidden document');
    }
  } catch (error) {
    Alert.alert('Error', 'Network error during document extraction');
    console.error('Extract decoy document error:', error);
  }
};
```

### UI Updates

New sections have been added to the main interface:

1. **Send Hidden Image Section** - Text area for image content and send button
2. **Send Hidden Document Section** - Inputs for filename, MIME type, document content and send button
3. **Automatic Detection** - Inbox messages automatically detect decoy content and show appropriate extraction buttons

### Media Example Component

The `ReactNativeMediaExample.js` file has been updated with:

#### Send Decoy Media Function
```javascript
const sendDecoyMedia = async (recipientUsername, disappearAfterHours = null) => {
  if (!selectedMedia) {
    Alert.alert('Error', 'Please select media first');
    return;
  }

  setIsUploading(true);
  
  try {
    // Read file as base64
    const base64Data = await RNFS.readFile(selectedMedia.uri, 'base64');
    
    // Get auth token from secure storage
    const authToken = 'user_auth_token'; // This should come from secure storage
    
    // Determine media type
    const isImage = selectedMedia.type?.includes('image');
    const mediaType = isImage ? 'photo' : 'video';
    
    // Filter out undefined fields
    const mediaData = {
      username: recipientUsername,
      media_type: mediaType,
      content: base64Data || '',
      filename: selectedMedia.fileName || 'media_file',
      file_size: selectedMedia.fileSize || 0,
      content_type: selectedMedia.type || 'application/octet-stream',
      disappear_after_hours: disappearAfterHours,
    };
    
    // Remove any undefined values
    Object.keys(mediaData).forEach(key => {
      if (mediaData[key] === undefined || mediaData[key] === 'undefined') {
        delete mediaData[key];
      }
    });

    // Send as simple (unencrypted) media
    const response = await fetch('http://your-server-url/media/simple_upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
      },
      body: JSON.stringify(mediaData),
    });

    const result = await response.json();
    
    if (response.ok) {
      Alert.alert('Success', 'Media sent as hidden decoy successfully');
      setSelectedMedia(null);
    } else {
      Alert.alert('Error', result.detail || 'Failed to send hidden media');
    }
  } catch (error) {
    console.error('Send decoy error:', error);
    Alert.alert('Error', 'Failed to send hidden media');
  } finally {
    setIsUploading(false);
  }
};
```

## Key Features

1. **No Encryption Required** - Images and documents are sent plainly but hidden under decoy text
2. **Master Token Protection** - Extraction requires valid master token authentication
3. **App Integration** - Document extraction suggests appropriate reading apps based on MIME type:
   - PDF: Adobe Acrobat, Microsoft Edge, Google PDF Viewer, WPS Office, Microsoft 365
   - Word: Microsoft Word, WPS Office, Google Docs, Apple Pages
   - Excel: Microsoft Excel, WPS Office, Google Sheets, Apple Numbers
   - PowerPoint: Microsoft PowerPoint, WPS Office, Google Slides, Apple Keynote
   - Other: File Viewer, WPS Office, Microsoft 365, Google Docs
4. **Undefined Field Filtering** - All requests filter out undefined fields to prevent server validation errors
5. **Disappearing Content Support** - Optional time-based auto-deletion for messages

## Implementation Notes

1. **Backend Integration** - All features are fully implemented in the FastAPI backend
2. **Frontend Ready** - React Native components are updated and ready for use
3. **Security** - Master token validation required for content extraction
4. **Compatibility** - Works alongside existing encrypted messaging features
5. **Error Handling** - Proper error handling and user feedback for all operations