# React Native Media Integration Guide

This guide explains how to integrate media functionality (sending and receiving images, videos, and documents) with the FastAPI backend in a React Native application.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Required Dependencies](#required-dependencies)
3. [Media Upload Integration](#media-upload-integration)
4. [Media Download Integration](#media-download-integration)
5. [Media Gallery Implementation](#media-gallery-implementation)
6. [Security Considerations](#security-considerations)

## Prerequisites

Before implementing media functionality, ensure you have:
- A working React Native project
- Backend server running on `http://localhost:8001` (or your deployed URL)
- User authentication implemented
- Master token setup for decryption

## Required Dependencies

Install the following packages:

```bash
npm install react-native-image-picker react-native-document-picker react-native-fs crypto-js
```

For iOS, also run:
```bash
cd ios && pod install
```

## Media Upload Integration

### 1. Select Media from Device

```javascript
import { launchImageLibrary } from 'react-native-image-picker';
import DocumentPicker from 'react-native-document-picker';

// Select media (photos/videos)
const selectMedia = () => {
  const options = {
    mediaType: 'mixed', // 'photo', 'video', or 'mixed'
    quality: 0.8,
    includeBase64: false,
  };

  launchImageLibrary(options, (response) => {
    if (response.didCancel || response.error) {
      console.log('User cancelled or error');
      return;
    }

    if (response.assets && response.assets.length > 0) {
      const asset = response.assets[0];
      // Process selected media
      processMediaUpload(asset);
    }
  });
};

// Select documents
const selectDocument = async () => {
  try {
    const result = await DocumentPicker.pick({
      type: [DocumentPicker.types.allFiles],
    });
    
    // Process selected document
    processDocumentUpload(result[0]);
  } catch (err) {
    if (DocumentPicker.isCancel(err)) {
      // User cancelled the picker
    } else {
      throw err;
    }
  }
};
```

### 2. Encrypt and Upload Media

```javascript
import RNFS from 'react-native-fs';
import CryptoJS from 'crypto-js';

// Encrypt media file
const encryptMedia = async (filePath, masterToken) => {
  try {
    // Read file as base64
    const fileContent = await RNFS.readFile(filePath, 'base64');
    
    // Generate random AES key
    const aesKey = CryptoJS.lib.WordArray.random(256/8);
    
    // Encrypt file content
    const encryptedContent = CryptoJS.AES.encrypt(fileContent, aesKey).toString();
    
    // In a real implementation, you would also encrypt the AES key 
    // with the recipient's public key here
    
    return {
      encrypted_content: encryptedContent,
      // Add other encryption metadata as needed
    };
  } catch (error) {
    console.error('Encryption error:', error);
    throw error;
  }
};

// Upload encrypted media
const uploadMedia = async (recipient, mediaData, mediaType, filename, fileSize) => {
  try {
    const response = await fetch('http://localhost:8001/media/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`, // User's session token
      },
      body: JSON.stringify({
        username: recipient,
        media_type: mediaType, // 'photo', 'video', or 'document'
        encrypted_content: mediaData.encrypted_content,
        filename: filename,
        file_size: fileSize,
        // Optional: disappear_after_hours: 24
      }),
    });

    const result = await response.json();
    
    if (response.ok) {
      console.log('Media uploaded successfully:', result);
      return result;
    } else {
      console.error('Upload failed:', result);
      throw new Error(result.detail || 'Upload failed');
    }
  } catch (error) {
    console.error('Upload error:', error);
    throw error;
  }
};

// Complete media upload process
const processMediaUpload = async (mediaAsset) => {
  try {
    // Encrypt the media file
    const encryptedMedia = await encryptMedia(mediaAsset.uri, userMasterToken);
    
    // Upload to server
    const uploadResult = await uploadMedia(
      recipientUsername,
      encryptedMedia,
      mediaAsset.type === 'image' ? 'photo' : 'video',
      mediaAsset.fileName || 'media_file',
      mediaAsset.fileSize || 0
    );
    
    console.log('Upload completed:', uploadResult);
    Alert.alert('Success', 'Media sent successfully');
  } catch (error) {
    console.error('Media upload failed:', error);
    Alert.alert('Error', 'Failed to send media');
  }
};
```

## Media Download Integration

### 1. Get Media Inbox

```javascript
// Fetch user's media inbox
const getMediaInbox = async () => {
  try {
    const response = await fetch('http://localhost:8001/media/inbox', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${sessionToken}`,
      },
    });

    const result = await response.json();
    
    if (response.ok) {
      console.log('Media inbox:', result);
      return result.media_files;
    } else {
      console.error('Failed to fetch media inbox:', result);
      throw new Error(result.detail || 'Failed to fetch media');
    }
  } catch (error) {
    console.error('Error fetching media inbox:', error);
    throw error;
  }
};
```

### 2. Download and Decrypt Media

```javascript
// Download encrypted media
const downloadMedia = async (mediaId) => {
  try {
    const response = await fetch(`http://localhost:8001/media/${mediaId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${sessionToken}`,
      },
    });

    const result = await response.json();
    
    if (response.ok) {
      console.log('Media downloaded:', result);
      return result;
    } else {
      console.error('Download failed:', result);
      throw new Error(result.detail || 'Download failed');
    }
  } catch (error) {
    console.error('Download error:', error);
    throw error;
  }
};

// Decrypt media file
const decryptMedia = async (encryptedMedia, masterToken) => {
  try {
    // In a real implementation, you would:
    // 1. Decrypt the AES key with your private key
    // 2. Decrypt the media content with the AES key
    // 3. Return the decrypted content
    
    // For demonstration, we'll just return the encrypted content
    // since server-side decryption is disabled for security
    return encryptedMedia.encrypted_content;
  } catch (error) {
    console.error('Decryption error:', error);
    throw error;
  }
};

// Complete media download and display process
const downloadAndDisplayMedia = async (mediaId) => {
  try {
    // Download encrypted media
    const encryptedMedia = await downloadMedia(mediaId);
    
    // Note: In a real app, you would decrypt the media here
    // But for security reasons, decryption must happen on the device
    // and the server does not provide this functionality for mobile users
    
    console.log('Encrypted media ready for local decryption:', encryptedMedia);
    
    // In a real implementation, you would then:
    // 1. Decrypt the media locally using the user's private key
    // 2. Display the decrypted media in the app
    
    return encryptedMedia;
  } catch (error) {
    console.error('Media download failed:', error);
    Alert.alert('Error', 'Failed to download media');
  }
};
```

## Media Gallery Implementation

### Display Media in a Gallery

```javascript
import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  FlatList,
  TouchableOpacity,
  Image,
  Alert,
  StyleSheet,
} from 'react-native';

const MediaGallery = () => {
  const [mediaFiles, setMediaFiles] = useState([]);
  const [loading, setLoading] = useState(false);

  // Load media inbox
  const loadMediaInbox = async () => {
    setLoading(true);
    try {
      const mediaList = await getMediaInbox();
      setMediaFiles(mediaList);
    } catch (error) {
      Alert.alert('Error', 'Failed to load media');
    } finally {
      setLoading(false);
    }
  };

  // Render media item
  const renderMediaItem = ({ item }) => (
    <TouchableOpacity 
      style={styles.mediaItem}
      onPress={() => handleMediaPress(item)}
    >
      <View style={styles.mediaHeader}>
        <Text style={styles.sender}>From: {item.sender}</Text>
        <Text style={styles.timestamp}>
          {new Date(item.timestamp).toLocaleDateString()}
        </Text>
      </View>
      
      <View style={styles.mediaContent}>
        <Text style={styles.filename}>{item.filename}</Text>
        <Text style={styles.filetype}>{item.media_type}</Text>
        <Text style={styles.filesize}>{(item.file_size / 1024).toFixed(1)} KB</Text>
      </View>
      
      {item.auto_delete && item.expires_at && (
        <Text style={styles.expires}>
          Expires: {new Date(item.expires_at).toLocaleDateString()}
        </Text>
      )}
    </TouchableOpacity>
  );

  // Handle media press (download and decrypt)
  const handleMediaPress = async (mediaItem) => {
    try {
      // Download the encrypted media
      const encryptedMedia = await downloadAndDisplayMedia(mediaItem.id);
      
      // In a real app, you would decrypt and display the media here
      Alert.alert(
        'Media Ready', 
        'Encrypted media downloaded. In a real app, this would be decrypted and displayed.',
        [
          {
            text: 'OK',
            onPress: () => {
              // Navigate to media viewer screen
              // navigation.navigate('MediaViewer', { mediaData: encryptedMedia });
            }
          }
        ]
      );
    } catch (error) {
      Alert.alert('Error', 'Failed to process media');
    }
  };

  useEffect(() => {
    loadMediaInbox();
  }, []);

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Media Gallery</Text>
        <TouchableOpacity onPress={loadMediaInbox} disabled={loading}>
          <Text style={styles.refreshButton}>
            {loading ? 'Loading...' : 'Refresh'}
          </Text>
        </TouchableOpacity>
      </View>
      
      <FlatList
        data={mediaFiles}
        renderItem={renderMediaItem}
        keyExtractor={(item) => item.id.toString()}
        ListEmptyComponent={
          <Text style={styles.emptyText}>
            {loading ? 'Loading media...' : 'No media files'}
          </Text>
        }
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
    backgroundColor: '#f5f5f5',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
  },
  refreshButton: {
    color: '#007AFF',
    fontSize: 16,
  },
  mediaItem: {
    backgroundColor: 'white',
    padding: 16,
    marginVertical: 8,
    borderRadius: 8,
    elevation: 2,
  },
  mediaHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 8,
  },
  sender: {
    fontWeight: 'bold',
    fontSize: 16,
  },
  timestamp: {
    color: '#666',
    fontSize: 12,
  },
  mediaContent: {
    marginBottom: 8,
  },
  filename: {
    fontSize: 14,
    marginBottom: 4,
  },
  filetype: {
    fontSize: 12,
    color: '#007AFF',
    marginBottom: 2,
  },
  filesize: {
    fontSize: 12,
    color: '#666',
  },
  expires: {
    fontSize: 12,
    color: '#FF3B30',
    fontStyle: 'italic',
  },
  emptyText: {
    textAlign: 'center',
    marginTop: 50,
    fontSize: 16,
    color: '#666',
  },
});

export default MediaGallery;
```

## Security Considerations

### End-to-End Encryption

The system implements end-to-end encryption for all media files:

1. **Client-Side Encryption**: All media is encrypted on the device before upload
2. **Zero-Knowledge Server**: The server cannot decrypt media files
3. **Private Key Storage**: Private keys are stored only on the user's device
4. **Master Token**: Required for decryption on the client device

### Implementation Notes

1. **Local Decryption Only**: Media decryption must happen on the client device
2. **Private Key Management**: Never store private keys on the server
3. **Secure Storage**: Use device keychain/keystore for key storage
4. **Master Token Security**: Never send master tokens to the server in plain text

### Error Handling

Always implement proper error handling for:
- Network failures
- Encryption/decryption errors
- File system errors
- Authentication failures

## API Endpoints Reference

### Media Upload
```
POST /media/upload
Authorization: Bearer {session_token}
Content-Type: application/json

{
  "username": "recipient_username",
  "media_type": "photo|video|document",
  "encrypted_content": "base64_encoded_encrypted_content",
  "filename": "original_filename.ext",
  "file_size": 12345,
  "disappear_after_hours": 24 // Optional
}
```

### Get Media Inbox
```
GET /media/inbox
Authorization: Bearer {session_token}
```

### Download Media
```
GET /media/{media_id}
Authorization: Bearer {session_token}
```

## Next Steps

1. Implement proper client-side encryption using RSA/AES
2. Add media preview functionality
3. Implement secure key storage using device keychain
4. Add support for progress indicators during upload/download
5. Implement media caching for better performance
6. Add support for media playback (videos, audio)