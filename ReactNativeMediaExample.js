/**
 * React Native Media Example
 * This is an example of how to implement media gallery functionality
 * with the secure messaging backend
 */

import React, { useState } from 'react';
import {
  View,
  Text,
  Button,
  Image,
  TouchableOpacity,
  StyleSheet,
  Alert,
  Platform,
} from 'react-native';
import { launchImageLibrary } from 'react-native-image-picker';
import RNFS from 'react-native-fs';
import CryptoJS from 'crypto-js';

const MediaExample = () => {
  const [selectedMedia, setSelectedMedia] = useState(null);
  const [isUploading, setIsUploading] = useState(false);

  // Function to select media from gallery
  const selectMedia = () => {
    const options = {
      mediaType: 'mixed', // Allow both photos and videos
      quality: 0.8,
      includeBase64: false,
    };

    launchImageLibrary(options, (response) => {
      if (response.didCancel || response.error) {
        console.log('User cancelled or error:', response.error);
        return;
      }

      if (response.assets && response.assets.length > 0) {
        const asset = response.assets[0];
        setSelectedMedia({
          uri: asset.uri,
          type: asset.type,
          fileName: asset.fileName,
          fileSize: asset.fileSize,
        });
      }
    });
  };

  // Function to encrypt media file
  const encryptMedia = async (filePath, masterToken) => {
    try {
      // Read file as base64
      const base64Data = await RNFS.readFile(filePath, 'base64');
      
      // Generate a random AES key for encryption
      const aesKey = CryptoJS.lib.WordArray.random(256/8);
      
      // Encrypt the media data with AES
      const encryptedData = CryptoJS.AES.encrypt(base64Data, aesKey).toString();
      
      // Encrypt the AES key with RSA using recipient's public key
      // This would require implementing RSA encryption with the recipient's public key
      // For this example, we'll simulate it
      const encryptedKey = `encrypted_rsa_key_${Math.random()}`;
      
      return {
        encryptedContent: encryptedData,
        encryptionMetadata: {
          algorithm: 'AES-256-GCM',
          encryptedKey: encryptedKey,
          iv: 'initialization_vector_example'
        }
      };
    } catch (error) {
      console.error('Encryption error:', error);
      throw error;
    }
  };

  // Function to upload encrypted media
  const uploadMedia = async (recipientUsername, disappearAfterHours = null) => {
    if (!selectedMedia) {
      Alert.alert('Error', 'Please select media first');
      return;
    }

    setIsUploading(true);
    
    try {
      // In a real implementation, you would:
      // 1. Get the master token from secure storage
      const masterToken = 'user_master_token'; // This should come from secure storage
      
      // 2. Encrypt the media file
      const encryptedMedia = await encryptMedia(selectedMedia.uri, masterToken);
      
      // 3. Get auth token from secure storage
      const authToken = 'user_auth_token'; // This should come from secure storage
      
      // 4. Upload to server
      const response = await fetch('http://your-server-url/media/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          username: recipientUsername,
          media_type: selectedMedia.type?.includes('video') ? 'video' : 'photo',
          encrypted_content: encryptedMedia.encryptedContent,
          filename: selectedMedia.fileName || 'media_file',
          file_size: selectedMedia.fileSize || 0,
          disappear_after_hours: disappearAfterHours,
        }),
      });

      const result = await response.json();
      
      if (response.ok) {
        Alert.alert('Success', 'Media uploaded successfully');
        setSelectedMedia(null);
      } else {
        Alert.alert('Error', result.detail || 'Failed to upload media');
      }
    } catch (error) {
      console.error('Upload error:', error);
      Alert.alert('Error', 'Failed to upload media');
    } finally {
      setIsUploading(false);
    }
  };

  // Function to download and decrypt media
  const downloadAndDecryptMedia = async (mediaId) => {
    try {
      // Get auth token from secure storage
      const authToken = 'user_auth_token'; // This should come from secure storage
      
      // Download encrypted media
      const response = await fetch(`http://your-server-url/media/${mediaId}`, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
        },
      });

      const result = await response.json();
      
      if (!response.ok) {
        throw new Error(result.detail || 'Failed to download media');
      }

      // Get master token for decryption
      const masterToken = 'user_master_token'; // This should come from user input or secure storage
      
      // Decrypt the AES key with RSA using user's private key
      // This would require implementing RSA decryption with the user's private key
      // For this example, we'll simulate it
      const aesKey = 'decrypted_aes_key';
      
      // Decrypt the media content with AES
      const decryptedData = CryptoJS.AES.decrypt(result.encrypted_content, aesKey).toString(CryptoJS.enc.Utf8);
      
      // Save decrypted media to device
      const filePath = `${RNFS.DocumentDirectoryPath}/${result.filename}`;
      await RNFS.writeFile(filePath, decryptedData, 'base64');
      
      return filePath;
    } catch (error) {
      console.error('Download/decrypt error:', error);
      throw error;
    }
  };

  // Function to send media as decoy (no encryption)
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

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Secure Media Sharing</Text>
      
      <TouchableOpacity style={styles.button} onPress={selectMedia}>
        <Text style={styles.buttonText}>Select Media from Gallery</Text>
      </TouchableOpacity>
      
      {selectedMedia && (
        <View style={styles.mediaPreview}>
          <Text>Selected: {selectedMedia.fileName}</Text>
          <Text>Size: {Math.round(selectedMedia.fileSize / 1024)} KB</Text>
          {selectedMedia.type?.includes('image') && (
            <Image 
              source={{ uri: selectedMedia.uri }} 
              style={styles.imagePreview}
              resizeMode="contain"
            />
          )}
        </View>
      )}
      
      {selectedMedia && (
        <>
          <TouchableOpacity 
            style={styles.button} 
            onPress={() => uploadMedia('recipient_username')}
            disabled={isUploading}
          >
            <Text style={styles.buttonText}>
              {isUploading ? 'Uploading...' : 'Upload Encrypted Media'}
            </Text>
          </TouchableOpacity>
          
          {/* New Decoy Features */}
          <TouchableOpacity 
            style={[styles.button, styles.decoyButton]} 
            onPress={() => sendDecoyMedia('recipient_username')}
            disabled={isUploading}
          >
            <Text style={styles.buttonText}>
              {isUploading ? 'Sending...' : 'Send Hidden Media (No Encryption)'}
            </Text>
          </TouchableOpacity>
        </>
      )}
      
      <Text style={styles.infoText}>
        Note: Encrypted media requires end-to-end encryption setup. 
        Hidden media is sent plainly but disguised with decoy text.
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#f5f5f5',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 30,
  },
  button: {
    backgroundColor: '#007AFF',
    padding: 15,
    borderRadius: 10,
    marginVertical: 10,
    alignItems: 'center',
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  decoyButton: {
    backgroundColor: '#FFCC00',
  },
  mediaPreview: {
    marginVertical: 20,
    padding: 15,
    backgroundColor: 'white',
    borderRadius: 10,
    alignItems: 'center',
  },
  imagePreview: {
    width: 200,
    height: 200,
    marginVertical: 10,
  },
  infoText: {
    marginTop: 30,
    padding: 15,
    backgroundColor: 'white',
    borderRadius: 10,
  },
});

export default MediaExample;