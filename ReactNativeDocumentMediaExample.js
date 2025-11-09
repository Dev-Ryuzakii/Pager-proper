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
  ScrollView,
} from 'react-native';
import { launchImageLibrary } from 'react-native-image-picker';
import DocumentPicker from 'react-native-document-picker';
import RNFS from 'react-native-fs';
import CryptoJS from 'crypto-js';

const DocumentMediaExample = () => {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [isUploading, setIsUploading] = useState(false);

  // Function to select media from gallery (photos/videos) - supports multiple selection
  const selectMedia = () => {
    const options = {
      mediaType: 'mixed', // Allow both photos and videos
      quality: 0.8,
      includeBase64: false,
      selectionLimit: 0, // 0 means unlimited, can select multiple files
    };

    launchImageLibrary(options, (response) => {
      if (response.didCancel || response.error) {
        console.log('User cancelled or error:', response.error);
        return;
      }

      if (response.assets && response.assets.length > 0) {
        // Handle multiple files
        const files = response.assets.map((asset, index) => ({
          id: index,
          uri: asset.uri,
          type: asset.type || 'media',
          fileName: asset.fileName,
          fileSize: asset.fileSize,
          fileType: asset.type?.includes('video') ? 'video' : 'photo',
        }));
        setSelectedFiles(files);
      }
    });
  };

  // Function to select document file
  const selectDocument = async () => {
    try {
      const res = await DocumentPicker.pick({
        type: [DocumentPicker.types.allFiles],
      });
      
      // Handle single document (DocumentPicker doesn't support multiple selection)
      setSelectedFiles([{
        id: 0,
        uri: res.uri,
        type: 'document',
        fileName: res.name,
        fileSize: res.size,
        fileType: 'document',
      }]);
    } catch (err) {
      if (DocumentPicker.isCancel(err)) {
        // User cancelled the picker
      } else {
        console.error('Document picker error:', err);
        Alert.alert('Error', 'Failed to select document');
      }
    }
  };

  // Function to encrypt file
  const encryptFile = async (filePath, masterToken) => {
    try {
      // Read file as base64
      const base64Data = await RNFS.readFile(filePath, 'base64');
      
      // Generate a random AES key for encryption
      const aesKey = CryptoJS.lib.WordArray.random(256/8);
      
      // Encrypt the file data with AES
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

  // Function to upload encrypted file
  const uploadFile = async (recipientUsername, disappearAfterHours = null, file) => {
    try {
      // In a real implementation, you would:
      // 1. Get the master token from secure storage
      const masterToken = 'user_master_token'; // This should come from secure storage
      
      // 2. Encrypt the file
      const encryptedFile = await encryptFile(file.uri, masterToken);
      
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
          media_type: file.fileType, // photo, video, or document
          encrypted_content: encryptedFile.encryptedContent,
          filename: file.fileName || 'file',
          file_size: file.fileSize || 0,
          disappear_after_hours: disappearAfterHours,
        }),
      });

      const result = await response.json();
      
      if (response.ok) {
        return { success: true, result };
      } else {
        return { success: false, error: result.detail || 'Failed to upload file' };
      }
    } catch (error) {
      console.error('Upload error:', error);
      return { success: false, error: 'Failed to upload file' };
    }
  };

  // Function to upload all selected files
  const uploadAllFiles = async (recipientUsername, disappearAfterHours = null) => {
    if (selectedFiles.length === 0) {
      Alert.alert('Error', 'Please select files first');
      return;
    }

    setIsUploading(true);
    
    try {
      const uploadResults = [];
      
      // Upload each file
      for (const file of selectedFiles) {
        const result = await uploadFile(recipientUsername, disappearAfterHours, file);
        uploadResults.push({ file: file.fileName, ...result });
      }
      
      // Check results
      const failedUploads = uploadResults.filter(r => !r.success);
      const successfulUploads = uploadResults.filter(r => r.success);
      
      if (failedUploads.length > 0) {
        Alert.alert(
          'Partial Success', 
          `${successfulUploads.length} files uploaded successfully, ${failedUploads.length} failed.`
        );
      } else {
        Alert.alert('Success', `All ${successfulUploads.length} files uploaded successfully`);
        setSelectedFiles([]);
      }
    } catch (error) {
      console.error('Upload error:', error);
      Alert.alert('Error', 'Failed to upload files');
    } finally {
      setIsUploading(false);
    }
  };

  // Function to download and decrypt file
  const downloadAndDecryptFile = async (mediaId) => {
    try {
      // Get auth token from secure storage
      const authToken = 'user_auth_token'; // This should come from secure storage
      
      // Download encrypted file
      const response = await fetch(`http://your-server-url/media/${mediaId}`, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
        },
      });

      const result = await response.json();
      
      if (!response.ok) {
        throw new Error(result.detail || 'Failed to download file');
      }

      // Get master token for decryption
      const masterToken = 'user_master_token'; // This should come from user input or secure storage
      
      // Decrypt the AES key with RSA using user's private key
      // This would require implementing RSA decryption with the user's private key
      // For this example, we'll simulate it
      const aesKey = 'decrypted_aes_key';
      
      // Decrypt the file content with AES
      const decryptedData = CryptoJS.AES.decrypt(result.encrypted_content, aesKey).toString(CryptoJS.enc.Utf8);
      
      // Save decrypted file to device
      const filePath = `${RNFS.DocumentDirectoryPath}/${result.filename}`;
      await RNFS.writeFile(filePath, decryptedData, 'base64');
      
      return filePath;
    } catch (error) {
      console.error('Download/decrypt error:', error);
      throw error;
    }
  };

  return (
    <ScrollView style={styles.container}>
      <Text style={styles.title}>Secure File Sharing</Text>
      <Text style={styles.subtitle}>Send Photos, Videos, and Documents</Text>
      
      <View style={styles.buttonContainer}>
        <TouchableOpacity style={styles.button} onPress={selectMedia}>
          <Text style={styles.buttonText}>Select Media from Gallery</Text>
        </TouchableOpacity>
        
        <TouchableOpacity style={[styles.button, styles.documentButton]} onPress={selectDocument}>
          <Text style={styles.buttonText}>Select Document</Text>
        </TouchableOpacity>
      </View>
      
      {selectedFiles.length > 0 && (
        <View style={styles.filePreview}>
          <Text style={styles.previewTitle}>Selected Files ({selectedFiles.length}):</Text>
          {selectedFiles.map((file) => (
            <View key={file.id} style={styles.fileItem}>
              <Text>Filename: {file.fileName}</Text>
              <Text>Type: {file.fileType}</Text>
              <Text>Size: {Math.round(file.fileSize / 1024)} KB</Text>
              {file.fileType === 'photo' && (
                <Image 
                  source={{ uri: file.uri }} 
                  style={styles.imagePreview}
                  resizeMode="contain"
                />
              )}
            </View>
          ))}
        </View>
      )}
      
      {selectedFiles.length > 0 && (
        <View style={styles.buttonContainer}>
          <TouchableOpacity 
            style={styles.button} 
            onPress={() => uploadAllFiles('recipient_username')}
            disabled={isUploading}
          >
            <Text style={styles.buttonText}>
              {isUploading ? 'Uploading...' : `Send ${selectedFiles.length} File(s)`}
            </Text>
          </TouchableOpacity>
          
          <TouchableOpacity 
            style={[styles.button, styles.disappearButton]} 
            onPress={() => uploadAllFiles('recipient_username', 24)}
            disabled={isUploading}
          >
            <Text style={styles.buttonText}>
              {isUploading ? 'Uploading...' : `Send File(s) (Disappears in 24h)`}
            </Text>
          </TouchableOpacity>
        </View>
      )}
      
      <View style={styles.infoSection}>
        <Text style={styles.infoTitle}>How it works:</Text>
        <Text>1. Select files from your device (multiple photos/videos or single document)</Text>
        <Text>2. Files are encrypted locally on your device</Text>
        <Text>3. Encrypted files are sent to the secure server</Text>
        <Text>4. Recipient uses their master token to decrypt</Text>
      </View>
    </ScrollView>
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
    marginBottom: 10,
  },
  subtitle: {
    fontSize: 16,
    textAlign: 'center',
    marginBottom: 30,
    color: '#666',
  },
  buttonContainer: {
    marginBottom: 20,
  },
  button: {
    backgroundColor: '#007AFF',
    padding: 15,
    borderRadius: 10,
    marginVertical: 10,
    alignItems: 'center',
  },
  documentButton: {
    backgroundColor: '#34C759',
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  disappearButton: {
    backgroundColor: '#FF3B30',
  },
  filePreview: {
    marginVertical: 20,
    padding: 15,
    backgroundColor: 'white',
    borderRadius: 10,
  },
  previewTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  fileItem: {
    marginBottom: 15,
    padding: 10,
    backgroundColor: '#f0f0f0',
    borderRadius: 5,
  },
  imagePreview: {
    width: 200,
    height: 200,
    marginVertical: 10,
  },
  infoSection: {
    marginTop: 30,
    padding: 15,
    backgroundColor: 'white',
    borderRadius: 10,
  },
  infoTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
  },
});

export default DocumentMediaExample;