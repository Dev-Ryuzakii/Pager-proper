/**
 * Simple Media Upload Example for React Native
 * This example shows how to send media files without encryption
 */

const BASE_URL = 'http://localhost:8001';

// Helper function to handle API responses
const handleResponse = async (response) => {
  if (response.status === 401) {
    throw new Error('Unauthorized. Please log in again.');
  }
  
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return response.json();
  } else {
    // If response is not JSON, return the text
    const text = await response.text();
    // If text is empty, return a success message
    return text || 'Operation successful';
  }
};

// Simple media upload function
export const uploadSimpleMedia = async (mediaData, token) => {
  const response = await fetch(`${BASE_URL}/media/simple_upload`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(mediaData),
  });
  
  return handleResponse(response);
};

// Example usage in a React Native component
import React, { useState } from 'react';
import { View, Button, Image, Alert } from 'react-native';

const SimpleMediaUploadScreen = () => {
  const [imageUri, setImageUri] = useState(null);
  const [userToken, setUserToken] = useState('USER_AUTH_TOKEN'); // Replace with actual token

  // Function to pick an image from gallery (you would use a library like react-native-image-picker)
  const pickImage = async () => {
    // This is a placeholder - in a real app, you would use a library like:
    // import { launchImageLibrary } from 'react-native-image-picker';
    // const result = await launchImageLibrary({ mediaType: 'photo' });
    // if (!result.didCancel && result.assets && result.assets.length > 0) {
    //   setImageUri(result.assets[0].uri);
    // }
    
    // For this example, we'll just simulate picking an image
    Alert.alert('Pick Image', 'In a real app, this would open the image picker');
  };

  // Function to upload the selected image as simple media
  const uploadSimpleMediaFile = async () => {
    if (!imageUri) {
      Alert.alert('Error', 'Please select an image first');
      return;
    }

    try {
      // Convert image to base64
      // In a real app, you would use a library like react-native-fs to read the file
      // const base64Data = await RNFS.readFile(imageUri, 'base64');
      
      // For this example, we'll use a placeholder base64 string
      const base64Data = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=='; // 1x1 transparent PNG
      
      // Prepare media data - ensure no undefined values
      const mediaData = {
        username: 'recipient_username', // Replace with actual recipient
        media_type: 'photo',
        content: base64Data || '',
        filename: 'image.png',
        file_size: base64Data ? base64Data.length : 0, // Approximate size
        content_type: 'image/png', // MIME type
        disappear_after_hours: null // Set to a number if you want disappearing media
      };

      // Remove any undefined values
      Object.keys(mediaData).forEach(key => {
        if (mediaData[key] === undefined || mediaData[key] === 'undefined') {
          delete mediaData[key];
        }
      });

      // Ensure username is provided
      if (!mediaData.username) {
        console.error('Username is required for media upload');
        throw new Error('Username is required');
      }

      // Log the data being sent for debugging
      console.log('Sending media data:', mediaData);

      // Upload the media
      const result = await uploadSimpleMedia(mediaData, userToken);
      
      Alert.alert('Success', `Media uploaded successfully: ${result.message}`);
    } catch (error) {
      Alert.alert('Error', `Failed to upload media: ${error.message}`);
    }
  };

  return (
    <View style={{ flex: 1, padding: 20 }}>
      <Button title="Pick Image" onPress={pickImage} />
      {imageUri && (
        <Image 
          source={{ uri: imageUri }} 
          style={{ width: 200, height: 200, marginVertical: 20 }} 
        />
      )}
      <Button title="Upload Simple Media" onPress={uploadSimpleMediaFile} />
    </View>
  );
};

export default SimpleMediaUploadScreen;