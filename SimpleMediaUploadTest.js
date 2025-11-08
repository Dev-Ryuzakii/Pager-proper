/**
 * Simple Media Upload Test for React Native
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
  // Remove any undefined values
  const cleanMediaData = {};
  Object.keys(mediaData).forEach(key => {
    if (mediaData[key] !== undefined && mediaData[key] !== 'undefined' && mediaData[key] !== null) {
      cleanMediaData[key] = mediaData[key];
    }
  });

  console.log('Sending clean media data:', cleanMediaData);

  const response = await fetch(`${BASE_URL}/media/simple_upload`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(cleanMediaData),
  });
  
  return handleResponse(response);
};

// Example usage in a React Native component
import React, { useState } from 'react';
import { View, Button, Image, Alert, TextInput } from 'react-native';

const SimpleMediaUploadTest = () => {
  const [imageUri, setImageUri] = useState(null);
  const [userToken, setUserToken] = useState(''); // Replace with actual token
  const [recipientUsername, setRecipientUsername] = useState('');

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
    if (!recipientUsername) {
      Alert.alert('Error', 'Please enter a recipient username');
      return;
    }

    try {
      // For this example, we'll use a placeholder base64 string
      const base64Data = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=='; // 1x1 transparent PNG
      
      // Prepare media data - ensure no undefined values
      const mediaData = {
        username: recipientUsername,
        media_type: 'photo',
        content: base64Data,
        filename: 'test_image.png',
        file_size: base64Data.length,
        content_type: 'image/png',
        disappear_after_hours: null // Set to a number if you want disappearing media
      };

      // Log the data being sent for debugging
      console.log('Sending media data:', mediaData);

      // Upload the media
      const result = await uploadSimpleMedia(mediaData, userToken);
      
      Alert.alert('Success', `Media uploaded successfully: ${JSON.stringify(result)}`);
    } catch (error) {
      console.error('Upload error:', error);
      Alert.alert('Error', `Failed to upload media: ${error.message}`);
    }
  };

  return (
    <View style={{ flex: 1, padding: 20 }}>
      <TextInput
        placeholder="Enter recipient username"
        value={recipientUsername}
        onChangeText={setRecipientUsername}
        style={{ borderWidth: 1, padding: 10, marginBottom: 10 }}
      />
      <TextInput
        placeholder="Enter user token"
        value={userToken}
        onChangeText={setUserToken}
        style={{ borderWidth: 1, padding: 10, marginBottom: 10 }}
      />
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

export default SimpleMediaUploadTest;