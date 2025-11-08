/**
 * Decoy Image Messaging Example for React Native
 * This example shows how to send images hidden under decoy text
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

// Send decoy image function
export const sendDecoyImage = async (imageData, token) => {
  const response = await fetch(`${BASE_URL}/messages/send_decoy_image`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(imageData),
  });
  
  return handleResponse(response);
};

// Extract hidden image function
export const extractHiddenImage = async (extractData, token) => {
  const response = await fetch(`${BASE_URL}/messages/extract_decoy_image`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(extractData),
  });
  
  return handleResponse(response);
};

// Example usage in a React Native component
import React, { useState } from 'react';
import { View, Button, Image, Alert, TextInput, ScrollView } from 'react-native';

const DecoyImageMessagingScreen = () => {
  const [imageUri, setImageUri] = useState(null);
  const [userToken, setUserToken] = useState('');
  const [recipientUsername, setRecipientUsername] = useState('');
  const [masterToken, setMasterToken] = useState('');
  const [messageId, setMessageId] = useState('');
  const [extractedImage, setExtractedImage] = useState(null);

  // Function to pick an image from gallery
  const pickImage = async () => {
    // This is a placeholder - in a real app, you would use a library like:
    // import { launchImageLibrary } from 'react-native-image-picker';
    // const result = await launchImageLibrary({ mediaType: 'photo' });
    // if (!result.didCancel && result.assets && result.assets.length > 0) {
    //   setImageUri(result.assets[0].uri);
    // }
    
    Alert.alert('Pick Image', 'In a real app, this would open the image picker');
  };

  // Function to send image hidden under decoy text
  const sendHiddenImage = async () => {
    if (!recipientUsername) {
      Alert.alert('Error', 'Please enter a recipient username');
      return;
    }

    try {
      // For this example, we'll use a placeholder base64 string
      const base64ImageData = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=='; // 1x1 transparent PNG
      
      // Prepare image data
      const imageData = {
        username: recipientUsername,
        image_content: base64ImageData,
        filename: 'hidden_image.png',
        file_size: base64ImageData.length,
        disappear_after_hours: null // Set to a number if you want disappearing images
      };

      // Log the data being sent for debugging
      console.log('Sending hidden image data:', imageData);

      // Send the hidden image
      const result = await sendDecoyImage(imageData, userToken);
      
      Alert.alert('Success', `Image sent successfully: ${JSON.stringify(result)}`);
      setMessageId(result.message_id.toString());
    } catch (error) {
      console.error('Send error:', error);
      Alert.alert('Error', `Failed to send hidden image: ${error.message}`);
    }
  };

  // Function to extract hidden image using master token
  const extractImage = async () => {
    if (!messageId) {
      Alert.alert('Error', 'Please enter a message ID');
      return;
    }

    if (!masterToken) {
      Alert.alert('Error', 'Please enter your master token');
      return;
    }

    try {
      // Prepare extraction data
      const extractData = {
        mastertoken: masterToken,
        message_id: parseInt(messageId)
      };

      // Extract the hidden image
      const result = await extractHiddenImage(extractData, userToken);
      
      // Display the extracted image
      if (result.image_data) {
        setExtractedImage(`data:image/png;base64,${result.image_data}`);
        Alert.alert('Success', `Image extracted successfully! Filename: ${result.filename}`);
      } else {
        Alert.alert('Error', 'No image data found in the response');
      }
    } catch (error) {
      console.error('Extract error:', error);
      Alert.alert('Error', `Failed to extract hidden image: ${error.message}`);
    }
  };

  return (
    <ScrollView style={{ flex: 1, padding: 20 }}>
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
      
      <Button title="Send Hidden Image" onPress={sendHiddenImage} />
      
      <TextInput
        placeholder="Enter message ID to extract image"
        value={messageId}
        onChangeText={setMessageId}
        keyboardType="numeric"
        style={{ borderWidth: 1, padding: 10, marginVertical: 10 }}
      />
      <TextInput
        placeholder="Enter master token"
        value={masterToken}
        onChangeText={setMasterToken}
        secureTextEntry={true}
        style={{ borderWidth: 1, padding: 10, marginBottom: 10 }}
      />
      <Button title="Extract Hidden Image" onPress={extractImage} />
      
      {extractedImage && (
        <View style={{ marginVertical: 20 }}>
          <Text>Extracted Image:</Text>
          <Image 
            source={{ uri: extractedImage }} 
            style={{ width: 200, height: 200, marginTop: 10 }} 
          />
        </View>
      )}
    </ScrollView>
  );
};

export default DecoyImageMessagingScreen;