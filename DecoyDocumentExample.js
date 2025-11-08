/**
 * Decoy Document Messaging Example for React Native
 * This example shows how to send documents hidden under decoy text
 * and integrate with document reading apps after master token validation
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

// Send decoy document function
export const sendDecoyDocument = async (documentData, token) => {
  const response = await fetch(`${BASE_URL}/messages/send_decoy_document`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(documentData),
  });
  
  return handleResponse(response);
};

// Extract hidden document function
export const extractHiddenDocument = async (extractData, token) => {
  const response = await fetch(`${BASE_URL}/messages/extract_decoy_document`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(extractData),
  });
  
  return handleResponse(response);
};

// Open document with external app (React Native specific)
const openDocumentWithApp = async (base64Data, filename, mimeType, suggestedApps) => {
  try {
    // In a real React Native app, you would use a library like:
    // import RNFS from 'react-native-fs';
    // import { Linking } from 'react-native';
    // import Share from 'react-native-share';
    
    console.log(`Opening document with one of these apps: ${suggestedApps.join(', ')}`);
    console.log(`Document: ${filename} (${mimeType})`);
    
    // Example implementation (this is pseudo-code for React Native):
    /*
    // Save the document to a temporary file
    const filePath = `${RNFS.DocumentDirectoryPath}/${filename}`;
    await RNFS.writeFile(filePath, base64Data, 'base64');
    
    // Open with a specific app or let the system choose
    if (Platform.OS === 'android') {
      // Android implementation
      const url = `file://${filePath}`;
      await Share.open({ url, type: mimeType, filename });
    } else {
      // iOS implementation
      const url = `file://${filePath}`;
      await Linking.openURL(url);
    }
    */
    
    alert(`Document saved successfully! Suggested apps to open it: ${suggestedApps.join(', ')}`);
  } catch (error) {
    console.error('Error opening document:', error);
    alert('Failed to open document. Please try manually opening it.');
  }
};

// Example usage in a React Native component
import React, { useState } from 'react';
import { View, Button, Alert, TextInput, ScrollView, Text, Platform } from 'react-native';

const DecoyDocumentMessagingScreen = () => {
  const [userToken, setUserToken] = useState('');
  const [recipientUsername, setRecipientUsername] = useState('');
  const [masterToken, setMasterToken] = useState('');
  const [messageId, setMessageId] = useState('');
  const [documentFilename, setDocumentFilename] = useState('document.pdf');
  const [documentMimeType, setDocumentMimeType] = useState('application/pdf');

  // Function to pick a document from file system
  const pickDocument = async () => {
    // This is a placeholder - in a real app, you would use a library like:
    // import DocumentPicker from 'react-native-document-picker';
    // const res = await DocumentPicker.pick({
    //   type: [DocumentPicker.types.allFiles],
    // });
    // Then read the file content as base64
    
    Alert.alert('Pick Document', 'In a real app, this would open the document picker');
  };

  // Function to send document hidden under decoy text
  const sendHiddenDocument = async () => {
    if (!recipientUsername) {
      Alert.alert('Error', 'Please enter a recipient username');
      return;
    }

    try {
      // For this example, we'll use a placeholder base64 string
      const base64DocumentData = 'JVBERi0xLjQKJcOkw7zDtsO' + '...'; // Truncated PDF header
      
      // Prepare document data
      const documentData = {
        username: recipientUsername,
        document_content: base64DocumentData,
        filename: documentFilename,
        file_size: base64DocumentData.length,
        mime_type: documentMimeType,
        disappear_after_hours: null // Set to a number if you want disappearing documents
      };

      // Log the data being sent for debugging
      console.log('Sending hidden document data:', documentData);

      // Send the hidden document
      const result = await sendDecoyDocument(documentData, userToken);
      
      Alert.alert('Success', `Document sent successfully: ${JSON.stringify(result)}`);
      setMessageId(result.message_id.toString());
    } catch (error) {
      console.error('Send error:', error);
      Alert.alert('Error', `Failed to send hidden document: ${error.message}`);
    }
  };

  // Function to extract hidden document using master token
  const extractDocument = async () => {
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

      // Extract the hidden document
      const result = await extractHiddenDocument(extractData, userToken);
      
      // Display success message and suggest apps
      if (result.document_data) {
        Alert.alert(
          'Success', 
          `Document extracted successfully!\nFilename: ${result.filename}\nSuggested apps: ${result.suggested_apps.join(', ')}`,
          [
            {
              text: 'Open with App',
              onPress: () => openDocumentWithApp(
                result.document_data, 
                result.filename, 
                result.mime_type, 
                result.suggested_apps
              )
            },
            { text: 'OK', style: 'cancel' }
          ]
        );
      } else {
        Alert.alert('Error', 'No document data found in the response');
      }
    } catch (error) {
      console.error('Extract error:', error);
      Alert.alert('Error', `Failed to extract hidden document: ${error.message}`);
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
      <TextInput
        placeholder="Document filename (e.g., report.pdf)"
        value={documentFilename}
        onChangeText={setDocumentFilename}
        style={{ borderWidth: 1, padding: 10, marginBottom: 10 }}
      />
      <TextInput
        placeholder="MIME type (e.g., application/pdf)"
        value={documentMimeType}
        onChangeText={setDocumentMimeType}
        style={{ borderWidth: 1, padding: 10, marginBottom: 10 }}
      />
      <Button title="Pick Document" onPress={pickDocument} />
      
      <Button title="Send Hidden Document" onPress={sendHiddenDocument} />
      
      <TextInput
        placeholder="Enter message ID to extract document"
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
      <Button title="Extract Hidden Document" onPress={extractDocument} />
      
      <View style={{ marginVertical: 20 }}>
        <Text style={{ fontWeight: 'bold', marginBottom: 10 }}>Supported Document Apps:</Text>
        <Text>• Microsoft 365 Suite (Word, Excel, PowerPoint)</Text>
        <Text>• WPS Office</Text>
        <Text>• Adobe Acrobat (PDFs)</Text>
        <Text>• Google Workspace (Docs, Sheets, Slides)</Text>
        <Text>• Apple iWork (Pages, Numbers, Keynote)</Text>
      </View>
    </ScrollView>
  );
};

export default DecoyDocumentMessagingScreen;