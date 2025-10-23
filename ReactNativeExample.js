/**
 * Example React Native component demonstrating API usage
 * This is a simplified example for educational purposes
 */

import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  Alert,
  ScrollView,
  StyleSheet,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

const SecureMessagingApp = () => {
  const [username, setUsername] = useState('');
  const [token, setToken] = useState('');
  const [masterToken, setMasterToken] = useState('');
  const [recipient, setRecipient] = useState('');
  const [message, setMessage] = useState('');
  const [inbox, setInbox] = useState([]);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [sessionToken, setSessionToken] = useState('');

  // Base URL - update for your deployment
  const API_BASE_URL = 'http://localhost:8001';

  // Register user
  const registerUser = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: username,
          token: token,
        }),
      });

      const data = await response.json();
      
      if (response.ok) {
        Alert.alert('Success', 'User registered successfully');
        // Auto-login after registration
        setSessionToken(data.token);
        await AsyncStorage.setItem('sessionToken', data.token);
        setIsLoggedIn(true);
      } else {
        Alert.alert('Error', data.detail || 'Registration failed');
      }
    } catch (error) {
      Alert.alert('Error', 'Network error during registration');
      console.error('Registration error:', error);
    }
  };

  // Login user
  const loginUser = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: username,
          token: token,
        }),
      });

      const data = await response.json();
      
      if (response.ok) {
        setSessionToken(data.token);
        await AsyncStorage.setItem('sessionToken', data.token);
        setIsLoggedIn(true);
        Alert.alert('Success', 'Logged in successfully');
      } else {
        Alert.alert('Error', data.detail || 'Login failed');
      }
    } catch (error) {
      Alert.alert('Error', 'Network error during login');
      console.error('Login error:', error);
    }
  };

  // Logout user
  const logoutUser = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sessionToken}`,
        },
      });

      if (response.ok) {
        await AsyncStorage.removeItem('sessionToken');
        setSessionToken('');
        setIsLoggedIn(false);
        setUsername('');
        setToken('');
        setInbox([]);
        Alert.alert('Success', 'Logged out successfully');
      } else {
        const data = await response.json();
        Alert.alert('Error', data.detail || 'Logout failed');
      }
    } catch (error) {
      Alert.alert('Error', 'Network error during logout');
      console.error('Logout error:', error);
    }
  };

  // Create master token
  const createMasterToken = async () => {
    try {
      // Validate master token format
      if (!masterToken || masterToken.length < 8) {
        Alert.alert('Error', 'Master token must be at least 8 characters long');
        return;
      }

      const hasUpper = /[A-Z]/.test(masterToken);
      const hasLower = /[a-z]/.test(masterToken);
      const hasDigit = /[0-9]/.test(masterToken);
      const hasSpecial = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(masterToken);

      if (!(hasUpper && hasLower && hasDigit && hasSpecial)) {
        Alert.alert('Error', 'Master token must contain at least one uppercase letter, lowercase letter, digit, and special character');
        return;
      }

      const response = await fetch(`${API_BASE_URL}/mastertoken/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          mastertoken: masterToken,
        }),
      });

      const data = await response.json();
      
      if (response.ok) {
        Alert.alert('Success', 'Master token created successfully');
      } else {
        Alert.alert('Error', data.detail || 'Failed to create master token');
      }
    } catch (error) {
      Alert.alert('Error', 'Network error during master token creation');
      console.error('Master token creation error:', error);
    }
  };

  // Send message
  const sendMessage = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/messages/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          username: recipient,
          message: message,
        }),
      });

      const data = await response.json();
      
      if (response.ok) {
        Alert.alert('Success', 'Message sent successfully');
        setMessage('');
      } else {
        Alert.alert('Error', data.detail || 'Failed to send message');
      }
    } catch (error) {
      Alert.alert('Error', 'Network error during message sending');
      console.error('Send message error:', error);
    }
  };

  // Get inbox messages
  const getInbox = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/messages/inbox`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${sessionToken}`,
        },
      });

      const data = await response.json();
      
      if (response.ok) {
        setInbox(data.messages || []);
      } else {
        Alert.alert('Error', data.detail || 'Failed to retrieve inbox');
      }
    } catch (error) {
      Alert.alert('Error', 'Network error during inbox retrieval');
      console.error('Get inbox error:', error);
    }
  };

  // Decrypt message
  const decryptMessage = async (messageId) => {
    try {
      // Validate master token first
      if (!masterToken || masterToken.length < 8) {
        Alert.alert('Error', 'Please enter a valid master token first');
        return;
      }

      const response = await fetch(`${API_BASE_URL}/decrypt`, {
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
        Alert.alert('Decrypted Message', data.content);
      } else {
        if (response.status === 403 && data.detail && data.detail.includes('barred')) {
          Alert.alert('Account Barred', 'Your account has been permanently barred due to too many failed decryption attempts. Please create a new account.');
        } else {
          Alert.alert('Error', data.detail || 'Failed to decrypt message');
        }
      }
    } catch (error) {
      Alert.alert('Error', 'Network error during message decryption');
      console.error('Decrypt message error:', error);
    }
  };

  // Check if user is already logged in
  useEffect(() => {
    const checkLoginStatus = async () => {
      const token = await AsyncStorage.getItem('sessionToken');
      if (token) {
        setSessionToken(token);
        setIsLoggedIn(true);
      }
    };

    checkLoginStatus();
  }, []);

  if (!isLoggedIn) {
    return (
      <ScrollView style={styles.container}>
        <Text style={styles.title}>Secure Messaging App</Text>
        
        <View style={styles.form}>
          <Text style={styles.label}>Username</Text>
          <TextInput
            style={styles.input}
            value={username}
            onChangeText={setUsername}
            placeholder="Enter username"
          />
          
          <Text style={styles.label}>Token</Text>
          <TextInput
            style={styles.input}
            value={token}
            onChangeText={setToken}
            placeholder="Enter token"
            secureTextEntry
          />
          
          <TouchableOpacity style={styles.button} onPress={registerUser}>
            <Text style={styles.buttonText}>Register</Text>
          </TouchableOpacity>
          
          <TouchableOpacity style={[styles.button, styles.secondaryButton]} onPress={loginUser}>
            <Text style={styles.buttonText}>Login</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    );
  }

  return (
    <ScrollView style={styles.container}>
      <Text style={styles.title}>Secure Messaging Dashboard</Text>
      
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Send Message</Text>
        <TextInput
          style={styles.input}
          value={recipient}
          onChangeText={setRecipient}
          placeholder="Recipient username"
        />
        <TextInput
          style={[styles.input, styles.textArea]}
          value={message}
          onChangeText={setMessage}
          placeholder="Enter your message"
          multiline
        />
        <TouchableOpacity style={styles.button} onPress={sendMessage}>
          <Text style={styles.buttonText}>Send Message</Text>
        </TouchableOpacity>
      </View>
      
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Master Token</Text>
        <TextInput
          style={styles.input}
          value={masterToken}
          onChangeText={setMasterToken}
          placeholder="Enter master token (8+ chars, upper, lower, digit, special)"
          secureTextEntry
        />
        <TouchableOpacity style={styles.button} onPress={createMasterToken}>
          <Text style={styles.buttonText}>Create/Update Master Token</Text>
        </TouchableOpacity>
      </View>
      
      <View style={styles.section}>
        <View style={styles.row}>
          <Text style={styles.sectionTitle}>Inbox</Text>
          <TouchableOpacity style={styles.refreshButton} onPress={getInbox}>
            <Text style={styles.refreshButtonText}>Refresh</Text>
          </TouchableOpacity>
        </View>
        
        {inbox.map((msg, index) => (
          <View key={index} style={styles.messageCard}>
            <Text style={styles.messageSender}>From: {msg.sender}</Text>
            {/* Display decoy text with encryption indicator */}
            <Text style={styles.messageContent}>
              {msg.content}
              {msg.is_encrypted && <Text style={styles.encryptionIndicator}> 🔒</Text>}
            </Text>
            <Text style={styles.messageTime}>{new Date(msg.timestamp).toLocaleString()}</Text>
            {msg.is_encrypted && (
              <TouchableOpacity 
                style={styles.decryptButton} 
                onPress={() => decryptMessage(msg.id)}
              >
                <Text style={styles.decryptButtonText}>Decrypt Message</Text>
              </TouchableOpacity>
            )}
          </View>
        ))}
      </View>
      
      <TouchableOpacity style={[styles.button, styles.logoutButton]} onPress={logoutUser}>
        <Text style={styles.buttonText}>Logout</Text>
      </TouchableOpacity>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    textAlign: 'center',
    marginVertical: 20,
    color: '#333',
  },
  form: {
    backgroundColor: 'white',
    padding: 20,
    borderRadius: 10,
    elevation: 3,
  },
  label: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 5,
    color: '#333',
  },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 5,
    padding: 10,
    marginBottom: 15,
    fontSize: 16,
  },
  textArea: {
    height: 80,
    textAlignVertical: 'top',
  },
  button: {
    backgroundColor: '#007AFF',
    padding: 15,
    borderRadius: 5,
    alignItems: 'center',
    marginVertical: 5,
  },
  secondaryButton: {
    backgroundColor: '#34C759',
  },
  logoutButton: {
    backgroundColor: '#FF3B30',
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  section: {
    backgroundColor: 'white',
    padding: 15,
    borderRadius: 10,
    marginVertical: 10,
    elevation: 2,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#333',
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  refreshButton: {
    backgroundColor: '#5856D6',
    paddingHorizontal: 15,
    paddingVertical: 8,
    borderRadius: 5,
  },
  refreshButtonText: {
    color: 'white',
    fontSize: 14,
    fontWeight: '600',
  },
  messageCard: {
    backgroundColor: '#f9f9f9',
    padding: 15,
    borderRadius: 8,
    marginBottom: 10,
    borderWidth: 1,
    borderColor: '#eee',
  },
  messageSender: {
    fontSize: 14,
    fontWeight: '600',
    color: '#007AFF',
    marginBottom: 5,
  },
  messageContent: {
    fontSize: 16,
    color: '#333',
    marginBottom: 5,
  },
  encryptionIndicator: {
    fontSize: 14,
    color: '#FF9500',
  },
  messageTime: {
    fontSize: 12,
    color: '#888',
    marginBottom: 10,
  },
  decryptButton: {
    backgroundColor: '#FF9500',
    padding: 10,
    borderRadius: 5,
    alignItems: 'center',
  },
  decryptButtonText: {
    color: 'white',
    fontSize: 14,
    fontWeight: '600',
  },
});

export default SecureMessagingApp;