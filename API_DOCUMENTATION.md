# Secure Messaging API Documentation for React Native Developers

This document provides comprehensive guidance on how to integrate the Secure Messaging API with React Native applications. The API implements robust security features including Token Binding Validation, Token Format Validation, and Failed Attempt Protection.

## Table of Contents
1. [API Overview](#api-overview)
2. [Authentication Flow](#authentication-flow)
3. [Security Features](#security-features)
4. [API Endpoints](#api-endpoints)
5. [React Native Implementation Examples](#react-native-implementation-examples)
6. [Error Handling](#error-handling)
7. [Best Practices](#best-practices)

## API Overview

The Secure Messaging API is built with FastAPI and PostgreSQL, providing end-to-end encryption for mobile messaging applications. Key features include:

- User registration and authentication
- Secure message sending and receiving
- End-to-end encryption with RSA/AES
- Master token-based decryption with enhanced security
- Account protection against brute force attacks

Base URL: `http://localhost:8001` (adjust for your deployment)

## Authentication Flow

### 1. User Registration
```javascript
// Register a new user
const registerUser = async (username, token, publicKey = null) => {
  try {
    const response = await fetch('http://localhost:8001/auth/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: username,
        token: token,
        public_key: publicKey, // Optional
      }),
    });
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Registration error:', error);
    throw error;
  }
};
```

### 2. User Login
```javascript
// Login user
const loginUser = async (username, token) => {
  try {
    const response = await fetch('http://localhost:8001/auth/login', {
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
    // Store the session token for future requests
    await AsyncStorage.setItem('sessionToken', data.token);
    return data;
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
};
```

### 3. Create and Confirm Master Token
```javascript
// Create master token (must meet complexity requirements)
const createMasterToken = async (masterToken) => {
  try {
    const sessionToken = await AsyncStorage.getItem('sessionToken');
    const response = await fetch('http://localhost:8001/mastertoken/create', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({
        mastertoken: masterToken, // Must be at least 8 chars with uppercase, lowercase, digit, and special char
      }),
    });
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Master token creation error:', error);
    throw error;
  }
};

// Confirm master token
const confirmMasterToken = async (masterToken) => {
  try {
    const sessionToken = await AsyncStorage.getItem('sessionToken');
    const response = await fetch('http://localhost:8001/mastertoken/confirm', {
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
    return data;
  } catch (error) {
    console.error('Master token confirmation error:', error);
    throw error;
  }
};
```

## Security Features

### Token Format Validation
Master tokens must meet the following requirements:
- Minimum 8 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one digit (0-9)
- At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

### Token Binding Validation
Tokens are securely hashed and bound to users:
- Tokens are hashed using PBKDF2 with 100,000 iterations
- Each token is salted with a 32-byte random salt
- Tokens are validated against audit logs for binding verification

### Failed Attempt Protection
Account security measures:
- Accounts are permanently barred after 3 failed decryption attempts
- Failed attempts are tracked and logged
- Barred accounts receive a 403 error with descriptive message

## API Endpoints

### Authentication
| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/auth/register` | POST | Register new user | No |
| `/auth/login` | POST | Login user | No |
| `/auth/logout` | POST | Logout user | Yes |

### Messaging
| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/messages/send` | POST | Send message | Yes |
| `/messages/inbox` | GET | Get inbox messages | Yes |
| `/messages/offline` | GET | Get offline messages | Yes |
| `/messages/{message_id}/read` | PUT | Mark message as read | Yes |

### Users
| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/users` | GET | Get list of users | Yes |
| `/users/{username}/public_key` | GET | Get user's public key | Yes |

### Master Token Management
| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/mastertoken/create` | POST | Create master token | Yes |
| `/mastertoken/confirm` | POST | Confirm master token | Yes |

### Message Decryption
| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/decrypt` | POST | Decrypt message with master token | Yes |

## React Native Implementation Examples

### Sending a Message
```javascript
const sendMessage = async (recipientUsername, messageContent) => {
  try {
    const sessionToken = await AsyncStorage.getItem('sessionToken');
    const response = await fetch('http://localhost:8001/messages/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({
        username: recipientUsername,
        message: messageContent,
      }),
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Send message error:', error);
    throw error;
  }
};
```

### Getting Inbox Messages
```javascript
const getInboxMessages = async () => {
  try {
    const sessionToken = await AsyncStorage.getItem('sessionToken');
    const response = await fetch('http://localhost:8001/messages/inbox', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${sessionToken}`,
      },
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    return data.messages;
  } catch (error) {
    console.error('Get inbox error:', error);
    throw error;
  }
};
```

### Decrypting a Message
```javascript
const decryptMessage = async (messageId, masterToken) => {
  try {
    const sessionToken = await AsyncStorage.getItem('sessionToken');
    const response = await fetch('http://localhost:8001/decrypt', {
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
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Decrypt message error:', error);
    throw error;
  }
};
```

## Error Handling

### Common Error Responses
```javascript
const handleApiError = (error) => {
  if (error.message.includes('401')) {
    // Unauthorized - token invalid
    Alert.alert('Authentication Error', 'Please log in again');
    // Redirect to login screen
  } else if (error.message.includes('403')) {
    // Forbidden - account barred
    Alert.alert('Account Barred', 'Your account has been permanently barred due to too many failed attempts. Please create a new account.');
    // Redirect to registration screen
  } else if (error.message.includes('404')) {
    // Not found
    Alert.alert('Not Found', 'The requested resource was not found');
  } else {
    // Other errors
    Alert.alert('Error', 'An unexpected error occurred');
  }
};
```

### Master Token Validation Errors
```javascript
const validateMasterToken = (token) => {
  if (!token || token.length < 8) {
    throw new Error('Master token must be at least 8 characters long');
  }
  
  const hasUpper = /[A-Z]/.test(token);
  const hasLower = /[a-z]/.test(token);
  const hasDigit = /[0-9]/.test(token);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(token);
  
  if (!(hasUpper && hasLower && hasDigit && hasSpecial)) {
    throw new Error('Master token must contain at least one uppercase letter, lowercase letter, digit, and special character');
  }
  
  return true;
};
```

## Best Practices

### 1. Secure Token Storage
```javascript
// Use secure storage for sensitive tokens
import * as SecureStore from 'expo-secure-store';

const storeSessionToken = async (token) => {
  await SecureStore.setItemAsync('sessionToken', token);
};

const getSessionToken = async () => {
  return await SecureStore.getItemAsync('sessionToken');
};
```

### 2. Master Token Management
```javascript
// Validate master token before use
const validateAndUseMasterToken = async (masterToken, messageId) => {
  try {
    // Validate format first
    validateMasterToken(masterToken);
    
    // Confirm token with server
    await confirmMasterToken(masterToken);
    
    // Decrypt message
    const decryptedMessage = await decryptMessage(messageId, masterToken);
    return decryptedMessage;
  } catch (error) {
    handleApiError(error);
    throw error;
  }
};
```

### 3. Account Security
```javascript
// Handle barred accounts
const checkAccountStatus = async () => {
  try {
    // Attempt a simple API call to check account status
    const sessionToken = await getSessionToken();
    const response = await fetch('http://localhost:8001/status', {
      headers: {
        'Authorization': `Bearer ${sessionToken}`,
      },
    });
    
    if (response.status === 403) {
      const data = await response.json();
      if (data.detail && data.detail.includes('barred')) {
        // Account is barred, handle accordingly
        Alert.alert('Account Barred', 'Your account has been permanently barred. Please create a new account.');
        // Clear local storage and redirect to registration
        return false;
      }
    }
    
    return true;
  } catch (error) {
    console.error('Account status check error:', error);
    return true; // Assume account is OK if we can't check
  }
};
```

### 4. Network Resilience
```javascript
// Implement retry logic for network requests
const apiRequestWithRetry = async (url, options, maxRetries = 3) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, options);
      return response;
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1))); // Exponential backoff
    }
  }
};
```

## Security Recommendations

1. **Token Complexity**: Always enforce strong master token requirements on the client side
2. **Secure Storage**: Use secure storage mechanisms for all authentication tokens
3. **Session Management**: Implement proper session timeout and renewal
4. **Network Security**: Use HTTPS in production environments
5. **Error Handling**: Never expose sensitive information in error messages
6. **Rate Limiting**: Implement client-side rate limiting to prevent abuse
7. **Audit Logging**: Log security-relevant events for monitoring

This documentation provides a comprehensive guide for integrating the Secure Messaging API with React Native applications while maintaining the highest security standards.