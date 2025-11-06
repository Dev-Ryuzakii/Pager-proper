# Admin API Functions

This document describes the JavaScript functions for interacting with the admin API endpoints of the secure messaging system.

## Base Configuration

```javascript
const BASE_URL = 'http://localhost:8001';
```

## Helper Functions

### handleResponse
Helper function to handle API responses consistently.

```javascript
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
```

## Admin API Functions

### adminLogin
Login as an admin user with username and password.

```javascript
export const adminLogin = async (username, password) => {
  const response = await fetch(`${BASE_URL}/admin/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  });
  
  // For login, we want to handle 401 specifically
  if (response.status === 401) {
    throw new Error('Invalid username or password');
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
    return text || 'Login successful';
  }
};
```

**Parameters:**
- `username` (string): Admin username (min 3 characters)
- `password` (string): Admin password (min 8 characters)

**Returns:**
- Object with `username`, `token`, and `must_change_password` properties

### adminChangePassword
Change admin password.

```javascript
export const adminChangePassword = async (currentPassword, newPassword, token) => {
  const response = await fetch(`${BASE_URL}/admin/change_password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ 
      current_password: currentPassword, 
      new_password: newPassword 
    }),
  });
  
  return handleResponse(response);
};
```

**Parameters:**
- `currentPassword` (string): Current admin password
- `newPassword` (string): New admin password (min 8 characters)
- `token` (string): Admin authentication token

**Returns:**
- Success message or error

### adminGetAllUsers
Get list of all users in the system.

```javascript
export const adminGetAllUsers = async (token) => {
  const response = await fetch(`${BASE_URL}/admin/users`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });
  
  return handleResponse(response);
};
```

**Parameters:**
- `token` (string): Admin authentication token

**Returns:**
- Object with `users` array containing user details and `count` property

### adminCreateUser
Create a new user account.

```javascript
export const adminCreateUser = async (userData, token) => {
  const response = await fetch(`${BASE_URL}/admin/users`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(userData),
  });
  
  return handleResponse(response);
};
```

**Parameters:**
- `userData` (object): User data with `username` (min 3 characters), `token`, and optional `public_key`
- `token` (string): Admin authentication token

**Returns:**
- Success message with created username

### adminDeleteUser
Delete a user account permanently.

```javascript
export const adminDeleteUser = async (username, token) => {
  const response = await fetch(`${BASE_URL}/admin/users/${username}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });
  
  // For DELETE requests, a 204 No Content response is common
  if (response.status === 204) {
    return 'User deleted successfully';
  }
  
  return handleResponse(response);
};
```

**Parameters:**
- `username` (string): Username of the account to delete
- `token` (string): Admin authentication token

**Returns:**
- Success message or error