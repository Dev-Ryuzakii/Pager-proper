/**
 * React Native Admin Example
 * This example shows how to implement admin functionality for user management
 */

import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  FlatList,
  Modal,
  ScrollView,
} from 'react-native';

const AdminExample = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [authToken, setAuthToken] = useState('');
  const [mustChangePassword, setMustChangePassword] = useState(false);
  
  // Login state
  const [loginCredentials, setLoginCredentials] = useState({ username: '', password: '' });
  
  // Password change state
  const [passwordChange, setPasswordChange] = useState({ 
    currentPassword: '', 
    newPassword: '', 
    confirmPassword: '' 
  });
  
  // New user creation state
  const [newUser, setNewUser] = useState({ username: '', token: '' });
  
  // UI states
  const [showLoginModal, setShowLoginModal] = useState(true);
  const [showPasswordChangeModal, setShowPasswordChangeModal] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Admin login
  const adminLogin = async () => {
    if (!loginCredentials.username || !loginCredentials.password) {
      Alert.alert('Error', 'Please enter both username and password');
      return;
    }

    try {
      // Login to admin API
      const response = await fetch('http://your-server-url/admin/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: loginCredentials.username,
          password: loginCredentials.password,
        }),
      });

      const result = await response.json();
      
      if (response.ok) {
        setAuthToken(result.token);
        setIsLoggedIn(true);
        setIsAdmin(true);
        setMustChangePassword(result.must_change_password);
        setShowLoginModal(false);
        
        if (result.must_change_password) {
          setShowPasswordChangeModal(true);
        } else {
          loadUsers();
        }
      } else {
        Alert.alert('Error', result.detail || 'Failed to login');
      }
    } catch (error) {
      console.error('Login error:', error);
      Alert.alert('Error', 'Failed to login');
    }
  };

  // Change password
  const changePassword = async () => {
    if (!passwordChange.currentPassword || !passwordChange.newPassword || !passwordChange.confirmPassword) {
      Alert.alert('Error', 'Please fill in all fields');
      return;
    }
    
    if (passwordChange.newPassword !== passwordChange.confirmPassword) {
      Alert.alert('Error', 'New passwords do not match');
      return;
    }
    
    if (passwordChange.newPassword.length < 8) {
      Alert.alert('Error', 'Password must be at least 8 characters long');
      return;
    }

    try {
      // Change password
      const response = await fetch('http://your-server-url/admin/change_password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          current_password: passwordChange.currentPassword,
          new_password: passwordChange.newPassword,
        }),
      });

      const result = await response.json();
      
      if (response.ok) {
        Alert.alert('Success', 'Password changed successfully');
        setShowPasswordChangeModal(false);
        setMustChangePassword(false);
        setPasswordChange({ currentPassword: '', newPassword: '', confirmPassword: '' });
        loadUsers(); // Load users after password change
      } else {
        Alert.alert('Error', result.detail || 'Failed to change password');
      }
    } catch (error) {
      console.error('Change password error:', error);
      Alert.alert('Error', 'Failed to change password');
    }
  };

  // Load users
  const loadUsers = async () => {
    if (!isAdmin || !authToken) return;
    
    setLoading(true);
    try {
      // Fetch all users
      const response = await fetch('http://your-server-url/admin/users', {
        headers: {
          'Authorization': `Bearer ${authToken}`,
        },
      });

      const result = await response.json();
      
      if (response.ok) {
        setUsers(result.users);
      } else {
        Alert.alert('Error', result.detail || 'Failed to load users');
      }
    } catch (error) {
      console.error('Load users error:', error);
      Alert.alert('Error', 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  // Create user
  const createUser = async () => {
    if (!newUser.username || !newUser.token) {
      Alert.alert('Error', 'Please fill in all fields');
      return;
    }

    try {
      // Create new user
      const response = await fetch('http://your-server-url/admin/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          username: newUser.username,
          token: newUser.token,
        }),
      });

      const result = await response.json();
      
      if (response.ok) {
        Alert.alert('Success', 'User created successfully');
        setNewUser({ username: '', token: '' });
        setShowCreateModal(false);
        loadUsers(); // Refresh the user list
      } else {
        Alert.alert('Error', result.detail || 'Failed to create user');
      }
    } catch (error) {
      console.error('Create user error:', error);
      Alert.alert('Error', 'Failed to create user');
    }
  };

  // Delete user
  const deleteUser = async (username) => {
    Alert.alert(
      'Confirm Delete',
      `Are you sure you want to permanently delete user ${username}?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              // Delete user
              const response = await fetch(`http://your-server-url/admin/users/${username}`, {
                method: 'DELETE',
                headers: {
                  'Authorization': `Bearer ${authToken}`,
                },
              });

              const result = await response.json();
              
              if (response.ok) {
                Alert.alert('Success', 'User deleted successfully');
                loadUsers(); // Refresh the user list
              } else {
                Alert.alert('Error', result.detail || 'Failed to delete user');
              }
            } catch (error) {
              console.error('Delete user error:', error);
              Alert.alert('Error', 'Failed to delete user');
            }
          },
        },
      ]
    );
  };

  // Logout
  const logout = () => {
    setIsLoggedIn(false);
    setIsAdmin(false);
    setAuthToken('');
    setUsers([]);
    setShowLoginModal(true);
  };

  // Render user item
  const renderUser = ({ item }) => (
    <View style={styles.userItem}>
      <View style={styles.userDetails}>
        <Text style={styles.username}>{item.username}</Text>
        <Text style={styles.userType}>
          {item.user_type} {item.is_admin ? '(Admin)' : ''} {item.is_active ? '(Active)' : '(Inactive)'}
        </Text>
        <Text style={styles.userDate}>
          Registered: {new Date(item.registered).toLocaleDateString()}
        </Text>
        {item.last_login && (
          <Text style={styles.userDate}>
            Last login: {new Date(item.last_login).toLocaleDateString()}
          </Text>
        )}
      </View>
      {!item.is_admin && (
        <TouchableOpacity
          style={styles.deleteButton}
          onPress={() => deleteUser(item.username)}
        >
          <Text style={styles.deleteButtonText}>Delete</Text>
        </TouchableOpacity>
      )}
    </View>
  );

  // Login Modal
  const renderLoginModal = () => (
    <Modal
      visible={showLoginModal}
      animationType="slide"
      onRequestClose={() => {}}
    >
      <View style={styles.modalContainer}>
        <View style={styles.modalContent}>
          <Text style={styles.modalTitle}>Admin Login</Text>
          
          <TextInput
            style={styles.input}
            placeholder="Username"
            value={loginCredentials.username}
            onChangeText={(text) => setLoginCredentials({...loginCredentials, username: text})}
          />
          
          <TextInput
            style={styles.input}
            placeholder="Password"
            value={loginCredentials.password}
            onChangeText={(text) => setLoginCredentials({...loginCredentials, password: text})}
            secureTextEntry
          />
          
          <TouchableOpacity
            style={styles.primaryButton}
            onPress={adminLogin}
          >
            <Text style={styles.buttonText}>Login</Text>
          </TouchableOpacity>
        </View>
      </View>
    </Modal>
  );

  // Password Change Modal
  const renderPasswordChangeModal = () => (
    <Modal
      visible={showPasswordChangeModal}
      animationType="slide"
      onRequestClose={() => {}}
    >
      <View style={styles.modalContainer}>
        <View style={styles.modalContent}>
          <Text style={styles.modalTitle}>Change Password</Text>
          <Text style={styles.modalSubtitle}>You must change your password on first login</Text>
          
          <TextInput
            style={styles.input}
            placeholder="Current Password"
            value={passwordChange.currentPassword}
            onChangeText={(text) => setPasswordChange({...passwordChange, currentPassword: text})}
            secureTextEntry
          />
          
          <TextInput
            style={styles.input}
            placeholder="New Password"
            value={passwordChange.newPassword}
            onChangeText={(text) => setPasswordChange({...passwordChange, newPassword: text})}
            secureTextEntry
          />
          
          <TextInput
            style={styles.input}
            placeholder="Confirm New Password"
            value={passwordChange.confirmPassword}
            onChangeText={(text) => setPasswordChange({...passwordChange, confirmPassword: text})}
            secureTextEntry
          />
          
          <View style={styles.modalButtonContainer}>
            <TouchableOpacity
              style={[styles.primaryButton, styles.modalButton]}
              onPress={changePassword}
            >
              <Text style={styles.buttonText}>Change Password</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );

  // Create User Modal
  const renderCreateUserModal = () => (
    <Modal
      visible={showCreateModal}
      animationType="slide"
      onRequestClose={() => setShowCreateModal(false)}
    >
      <View style={styles.modalContainer}>
        <View style={styles.modalContent}>
          <Text style={styles.modalTitle}>Create New User</Text>
          
          <TextInput
            style={styles.input}
            placeholder="Username"
            value={newUser.username}
            onChangeText={(text) => setNewUser({...newUser, username: text})}
          />
          
          <TextInput
            style={styles.input}
            placeholder="Token"
            value={newUser.token}
            onChangeText={(text) => setNewUser({...newUser, token: text})}
            secureTextEntry
          />
          
          <View style={styles.modalButtonContainer}>
            <TouchableOpacity
              style={[styles.primaryButton, styles.modalButton]}
              onPress={createUser}
            >
              <Text style={styles.buttonText}>Create User</Text>
            </TouchableOpacity>
            
            <TouchableOpacity
              style={[styles.secondaryButton, styles.modalButton]}
              onPress={() => setShowCreateModal(false)}
            >
              <Text style={styles.buttonText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );

  if (!isLoggedIn) {
    return renderLoginModal();
  }

  if (mustChangePassword) {
    return renderPasswordChangeModal();
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Admin User Management</Text>
        <TouchableOpacity style={styles.logoutButton} onPress={logout}>
          <Text style={styles.logoutButtonText}>Logout</Text>
        </TouchableOpacity>
      </View>
      
      <View style={styles.buttonContainer}>
        <TouchableOpacity
          style={styles.primaryButton}
          onPress={() => setShowCreateModal(true)}
        >
          <Text style={styles.buttonText}>Create New User</Text>
        </TouchableOpacity>
        
        <TouchableOpacity
          style={styles.secondaryButton}
          onPress={loadUsers}
          disabled={loading}
        >
          <Text style={styles.buttonText}>
            {loading ? 'Loading...' : 'Refresh Users'}
          </Text>
        </TouchableOpacity>
      </View>
      
      <FlatList
        data={users}
        keyExtractor={(item) => item.username}
        renderItem={renderUser}
        refreshing={loading}
        onRefresh={loadUsers}
        ListEmptyComponent={
          <Text style={styles.emptyText}>
            {loading ? 'Loading users...' : 'No users found'}
          </Text>
        }
      />
      
      {renderCreateUserModal()}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 20,
    backgroundColor: '#fff',
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
  },
  logoutButton: {
    backgroundColor: '#FF3B30',
    padding: 10,
    borderRadius: 5,
  },
  logoutButtonText: {
    color: 'white',
    fontWeight: 'bold',
  },
  buttonContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    padding: 20,
  },
  primaryButton: {
    backgroundColor: '#007AFF',
    padding: 15,
    borderRadius: 10,
    flex: 1,
    marginHorizontal: 5,
    alignItems: 'center',
  },
  secondaryButton: {
    backgroundColor: '#8E8E93',
    padding: 15,
    borderRadius: 10,
    flex: 1,
    marginHorizontal: 5,
    alignItems: 'center',
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  userItem: {
    backgroundColor: 'white',
    padding: 15,
    borderRadius: 10,
    marginBottom: 10,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginHorizontal: 20,
  },
  userDetails: {
    flex: 1,
  },
  username: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 5,
  },
  userType: {
    fontSize: 14,
    color: '#666',
    marginBottom: 3,
  },
  userDate: {
    fontSize: 12,
    color: '#999',
  },
  deleteButton: {
    backgroundColor: '#FF3B30',
    padding: 10,
    borderRadius: 5,
  },
  deleteButtonText: {
    color: 'white',
    fontWeight: 'bold',
  },
  emptyText: {
    textAlign: 'center',
    color: '#666',
    marginTop: 50,
    fontSize: 16,
  },
  modalContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.5)',
  },
  modalContent: {
    backgroundColor: 'white',
    padding: 20,
    borderRadius: 10,
    width: '80%',
  },
  modalTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 10,
  },
  modalSubtitle: {
    fontSize: 14,
    textAlign: 'center',
    color: '#666',
    marginBottom: 20,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    padding: 10,
    marginBottom: 15,
  },
  modalButtonContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  modalButton: {
    flex: 1,
    marginHorizontal: 5,
  },
});

export default AdminExample;