#!/usr/bin/env python3
"""
Offline Messaging Test - Test sending messages to offline users
"""

import threading
import time
import json
from client_tls import SecureMessagingClient

def test_offline_messaging():
    """Test offline message delivery"""
    print("🔒 Testing Offline Message Delivery")
    print("=" * 50)
    
    # Create two client instances
    sender = SecureMessagingClient()
    receiver = SecureMessagingClient()
    
    try:
        # Step 1: Connect sender (kami)
        print("1. Connecting sender (kami)...")
        if sender.connect("127.0.0.1", 5050):
            sender.login("kami", "token432")
            print("✅ Sender connected and logged in")
        else:
            print("❌ Sender connection failed")
            return
        
        # Step 2: Send message while receiver is offline
        print("\n2. Sending message to offline user (tougen)...")
        success = sender.send_message("tougen", "Hello! This is an offline message test.")
        if success:
            print("✅ Message sent (stored for offline delivery)")
        else:
            print("❌ Message send failed")
            return
        
        # Wait a moment
        time.sleep(2)
        
        # Step 3: Connect receiver to get offline messages
        print("\n3. Connecting receiver (tougen) to get offline messages...")
        if receiver.connect("127.0.0.1", 5050):
            receiver.login("tougen", "token789")
            print("✅ Receiver connected - should receive offline messages")
        else:
            print("❌ Receiver connection failed")
            return
        
        # Wait for message delivery
        print("\n4. Waiting for offline message delivery...")
        time.sleep(3)
        
        # Step 4: Check if messages were delivered
        print("\n5. Checking message delivery...")
        print(f"   Sender messages sent: {len(sender.message_history)}")
        print(f"   Receiver messages received: {len(receiver.message_history)}")
        
        if receiver.message_history:
            print("✅ Offline message delivered successfully!")
            print(f"   Message: {receiver.message_history[-1].get('payload', {}).get('content', 'encrypted')}")
        else:
            print("❌ No offline messages received")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        try:
            sender.disconnect()
            receiver.disconnect()
        except:
            pass

def test_multiple_offline_messages():
    """Test sending multiple messages to offline user"""
    print("\n" + "=" * 50)
    print("🔒 Testing Multiple Offline Messages")
    print("=" * 50)
    
    sender = SecureMessagingClient()
    receiver = SecureMessagingClient()
    
    try:
        # Connect sender
        if sender.connect("127.0.0.1", 5050):
            sender.login("kami", "token432")
            print("✅ Sender connected")
        else:
            print("❌ Sender connection failed")
            return
        
        # Send multiple messages while receiver is offline
        messages = [
            "First offline message",
            "Second offline message", 
            "Third offline message"
        ]
        
        print(f"\n📤 Sending {len(messages)} messages to offline user...")
        for i, msg in enumerate(messages, 1):
            success = sender.send_message("tougen", msg)
            print(f"   Message {i}: {'✅ Sent' if success else '❌ Failed'}")
            time.sleep(0.5)
        
        # Connect receiver
        print(f"\n📥 Connecting receiver to get {len(messages)} offline messages...")
        if receiver.connect("127.0.0.1", 5050):
            receiver.login("tougen", "token789")
            time.sleep(3)  # Wait for all messages to be delivered
            
            received_count = len(receiver.message_history)
            print(f"✅ Received {received_count} messages")
            
            if received_count == len(messages):
                print("✅ All offline messages delivered successfully!")
            else:
                print(f"⚠️  Expected {len(messages)}, got {received_count}")
                
        else:
            print("❌ Receiver connection failed")
    
    except Exception as e:
        print(f"❌ Multiple message test failed: {e}")
    
    finally:
        try:
            sender.disconnect()
            receiver.disconnect()
        except:
            pass

if __name__ == "__main__":
    print("🧪 Offline Messaging Test Suite")
    print("Make sure the server is running first!")
    print("Press Enter to continue...")
    input()
    
    # Test 1: Basic offline messaging
    test_offline_messaging()
    
    # Wait between tests
    time.sleep(2)
    
    # Test 2: Multiple offline messages
    test_multiple_offline_messages()
    
    print("\n🎉 Offline messaging tests completed!")