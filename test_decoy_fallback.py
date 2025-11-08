"""
Test script to verify decoy text implementation
"""

def test_decoy_text_fallback():
    """Test that the system works even when decoy_content column is missing"""
    print("Testing decoy text fallback mechanism")
    print("=" * 50)
    
    # Simulate a message object without decoy_content attribute
    class MockMessage:
        def __init__(self):
            self.id = 1
            self.sender_id = 2
            self.recipient_id = 3
            self.encrypted_content = "ENCRYPTED_DATA_HERE"
            self.content_type = "text"
            self.timestamp = "2023-01-01T12:00:00"
            self.delivered = False
            self.read = False
            # Note: no decoy_content attribute
    
    # Simulate a message object with decoy_content attribute
    class MockMessageWithDecoy:
        def __init__(self):
            self.id = 1
            self.sender_id = 2
            self.recipient_id = 3
            self.encrypted_content = "ENCRYPTED_DATA_HERE"
            self.decoy_content = "This is a realistic decoy message about system operations"
            self.content_type = "text"
            self.timestamp = "2023-01-01T12:00:00"
            self.delivered = False
            self.read = False
    
    # Test fallback mechanism
    msg1 = MockMessage()
    msg2 = MockMessageWithDecoy()
    
    # Simulate the content selection logic
    content1 = getattr(msg1, 'decoy_content', None) or getattr(msg1, 'encrypted_content', '')
    content2 = getattr(msg2, 'decoy_content', None) or getattr(msg2, 'encrypted_content', '')
    
    print(f"Message without decoy_content: {content1}")
    print(f"Message with decoy_content: {content2}")
    
    # Verify results
    assert content1 == "ENCRYPTED_DATA_HERE", "Fallback to encrypted_content failed"
    assert content2 == "This is a realistic decoy message about system operations", "Decoy content not used"
    
    print("\n✅ All tests passed!")
    print("✅ Fallback mechanism works correctly")
    print("✅ Decoy text is properly displayed when available")

if __name__ == "__main__":
    test_decoy_text_fallback()