"""
Demonstration script for decoy text feature
Shows how the feature works in practice
"""

from fake_text_generator import FakeTextGenerator

def demonstrate_decoy_text_feature():
    """Demonstrate the decoy text feature"""
    print("Pager-proper Decoy Text Feature Demonstration")
    print("=" * 50)
    
    # Simulate receiving an encrypted message
    print("1. Receiving an encrypted message:")
    encrypted_message = "ENCRYPTED_CONTENT_WITH_RANDOM_CHARACTERS_AND_NUMBERS_1234567890"
    print(f"   Encrypted content: {encrypted_message}")
    
    # Generate decoy text
    print("\n2. Generating decoy text:")
    decoy_text = FakeTextGenerator.generate_decoy_text_for_message(encrypted_message)
    print(f"   Decoy text: {decoy_text}")
    
    # Show how it would appear to the user
    print("\n3. How it appears to the user:")
    print(f"   🔒 [TLS-ENCRYPTED] MESSAGE from alice at 14:30")
    print(f"   📝 Preview: {decoy_text}")
    print("   🔐 Type 'decrypt <ID>' to read this message")
    
    # Show what happens when user requests decryption
    print("\n4. User requests decryption:")
    print("   🔓 Decrypting TLS message from alice at 14:30")
    print(f"   📝 Previously shown as: {decoy_text}")
    print("   🔑 Enter your master decrypt token: [USER INPUT]")
    
    # Show decrypted content
    print("\n5. After successful decryption:")
    print("   📨 🔓 DECRYPTED MESSAGE (ID: 0)")
    print("   ================================")
    print("   👤 From: alice ✅")
    print("   ⏰ Time: 14:30")
    print("   🔐 Security: TLS 1.3 + AES-256-GCM + RSA-4096")
    print("   🛡️  Server HMAC: ✅")
    print("   --------------------------------")
    print("   💬 Message: Meet me at the usual place at 3 PM")
    print("   ================================")
    
    print("\n✅ Decoy text feature demonstration completed!")

if __name__ == "__main__":
    demonstrate_decoy_text_feature()