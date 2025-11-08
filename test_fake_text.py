"""
Test script for fake text generator
"""

from fake_text_generator import FakeTextGenerator

def test_fake_text_generator():
    """Test the fake text generator functionality"""
    print("Testing Fake Text Generator")
    print("=" * 50)
    
    # Test sentence generation
    print("1. Generating sample sentences:")
    for i in range(5):
        sentence = FakeTextGenerator.generate_sentence()
        print(f"   {i+1}. {sentence}")
    
    # Test paragraph generation
    print("\n2. Generating sample paragraphs:")
    for i in range(3):
        paragraph = FakeTextGenerator.generate_paragraph()
        print(f"   {i+1}. {paragraph}")
    
    # Test message preview generation
    print("\n3. Generating message previews:")
    for i in range(5):
        preview = FakeTextGenerator.generate_message_preview()
        print(f"   {i+1}. {preview}")
    
    # Test decoy text for encrypted content
    print("\n4. Generating decoy text for encrypted content:")
    sample_encrypted_contents = [
        "ENCRYPTED_CONTENT_WITH_RANDOM_CHARACTERS_AND_NUMBERS_1234567890",
        "SHORT_ENCRYPTED",
        "VERY_LONG_ENCRYPTED_CONTENT_WITH_MANY_CHARACTERS_AND_NUMBERS_1234567890_ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz_1234567890",
        "MEDIUM_LENGTH_ENCRYPTED_CONTENT_1234567890"
    ]
    
    for i, content in enumerate(sample_encrypted_contents):
        decoy = FakeTextGenerator.generate_decoy_text_for_message(content)
        print(f"   {i+1}. Content length: {len(content)} -> Decoy: {decoy}")
    
    print("\n✅ All tests completed successfully!")

if __name__ == "__main__":
    test_fake_text_generator()