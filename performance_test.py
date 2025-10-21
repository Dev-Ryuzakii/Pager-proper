#!/usr/bin/env python3
"""
Performance test comparing RSA vs Hybrid (AES+RSA) encryption
Shows the speed improvement with hybrid encryption
"""

import time
import sys
sys.path.insert(0, '.')

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json

def test_rsa_only(message, public_key, private_key):
    """Test pure RSA encryption (slow)"""
    start = time.time()
    
    # Encrypt with RSA
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())
    
    encrypt_time = time.time() - start
    
    # Decrypt with RSA
    decrypt_start = time.time()
    cipher_decrypt = PKCS1_OAEP.new(private_key)
    decrypted = cipher_decrypt.decrypt(encrypted)
    decrypt_time = time.time() - decrypt_start
    
    return encrypt_time, decrypt_time, len(encrypted)

def test_hybrid_aes_rsa(message, public_key, private_key):
    """Test hybrid AES+RSA encryption (fast)"""
    start = time.time()
    
    # Generate AES key
    aes_key = get_random_bytes(32)
    
    # Encrypt message with AES
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = aes_cipher.iv
    encrypted_message = aes_cipher.encrypt(pad(message.encode(), AES.block_size))
    
    # Encrypt AES key with RSA
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = rsa_cipher.encrypt(aes_key)
    
    encrypt_time = time.time() - start
    
    # Decrypt
    decrypt_start = time.time()
    
    # Decrypt AES key with RSA
    rsa_cipher_decrypt = PKCS1_OAEP.new(private_key)
    decrypted_aes_key = rsa_cipher_decrypt.decrypt(encrypted_key)
    
    # Decrypt message with AES
    aes_cipher_decrypt = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
    decrypted_padded = aes_cipher_decrypt.decrypt(encrypted_message)
    decrypted = unpad(decrypted_padded, AES.block_size)
    
    decrypt_time = time.time() - decrypt_start
    
    total_size = len(encrypted_key) + len(iv) + len(encrypted_message)
    return encrypt_time, decrypt_time, total_size

def run_performance_test():
    print("🚀 Encryption Performance Test")
    print("=" * 50)
    
    # Generate test keys
    print("Generating 2048-bit RSA keys...")
    key = RSA.generate(2048)
    public_key = key.publickey()
    private_key = key
    
    # Test messages of different sizes
    test_messages = [
        ("Short message", "Hello!"),
        ("Medium message", "This is a longer message that might be typical in messaging apps. " * 2),
        ("Long message", "This is a very long message that would definitely be slow with pure RSA. " * 10),
        ("Very long message", "Long message with lots of text to test performance with larger payloads. " * 50)
    ]
    
    print(f"\n{'Message Type':<20} {'Size':<8} {'Method':<12} {'Encrypt':<10} {'Decrypt':<10} {'Total':<10} {'Data Size':<10}")
    print("-" * 90)
    
    for msg_name, message in test_messages:
        msg_size = len(message.encode())
        
        # Test RSA only (if message is small enough)
        if len(message) <= 190:  # RSA 2048-bit can encrypt max ~245 bytes
            try:
                rsa_enc, rsa_dec, rsa_size = test_rsa_only(message, public_key, private_key)
                total_rsa = rsa_enc + rsa_dec
                print(f"{msg_name:<20} {msg_size:<8} {'RSA Only':<12} {rsa_enc:.3f}s{'':<4} {rsa_dec:.3f}s{'':<4} {total_rsa:.3f}s{'':<4} {rsa_size:<10}")
            except Exception as e:
                print(f"{msg_name:<20} {msg_size:<8} {'RSA Only':<12} {'TOO LARGE':<30} {'-':<10}")
        else:
            print(f"{msg_name:<20} {msg_size:<8} {'RSA Only':<12} {'TOO LARGE - RSA limit ~245 bytes':<50}")
        
        # Test Hybrid AES+RSA
        try:
            hyb_enc, hyb_dec, hyb_size = test_hybrid_aes_rsa(message, public_key, private_key)
            total_hyb = hyb_enc + hyb_dec
            print(f"{msg_name:<20} {msg_size:<8} {'Hybrid':<12} {hyb_enc:.3f}s{'':<4} {hyb_dec:.3f}s{'':<4} {total_hyb:.3f}s{'':<4} {hyb_size:<10}")
            
            # Calculate speed improvement if RSA was possible
            if len(message) <= 190:
                speedup = total_rsa / total_hyb
                print(f"{'':<20} {'':<8} {'Speedup:':<12} {f'{speedup:.1f}x faster':<50}")
                
        except Exception as e:
            print(f"{msg_name:<20} {msg_size:<8} {'Hybrid':<12} {'ERROR: ' + str(e):<50}")
        
        print()
    
    print("💡 Key Benefits of Hybrid Encryption:")
    print("✅ Can encrypt messages of ANY size (RSA limited to ~245 bytes)")
    print("✅ Much faster for longer messages")
    print("✅ Same security level (AES-256 + RSA-2048)")
    print("✅ Industry standard (used by HTTPS, Signal, WhatsApp)")
    print("✅ Perfect for real-time messaging")

if __name__ == "__main__":
    run_performance_test()