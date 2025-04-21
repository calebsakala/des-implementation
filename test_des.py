#!/usr/bin/env python3
"""
DES Test Script

This script tests the DES implementation to verify that all transformations
are working correctly according to the specifications.

Usage:
    python test_des.py
"""

from des import DES
import binascii

def print_bits(bits, width=8, title=None):
    """Print bit array in readable format."""
    if title:
        print(f"{title}:")
    
    for i in range(0, len(bits), width):
        chunk = bits[i:i+width]
        print(''.join(str(bit) for bit in chunk), end=' ')
    print()

def test_initial_permutation():
    """Test the initial permutation."""
    print("\n=== Testing Initial Permutation ===")
    
    # Test vector - 64 bits
    test_block = [0, 0, 0, 0, 0, 0, 0, 1,   # 01
                  0, 0, 1, 0, 0, 0, 1, 1,   # 23
                  0, 1, 0, 0, 0, 1, 0, 1,   # 45
                  0, 1, 1, 0, 0, 1, 1, 1,   # 67
                  1, 0, 0, 0, 1, 0, 0, 1,   # 89
                  1, 0, 1, 0, 1, 0, 1, 1,   # AB
                  1, 1, 0, 0, 1, 1, 0, 1,   # CD
                  1, 1, 1, 0, 1, 1, 1, 1]   # EF
    
    # Create DES instance
    des = DES(b"TESTKEY!", debug=True)
    
    # Apply permutation
    print("Input block:")
    print_bits(test_block)
    
    permuted = des._initial_permutation(test_block)
    
    print("\nOutput after IP:")
    print_bits(permuted)
    
    # Apply inverse permutation to check
    original = des._inverse_initial_permutation(permuted)
    
    print("\nOutput after IP^-1 (should match input):")
    print_bits(original)
    
    # Verify
    assert original == test_block, "Initial permutation test failed"
    print("\nInitial permutation test passed!")

def test_expansion():
    """Test the expansion permutation."""
    print("\n=== Testing Expansion Permutation ===")
    
    # Test vector - 32 bits
    test_block = [1, 1, 0, 0, 1, 1, 0, 0,
                  1, 0, 1, 0, 1, 0, 1, 0,
                  0, 1, 0, 1, 0, 1, 0, 1,
                  1, 1, 1, 1, 0, 0, 0, 0]
    
    # Create DES instance
    des = DES(b"TESTKEY!", debug=True)
    
    # Apply expansion
    print("Input block (32 bits):")
    print_bits(test_block)
    
    expanded = des._expansion(test_block)
    
    print("\nOutput after expansion (48 bits):")
    print_bits(expanded, width=6)
    
    # Expected size
    assert len(expanded) == 48, "Expansion test failed - wrong output size"
    print("\nExpansion test passed!")

def test_key_generation():
    """Test round key generation."""
    print("\n=== Testing Round Key Generation ===")
    
    # Create DES instance with a test key
    key = b"TESTKEY!"
    des = DES(key, debug=True)
    
    print(f"Master Key: {key.decode()} ({binascii.hexlify(key).decode()})")
    
    # Print PC-1 output
    key_bits = des._bytes_to_bit_array(key)
    pc1_out = des._permuted_choice_1(key_bits)
    
    print("\nPC-1 Output (56 bits):")
    print_bits(pc1_out, width=7)
    
    # Print the first few round keys
    for i in range(3):  # Just show first 3 keys to save space
        print(f"\nRound Key {i+1} (48 bits):")
        print_bits(des.subkeys[i], width=6)
    
    # Verify we have 16 round keys
    assert len(des.subkeys) == 16, "Key generation test failed - wrong number of keys"
    # Verify each key is 48 bits
    for subkey in des.subkeys:
        assert len(subkey) == 48, "Key generation test failed - wrong key size"
    
    print("\nKey generation test passed!")

def test_s_box():
    """Test S-box substitution."""
    print("\n=== Testing S-box Substitution ===")
    
    # Test vector - 48 bits (six 6-bit blocks)
    test_block = [0, 0, 1, 1, 1, 1,  # S1: row 0, col 15 -> 7
                  1, 0, 1, 0, 1, 0,  # S2: row 2, col 5 -> 13
                  0, 0, 0, 0, 0, 0,  # S3: row 0, col 0 -> 10
                  1, 1, 1, 1, 0, 0,  # S4: row 1, col 14 -> 14
                  1, 0, 1, 0, 1, 1,  # S5: row 3, col 5 -> 3
                  0, 1, 0, 1, 0, 1,  # S6: row 1, col 10 -> 11
                  1, 1, 0, 0, 1, 1,  # S7: row 3, col 6 -> 8
                  0, 1, 1, 1, 1, 0]  # S8: row 2, col 7 -> 1
    
    # Create DES instance
    des = DES(b"TESTKEY!", debug=True)
    
    # Apply S-box substitution
    print("Input block (48 bits):")
    print_bits(test_block, width=6)
    
    substituted = des._s_box_substitution(test_block)
    
    print("\nOutput after S-box substitution (32 bits):")
    print_bits(substituted)
    
    # Verify size
    assert len(substituted) == 32, "S-box test failed - wrong output size"
    print("\nS-box test passed!")

def test_permutation_p():
    """Test permutation P."""
    print("\n=== Testing Permutation P ===")
    
    # Test vector - 32 bits
    test_block = [1, 0, 1, 0, 1, 0, 1, 0,
                  0, 1, 0, 1, 0, 1, 0, 1,
                  1, 1, 0, 0, 1, 1, 0, 0,
                  0, 0, 1, 1, 1, 1, 0, 0]
    
    # Create DES instance
    des = DES(b"TESTKEY!", debug=True)
    
    # Apply P permutation
    print("Input block:")
    print_bits(test_block)
    
    permuted = des._permutation_p(test_block)
    
    print("\nOutput after P:")
    print_bits(permuted)
    
    # Verify size
    assert len(permuted) == 32, "Permutation P test failed - wrong output size"
    print("\nPermutation P test passed!")

def test_f_function():
    """Test the Feistel function."""
    print("\n=== Testing Feistel Function ===")
    
    # Test vector - 32 bits
    test_block = [1, 0, 1, 0, 1, 0, 1, 0,
                  0, 1, 0, 1, 0, 1, 0, 1,
                  1, 1, 0, 0, 1, 1, 0, 0,
                  0, 0, 1, 1, 1, 1, 0, 0]
    
    # Create DES instance
    des = DES(b"TESTKEY!", debug=True)
    
    # Use first round key
    subkey = des.subkeys[0]
    
    # Apply f function
    print("Input block (32 bits):")
    print_bits(test_block)
    
    print("\nSubkey (48 bits):")
    print_bits(subkey, width=6)
    
    f_result = des._f_function(test_block, subkey)
    
    print("\nOutput of f function (32 bits):")
    print_bits(f_result)
    
    # Verify size
    assert len(f_result) == 32, "f function test failed - wrong output size"
    print("\nf function test passed!")

def test_des_round():
    """Test a complete DES round."""
    print("\n=== Testing DES Round ===")
    
    # Test vectors - 32 bits each for left and right
    left = [1, 0, 1, 0, 1, 0, 1, 0,
            0, 1, 0, 1, 0, 1, 0, 1,
            1, 1, 0, 0, 1, 1, 0, 0,
            0, 0, 1, 1, 1, 1, 0, 0]
    
    right = [0, 1, 0, 1, 0, 1, 0, 1,
             1, 0, 1, 0, 1, 0, 1, 0,
             0, 0, 1, 1, 0, 0, 1, 1,
             1, 1, 0, 0, 0, 0, 1, 1]
    
    # Create DES instance
    des = DES(b"TESTKEY!", debug=True)
    
    # Use first round key
    subkey = des.subkeys[0]
    
    # Print inputs
    print("Left input (32 bits):")
    print_bits(left)
    
    print("\nRight input (32 bits):")
    print_bits(right)
    
    print("\nSubkey (48 bits):")
    print_bits(subkey, width=6)
    
    # Apply round
    new_left, new_right = des._des_round(left, right, subkey)
    
    # Print outputs
    print("\nNew left output (32 bits):")
    print_bits(new_left)
    
    print("\nNew right output (32 bits):")
    print_bits(new_right)
    
    # Verify structure
    assert new_left == right, "DES round test failed - new left should be old right"
    assert len(new_right) == 32, "DES round test failed - wrong output size"
    print("\nDES round test passed!")

def test_encrypt_decrypt():
    """Test complete encryption and decryption."""
    print("\n=== Testing Complete Encryption/Decryption ===")
    
    # Test plaintext and key
    plaintext = b"Hello, World! This is a test message."
    key = b"SECRET!!"
    
    print(f"Plaintext: {plaintext.decode()}")
    print(f"Key: {key.decode()} ({binascii.hexlify(key).decode()})")
    
    # Create DES instance
    des = DES(key)
    
    # Encrypt
    ciphertext = des.encrypt(plaintext)
    print(f"\nCiphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    
    # Decrypt
    decrypted = des.decrypt(ciphertext)
    print(f"\nDecrypted: {decrypted.decode()}")
    
    # Verify
    assert decrypted == plaintext, "Encryption/decryption test failed"
    print("\nEncryption/decryption test passed!")

def main():
    """Main test function."""
    print("=== DES Algorithm Test Suite ===")
    
    # Run all tests
    test_initial_permutation()
    test_expansion()
    test_key_generation()
    test_s_box()
    test_permutation_p()
    test_f_function()
    test_des_round()
    test_encrypt_decrypt()
    
    print("\n=== All tests passed! ===")

if __name__ == "__main__":
    main()
