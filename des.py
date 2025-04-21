"""
DES (Data Encryption Standard) Implementation

This module implements the core DES algorithm with all its components:
- Initial permutation (IP) and its inverse (IP-1)
- Expansion/permutation (E-box)
- Key scheduling (PC-1, shift schedule, PC-2)
- The round function (XOR, S-boxes, P-box)
- The overall structure with 16 rounds
"""

class DES:
    # Initial Permutation table
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]

    # Inverse Initial Permutation table
    IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

    # Expansion table
    E = [32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32, 1]

    # Permutation Choice 1 table
    PC1 = [57, 49, 41, 33, 25, 17, 9,
           1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29,
           21, 13, 5, 28, 20, 12, 4]

    # Permutation Choice 2 table
    PC2 = [14, 17, 11, 24, 1, 5,
           3, 28, 15, 6, 21, 10,
           23, 19, 12, 4, 26, 8,
           16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55,
           30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53,
           46, 42, 50, 36, 29, 32]

    # Left circular shift schedule
    SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # S-Boxes
    S_BOXES = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    # Permutation P table
    P = [16, 7, 20, 21,
         29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2, 8, 24, 14,
         32, 27, 3, 9,
         19, 13, 30, 6,
         22, 11, 4, 25]

    def __init__(self, key, debug=False):
        """
        Initialize DES cipher with a key.
        
        Args:
            key (bytes): 8-byte key (64 bits, but only 56 bits are used)
            debug (bool): If True, print debug information during operations
        """
        if len(key) != 8:
            raise ValueError("Key must be 8 bytes (64 bits)")
        
        self.key = self._bytes_to_bit_array(key)
        self.debug = debug
        self.subkeys = self._generate_subkeys()
        
        if self.debug:
            print("Initial key (64 bits):", self.key)
            for i, subkey in enumerate(self.subkeys):
                print(f"Round key {i+1} (48 bits):", subkey)

    def _bytes_to_bit_array(self, data):
        """Convert bytes to a bit array."""
        result = []
        for byte in data:
            for i in range(7, -1, -1):  # MSB first
                result.append((byte >> i) & 1)
        return result

    def _bit_array_to_bytes(self, bits):
        """Convert a bit array to bytes."""
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)

    def _permute(self, block, table):
        """Permute the block using the given table."""
        return [block[table[i] - 1] for i in range(len(table))]

    def _initial_permutation(self, block):
        """Apply initial permutation to the 64-bit block."""
        if self.debug:
            print("Before IP:", block)
        result = self._permute(block, self.IP)
        if self.debug:
            print("After IP:", result)
        return result

    def _inverse_initial_permutation(self, block):
        """Apply inverse initial permutation to the 64-bit block."""
        if self.debug:
            print("Before IP^-1:", block)
        result = self._permute(block, self.IP_INV)
        if self.debug:
            print("After IP^-1:", result)
        return result

    def _expansion(self, block):
        """Expand 32-bit block to 48 bits using E-box."""
        if self.debug:
            print("Before E:", block)
        result = self._permute(block, self.E)
        if self.debug:
            print("After E:", result)
        return result

    def _permuted_choice_1(self, key):
        """Apply PC-1 permutation to 64-bit key to get 56-bit key."""
        if self.debug:
            print("Before PC-1:", key)
        result = self._permute(key, self.PC1)
        if self.debug:
            print("After PC-1:", result)
        return result

    def _permuted_choice_2(self, key):
        """Apply PC-2 permutation to 56-bit key to get 48-bit subkey."""
        if self.debug:
            print("Before PC-2:", key)
        result = self._permute(key, self.PC2)
        if self.debug:
            print("After PC-2:", result)
        return result

    def _left_circular_shift(self, bits, shift):
        """Apply left circular shift to a bit array."""
        return bits[shift:] + bits[:shift]

    def _generate_subkeys(self):
        """Generate 16 48-bit subkeys from the 64-bit master key."""
        # Apply PC-1
        key_56 = self._permuted_choice_1(self.key)
        
        # Split into left and right halves (28 bits each)
        c = key_56[:28]
        d = key_56[28:]
        
        # Generate 16 subkeys
        subkeys = []
        for i in range(16):
            # Apply shift schedule
            shift = self.SHIFT_SCHEDULE[i]
            c = self._left_circular_shift(c, shift)
            d = self._left_circular_shift(d, shift)
            
            # Combine C and D
            cd = c + d
            
            # Apply PC-2
            subkey = self._permuted_choice_2(cd)
            subkeys.append(subkey)
            
            if self.debug:
                print(f"Round {i+1} C:", c)
                print(f"Round {i+1} D:", d)
        
        return subkeys

    def _xor(self, a, b):
        """Bitwise XOR of two bit arrays."""
        return [a[i] ^ b[i] for i in range(len(a))]

    def _s_box_substitution(self, block):
        """
        Apply S-box substitution to transform 48-bit block to 32-bit block.
        
        Args:
            block (list): 48-bit block
            
        Returns:
            list: 32-bit block after S-box substitution
        """
        if self.debug:
            print("Before S-boxes:", block)
            
        # Split block into 8 groups of 6 bits each
        groups = [block[i:i+6] for i in range(0, 48, 6)]
        
        result = []
        for i, group in enumerate(groups):
            # First and last bit determine row (0-3)
            row = (group[0] << 1) | group[5]
            
            # Middle 4 bits determine column (0-15)
            col = (group[1] << 3) | (group[2] << 2) | (group[3] << 1) | group[4]
            
            # Get value from S-box (0-15)
            value = self.S_BOXES[i][row][col]
            
            # Convert to 4 bits
            for j in range(3, -1, -1):
                result.append((value >> j) & 1)
                
            if self.debug:
                print(f"S-box {i+1}: input={group}, row={row}, col={col}, output={value:04b}")
        
        if self.debug:
            print("After S-boxes:", result)
            
        return result

    def _permutation_p(self, block):
        """Apply permutation P to 32-bit block after S-box substitution."""
        if self.debug:
            print("Before P:", block)
        result = self._permute(block, self.P)
        if self.debug:
            print("After P:", result)
        return result

    def _f_function(self, r, subkey):
        """
        Apply Feistel function to right half and subkey.
        
        Args:
            r (list): 32-bit right half
            subkey (list): 48-bit subkey
            
        Returns:
            list: 32-bit result
        """
        # Expansion: 32 bits -> 48 bits
        expanded = self._expansion(r)
        
        # XOR with subkey
        xored = self._xor(expanded, subkey)
        if self.debug:
            print("After XOR with round key:", xored)
        
        # S-box substitution: 48 bits -> 32 bits
        substituted = self._s_box_substitution(xored)
        
        # Permutation P
        permuted = self._permutation_p(substituted)
        
        return permuted

    def _des_round(self, left, right, subkey):
        """
        Execute one round of DES.
        
        Args:
            left (list): 32-bit left half
            right (list): 32-bit right half
            subkey (list): 48-bit subkey
            
        Returns:
            tuple: (new left half, new right half)
        """
        # Calculate f(R, K)
        f_result = self._f_function(right, subkey)
        
        # XOR left half with f_result
        new_right = self._xor(left, f_result)
        if self.debug:
            print("After XOR with left half:", new_right)
        
        # New left half is the old right half
        new_left = right
        
        # Return new left and right halves
        return new_left, new_right

    def encrypt_block(self, plaintext_block):
        """
        Encrypt a 64-bit block using DES.
        
        Args:
            plaintext_block (list): 64-bit block to encrypt
            
        Returns:
            list: 64-bit encrypted block
        """
        # Initial permutation
        block = self._initial_permutation(plaintext_block)
        
        # Split into left and right halves
        left = block[:32]
        right = block[32:]
        
        if self.debug:
            print("Initial L:", left)
            print("Initial R:", right)
        
        # 16 rounds
        for i in range(16):
            if self.debug:
                print(f"\n--- Round {i+1} ---")
            
            # Apply round
            left, right = self._des_round(left, right, self.subkeys[i])
            
            if self.debug:
                print(f"L{i+1}:", left)
                print(f"R{i+1}:", right)
        
        # Swap final left and right halves
        if self.debug:
            print("\n--- Final swap ---")
            print("Before swap - L16:", left)
            print("Before swap - R16:", right)
        
        # Note: In DES, there's a final swap of L16 and R16
        final_block = right + left
        
        if self.debug:
            print("After swap:", final_block)
        
        # Inverse initial permutation
        ciphertext_block = self._inverse_initial_permutation(final_block)
        
        return ciphertext_block

    def decrypt_block(self, ciphertext_block):
        """
        Decrypt a 64-bit block using DES.
        
        Args:
            ciphertext_block (list): 64-bit block to decrypt
            
        Returns:
            list: 64-bit decrypted block
        """
        # Initial permutation
        block = self._initial_permutation(ciphertext_block)
        
        # Split into left and right halves
        left = block[:32]
        right = block[32:]
        
        if self.debug:
            print("Initial L:", left)
            print("Initial R:", right)
        
        # 16 rounds with reversed subkeys
        for i in range(16):
            if self.debug:
                print(f"\n--- Round {i+1} ---")
            
            # Apply round with reversed subkey order
            left, right = self._des_round(left, right, self.subkeys[15-i])
            
            if self.debug:
                print(f"L{i+1}:", left)
                print(f"R{i+1}:", right)
        
        # Swap final left and right halves
        if self.debug:
            print("\n--- Final swap ---")
            print("Before swap - L16:", left)
            print("Before swap - R16:", right)
        
        final_block = right + left
        
        if self.debug:
            print("After swap:", final_block)
        
        # Inverse initial permutation
        plaintext_block = self._inverse_initial_permutation(final_block)
        
        return plaintext_block

    def encrypt(self, plaintext):
        """
        Encrypt plaintext using DES.
        
        Args:
            plaintext (bytes): Data to encrypt (will be padded to 8-byte blocks)
            
        Returns:
            bytes: Encrypted data
        """
        # Pad to 8-byte blocks if necessary
        padding_length = 8 - (len(plaintext) % 8)
        if padding_length < 8:
            plaintext += bytes([padding_length]) * padding_length
        
        # Process each 8-byte block
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i+8]
            bit_block = self._bytes_to_bit_array(block)
            encrypted_bit_block = self.encrypt_block(bit_block)
            encrypted_block = self._bit_array_to_bytes(encrypted_bit_block)
            ciphertext.extend(encrypted_block)
        
        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using DES.
        
        Args:
            ciphertext (bytes): Data to decrypt (must be multiple of 8 bytes)
            
        Returns:
            bytes: Decrypted data with padding removed
        """
        if len(ciphertext) % 8 != 0:
            raise ValueError("Ciphertext length must be a multiple of 8 bytes")
        
        # Process each 8-byte block
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            bit_block = self._bytes_to_bit_array(block)
            decrypted_bit_block = self.decrypt_block(bit_block)
            decrypted_block = self._bit_array_to_bytes(decrypted_bit_block)
            plaintext.extend(decrypted_block)
        
        # Remove padding
        padding_length = plaintext[-1]
        if padding_length < 8 and all(b == padding_length for b in plaintext[-padding_length:]):
            plaintext = plaintext[:-padding_length]
        
        return bytes(plaintext)
