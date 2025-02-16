"""
Author: Elijah Cross
Date: Jan 30th 2025
Part of the challenge "Lady Liz" on MysteryTwister.org


Lady Liz Encryption Implementation
=================================

This module implements the Lady Liz encryption algorithm, a symmetric key cipher that operates on
printable ASCII characters using keyed substitution alphabets and dynamic state changes.

Key Features:
- Digraph-based encryption/decryption (processes text in pairs of characters)
- Uses two rotating keyed alphabets for substitution
- Includes initialization vector (IV) for adding randomness
- Maintains message formatting (line breaks)
- Supports both file-based and direct input/output

Using functions in external scripts:
    from lady_liz import encrypt_message, decrypt_message, create_keyed_alphabets

    # Create keyed alphabets from keywords
    keywords = ["your_first_key", "your_second_key"]
    keyed_alphabets = create_keyed_alphabets(keywords)

    # Encrypt a message
    iv = "AB"  # Two-character initialization vector
    encrypted_message, line_breaks, padding_added, encryption_time = encrypt_message(
        plaintext, keyed_alphabets, iv
    )

    # Decrypt a message
    decrypted_message, decryption_time = decrypt_message(
        ciphertext, keyed_alphabets, iv, line_breaks, padding_added
    )

Security Note:
    This implementation is for educational purposes. For production use, employ standard
    cryptographic libraries like pycryptodome or cryptography.
"""

import secrets
import argparse
import string
import time
import sys

# Define printable ASCII characters, excluding whitespace control characters
PRINTABLE_ASCII = string.printable.replace('\t\n\r\x0b\x0c', '')

def measure_time(func):
    """
    Decorator to measure execution time of functions.
    
    Args:
        func: The function to measure
        
    Returns:
        tuple: Function results and execution time
    """
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        return (*result, execution_time)
    return wrapper

def create_keyed_alphabets(keywords):
    """
    Create keyed alphabets from the provided keywords.
    
    Args:
        keywords (list): List of two keyword strings
        
    Returns:
        list: Two keyed alphabets derived from the keywords
        
    Raises:
        ValueError: If fewer than 2 keywords provided or if keywords contain invalid characters
    """
    if len(keywords) < 2:
        raise ValueError("Two keywords are required")
    
    if not all(all(char in PRINTABLE_ASCII for char in keyword) for keyword in keywords):
        raise ValueError("Keywords must contain only printable ASCII characters")

    keyed_alphabets = []
    for keyword in keywords:
        # Create unique character sequence from keyword while preserving order
        keyword_unique = ''.join(sorted(set(keyword), key=keyword.index))
        # Append remaining printable ASCII characters in sorted order
        keyed_alphabet = keyword_unique + ''.join(sorted(set(PRINTABLE_ASCII) - set(keyword_unique)))
        keyed_alphabets.append(keyed_alphabet)
    return keyed_alphabets

def rotate_alphabet(alphabet, shift_amount):
    """
    Rotate an alphabet string by the specified amount.
    
    Args:
        alphabet (str): The alphabet to rotate
        shift_amount (int): Number of positions to rotate
        
    Returns:
        str: Rotated alphabet
    """
    return alphabet[-shift_amount:] + alphabet[:-shift_amount]

def generate_unique_shuffle_key():
    """
    Generate a randomly shuffled key using all printable ASCII characters.
    
    Returns:
        str: Shuffled printable ASCII characters
    """
    key = list(PRINTABLE_ASCII)
    secrets.SystemRandom().shuffle(key)
    return ''.join(key)

def preprocess_message(message):
    """
    Prepare message for encryption by filtering characters and handling padding.
    
    Args:
        message (str): Original message
        
    Returns:
        tuple: (filtered_message, line_break_positions, padding_added_flag)
    """
    printable_count = 0
    line_breaks = []
    
    # Track position of line breaks in original message
    for char in message:
        if char in PRINTABLE_ASCII:
            printable_count += 1
        if char == '\n':
            line_breaks.append(printable_count)

    # Filter out non-printable characters
    filtered_message = ''.join(filter(lambda x: x in PRINTABLE_ASCII, message))
    
    # Add padding if necessary for even length
    padding_added = False
    if len(filtered_message) % 2 != 0:
        filtered_message += secrets.choice(PRINTABLE_ASCII)
        padding_added = True
        
    return filtered_message, line_breaks, padding_added

@measure_time
def core_encrypt(filtered_message, keyed_alphabets, iv):
    """
    Core encryption function implementing the Lady Liz algorithm.
    
    Args:
        filtered_message (str): Preprocessed message to encrypt
        keyed_alphabets (list): List of two keyed alphabets
        iv (str): Two-character initialization vector
        
    Returns:
        tuple: (encrypted_message, final_keyed_alphabets)
    """
    result = []
    cycle_length = len(keyed_alphabets)
    current_index = 0
    current_iv = iv
    state_info = []

    # Process message in digraphs (pairs of characters)
    for i in range(0, len(filtered_message), 2):
        digraph = filtered_message[i:i+2]
        next_index = (current_index + 1) % cycle_length

        # Calculate positions for first round of substitution
        first_pos = ((keyed_alphabets[current_index].index(current_iv[0]) + 1) + 
                    (keyed_alphabets[current_index].index(digraph[0]) + 1) - 1) % 95
        second_pos = ((keyed_alphabets[current_index].index(current_iv[1]) + 1) + 
                     (keyed_alphabets[current_index].index(digraph[1]) + 1) - 1) % 95
        intermediate_block = (keyed_alphabets[current_index][first_pos] + 
                            keyed_alphabets[current_index][second_pos])

        # Calculate distances and perform second round of substitution
        if intermediate_block[0] == intermediate_block[1]:
            first_letter_distance = 95
        else:
            first_letter_distance = (keyed_alphabets[current_index].index(intermediate_block[1]) - 
                                   keyed_alphabets[current_index].index(intermediate_block[0])) % 95

        first_letter = keyed_alphabets[next_index][(first_letter_distance + 94) % 95]

        second_letter_distance = (keyed_alphabets[next_index].index(intermediate_block[0]) - 
                                keyed_alphabets[next_index].index(first_letter)) % 95
        second_letter = keyed_alphabets[current_index][(second_letter_distance + 94) % 95]

        ciphertext_digraph = first_letter + second_letter
        result.append(ciphertext_digraph)

        # Record state information for logging
        state_info.append({
            'digraph': digraph,
            'current_key_index': current_index,
            'current_key': keyed_alphabets[current_index],
            'next_key_index': next_index,
            'next_key': keyed_alphabets[next_index],
            'intermediate_block': intermediate_block,
            'ciphertext': ciphertext_digraph,
            'first_letter_distance': first_letter_distance,
            'second_letter_distance': second_letter_distance,
            'shift_for_cycle': first_letter_distance % cycle_length,
            'shift_for_order': second_letter_distance,
            'current_iv': current_iv
        })

        # Update alphabet state based on intermediate results
        if intermediate_block[0] != intermediate_block[1]:
            first_key = keyed_alphabets[current_index]
            first_key_list = list(first_key)
            pos1, pos2 = first_key.index(intermediate_block[0]), first_key.index(intermediate_block[1])
            first_key_list[pos1], first_key_list[pos2] = first_key_list[pos2], first_key_list[pos1]
            keyed_alphabets[current_index] = ''.join(first_key_list)

        if first_letter != second_letter:
            second_key = keyed_alphabets[next_index]
            second_key_list = list(second_key)
            pos1, pos2 = second_key.index(first_letter), second_key.index(second_letter)
            second_key_list[pos1], second_key_list[pos2] = second_key_list[pos2], second_key_list[pos1]
            keyed_alphabets[next_index] = ''.join(second_key_list)

        # Update state for next iteration
        shift_for_cycle = first_letter_distance % cycle_length
        shift_for_order = second_letter_distance

        current_index = (current_index + shift_for_cycle) % cycle_length
        keyed_alphabets = [rotate_alphabet(alphabet, shift_for_order) for alphabet in keyed_alphabets]

        current_iv = ciphertext_digraph

    log_encryption_process(state_info)
    return ''.join(result), keyed_alphabets

def encrypt_message(message, keyed_alphabets, iv):
    """
    High-level encryption function that handles preprocessing and core encryption.
    
    Args:
        message (str): Original message to encrypt
        keyed_alphabets (list): List of two keyed alphabets
        iv (str): Two-character initialization vector
        
    Returns:
        tuple: (encrypted_message, line_breaks, padding_added, encryption_time)
        
    Raises:
        ValueError: If iv or keyed_alphabets are invalid
    """
    if len(iv) != 2 or not all(char in PRINTABLE_ASCII for char in iv):
        raise ValueError("IV must be exactly 2 printable ASCII characters")
        
    if len(keyed_alphabets) != 2 or not all(len(alpha) == len(PRINTABLE_ASCII) for alpha in keyed_alphabets):
        raise ValueError("Invalid keyed alphabets format")

    filtered_message, line_breaks, padding_added = preprocess_message(message)
    encrypted_message, final_keyed_alphabets, encryption_time = core_encrypt(
        filtered_message, keyed_alphabets.copy(), iv
    )
    
    return encrypted_message, line_breaks, padding_added, encryption_time

@measure_time
def core_decrypt(ciphertext, keyed_alphabets, iv):
    """
    Core decryption function implementing the Lady Liz algorithm.
    
    Args:
        ciphertext (str): Encrypted message to decrypt
        keyed_alphabets (list): List of two keyed alphabets
        iv (str): Two-character initialization vector
        
    Returns:
        tuple: (decrypted_message, final_keyed_alphabets)
    """
    result = []
    cycle_length = len(keyed_alphabets)
    current_index = 0
    current_iv = iv
    state_info = []

    for i in range(0, len(ciphertext), 2):
        digraph = ciphertext[i:i+2]
        next_index = (current_index + 1) % cycle_length

        # Reverse the encryption process to recover intermediate block
        first_letter_distance = (keyed_alphabets[current_index].index(digraph[1]) + 1) % 95
        intermediate_first_letter = keyed_alphabets[next_index][
            (keyed_alphabets[next_index].index(digraph[0]) + first_letter_distance) % 95
        ]

        second_letter_distance = (keyed_alphabets[next_index].index(digraph[0]) + 1) % 95
        if second_letter_distance == 0:
            second_letter_distance = 95
        intermediate_second_letter = keyed_alphabets[current_index][
            (keyed_alphabets[current_index].index(intermediate_first_letter) + second_letter_distance) % 95
        ]

        intermediate_block = intermediate_first_letter + intermediate_second_letter

        # Recover original plaintext
        first_pos = (keyed_alphabets[current_index].index(intermediate_block[0]) - 
                    (keyed_alphabets[current_index].index(current_iv[0]) + 1)) % 95
        second_pos = (keyed_alphabets[current_index].index(intermediate_block[1]) - 
                     (keyed_alphabets[current_index].index(current_iv[1]) + 1)) % 95
        plaintext_digraph = keyed_alphabets[current_index][first_pos] + keyed_alphabets[current_index][second_pos]

        result.append(plaintext_digraph)

        # Record state information for logging
        state_info.append({
            'digraph': digraph,
            'current_key_index': current_index,
            'current_key': keyed_alphabets[current_index],
            'next_key_index': next_index,
            'next_key': keyed_alphabets[next_index],
            'intermediate_block': intermediate_block,
            'plaintext': plaintext_digraph,
            'first_letter_distance': first_letter_distance,
            'second_letter_distance': second_letter_distance,
            'shift_for_cycle': second_letter_distance % cycle_length,
            'shift_for_order': first_letter_distance,
            'current_iv': current_iv
        })

        # Update alphabet state based on intermediate results
        if intermediate_block[0] != intermediate_block[1]:
            first_key = keyed_alphabets[current_index]
            first_key_list = list(first_key)
            pos1, pos2 = first_key.index(intermediate_block[0]), first_key.index(intermediate_block[1])
            first_key_list[pos1], first_key_list[pos2] = first_key_list[pos2], first_key_list[pos1]
            keyed_alphabets[current_index] = ''.join(first_key_list)

        if digraph[0] != digraph[1]:
            second_key = keyed_alphabets[next_index]
            second_key_list = list(second_key)
            pos1, pos2 = second_key.index(digraph[0]), second_key.index(digraph[1])
            second_key_list[pos1], second_key_list[pos2] = second_key_list[pos2], second_key_list[pos1]
            keyed_alphabets[next_index] = ''.join(second_key_list)

        # Update state for next iteration
        shift_for_cycle = second_letter_distance % cycle_length
        shift_for_order = first_letter_distance

        current_index = (current_index + shift_for_cycle) % cycle_length
        keyed_alphabets = [rotate_alphabet(alphabet, shift_for_order) for alphabet in keyed_alphabets]

        current_iv = digraph

    log_decryption_process(state_info)
    return ''.join(result), keyed_alphabets

def decrypt_message(ciphertext, keyed_alphabets, iv, line_breaks, padding_added):
    """
    High-level decryption function that handles core decryption and post-processing.
    
    Args:
        ciphertext (str): Encrypted message to decrypt
        keyed_alphabets (list): List of two keyed alphabets
        iv (str): Two-character initialization vector
        line_breaks (list): Positions of original line breaks
        padding_added (bool): Whether padding was added during encryption
        
    Returns:
        tuple: (decrypted_message, decryption_time)
        
    Raises:
        ValueError: If iv or keyed_alphabets are invalid
    """
    if len(iv) != 2 or not all(char in PRINTABLE_ASCII for char in iv):
        raise ValueError("IV must be exactly 2 printable ASCII characters")
        
    if len(keyed_alphabets) != 2 or not all(len(alpha) == len(PRINTABLE_ASCII) for alpha in keyed_alphabets):
        raise ValueError("Invalid keyed alphabets format")

    decrypted_message, final_keyed_alphabets, decryption_time = core_decrypt(
        ciphertext, keyed_alphabets.copy(), iv
    )

    # Remove padding if it was added during encryption
    if padding_added:
        decrypted_message = decrypted_message[:-1]

    # Restore original line breaks
    if line_breaks:
        for pos in sorted(line_breaks, reverse=True):
            if pos <= len(decrypted_message):
                decrypted_message = decrypted_message[:pos] + '\n' + decrypted_message[pos:]

    return decrypted_message, decryption_time

def log_encryption_process(state_info):
    """
    Log detailed encryption process information to files.
    
    Args:
        state_info (list): List of dictionaries containing state information for each step
    """
    with open("encryption_log.txt", "w") as file, open("95Log.txt", "w") as log_file:
        for step in state_info:
            # Extract state information
            digraph = step['digraph']
            current_key_index = step['current_key_index']
            current_key = step['current_key']
            next_key_index = step['next_key_index']
            next_key = step['next_key']
            intermediate_block = step['intermediate_block']
            ciphertext = step['ciphertext']
            first_letter_distance = step['first_letter_distance']
            second_letter_distance = step['second_letter_distance']
            shift_for_cycle = step['shift_for_cycle']
            shift_for_order = step['shift_for_order']
            current_iv = step['current_iv']

            # Write basic log
            file.write(f"{digraph} via Key {current_key_index + 1} ({current_key}) & Key {next_key_index + 1} ({next_key}) => {ciphertext}\n")

            # Write detailed log
            log_file.write(f"Digraph: {digraph}\n")
            log_file.write(f"IV: {current_iv}\n")
            log_file.write(f"Intermediate block: {intermediate_block}\n")
            log_file.write(f"Key {current_key_index + 1}: {current_key}\n")
            log_file.write(f"Key {next_key_index + 1}: {next_key}\n")
            log_file.write(f"First letter distance: {first_letter_distance if first_letter_distance != 0 else 95}\n")
            log_file.write(f"Second letter distance: {second_letter_distance if second_letter_distance != 0 else 95}\n")
            log_file.write(f"Ciphertext: {ciphertext}\n")
            log_file.write(f"Shift for cycle: {shift_for_cycle}\n")
            log_file.write(f"Shift for order: {shift_for_order}\n")
            log_file.write("\n")

def log_decryption_process(state_info):
    """
    Log detailed decryption process information to files.
    
    Args:
        state_info (list): List of dictionaries containing state information for each step
    """
    with open("decryption_log.txt", "w") as file, open("95Log_decrypt.txt", "w") as log_file:
        for step in state_info:
            # Extract state information
            digraph = step['digraph']
            current_key_index = step['current_key_index']
            current_key = step['current_key']
            next_key_index = step['next_key_index']
            next_key = step['next_key']
            intermediate_block = step['intermediate_block']
            plaintext = step['plaintext']
            first_letter_distance = step['first_letter_distance']
            second_letter_distance = step['second_letter_distance']
            shift_for_cycle = step['shift_for_cycle']
            shift_for_order = step['shift_for_order']
            current_iv = step['current_iv']

            # Write basic log
            file.write(f"{digraph} via Key {current_key_index + 1} ({current_key}) & Key {next_key_index + 1} ({next_key}) => {plaintext}\n")

            # Write detailed log
            log_file.write(f"Ciphertext digraph: {digraph}\n")
            log_file.write(f"IV: {current_iv}\n")
            log_file.write(f"Intermediate block: {intermediate_block}\n")
            log_file.write(f"Key {current_key_index + 1}: {current_key}\n")
            log_file.write(f"Key {next_key_index + 1}: {next_key}\n")
            log_file.write(f"First letter distance: {first_letter_distance if first_letter_distance != 0 else 95}\n")
            log_file.write(f"Second letter distance: {second_letter_distance if second_letter_distance != 0 else 95}\n")
            log_file.write(f"Plaintext: {plaintext}\n")
            log_file.write(f"Shift for cycle: {shift_for_cycle}\n")
            log_file.write(f"Shift for order: {shift_for_order}\n")
            log_file.write("\n")
def main():
    parser = argparse.ArgumentParser(
        description="Command-line tool for encryption and decryption using a custom cipher."
    )
    
    parser.add_argument("mode", choices=["e", "d"], help="Mode: 'e' for encrypt, 'd' for decrypt")
    parser.add_argument("-iv", required=True, help="Two-letter initialization vector (IV)")
    parser.add_argument("-k1", required=True, help="First key (printable ASCII characters only)")
    parser.add_argument("-k2", required=True, help="Second key (printable ASCII characters only)")
    parser.add_argument("-f", "--file", action="store_true", help="Read input from pt.txt (encryption) or ct.txt (decryption)")
    
    if len(sys.argv) == 1:
        # print usage
        parser.print_help()
        print("Usage: python script.py e -iv AB -k1 mykey1 -k2 mykey2 -f")
        print("Usage: python script.py d -iv AB -k1 mykey1 -k2 mykey2 -f")
        sys.exit(1)
    args = parser.parse_args()

    # Validate IV
    if len(args.iv) != 2 or not all(c in PRINTABLE_ASCII for c in args.iv):
        print("Error: IV must be exactly two printable ASCII characters.")
        sys.exit(1)
    
    # Validate keys
    if not all(c in PRINTABLE_ASCII for c in args.k1) or not all(c in PRINTABLE_ASCII for c in args.k2):
        print("Error: Keys must contain only printable ASCII characters.")
        sys.exit(1)
    
    keywords = [args.k1, args.k2]
    keyed_alphabets = create_keyed_alphabets(keywords)
    
    if args.mode == "e":
        # Handle encryption
        if args.file:
            try:
                with open('pt.txt', 'r', encoding='utf-8') as file:
                    message = file.read().replace('“', '"').replace('”', '"').replace('’', "'")
            except FileNotFoundError:
                print("Error: pt.txt file not found.")
                sys.exit(1)
        else:
            message = input("Enter plaintext message: ")
        
        encrypted_message, line_breaks, padding_added, encryption_time = encrypt_message(
            message, keyed_alphabets, args.iv
        )
        
        with open('ct.txt', 'w') as file:
            file.write(encrypted_message)
        
        with open('metadata.txt', 'w') as file:
            file.write(f"line_breaks:{','.join(map(str, line_breaks))}\n")
            file.write(f"padding_added:{padding_added}")
        
        print(f"\nEncrypted message: {' '.join([encrypted_message[i:i+2] for i in range(0, len(encrypted_message), 2)])}")
        print(f"\nCore encryption time: {encryption_time:.5f} seconds")
    
    elif args.mode == "d":
        # Handle decryption
        if args.file:
            try:
                with open('ct.txt', 'r') as file:
                    ciphertext = file.read()
            except FileNotFoundError:
                print("Error: ct.txt file not found.")
                sys.exit(1)
            
            try:
                with open('metadata.txt', 'r') as file:
                    metadata = file.readlines()
                    line_breaks = list(map(int, metadata[0].split(':')[1].strip().split(','))) if metadata[0].split(':')[1].strip() else None
                    padding_added = metadata[1].split(':')[1].strip() == 'True'
            except FileNotFoundError:
                print("Warning: metadata.txt not found. Line breaks will not be restored and padding status is unknown.")
                line_breaks = None
                padding_added = False
        else:
            ciphertext = input("Enter ciphertext message: ")
            line_breaks = None
            padding_added = False
        
        decrypted_message, decryption_time = decrypt_message(
            ciphertext, keyed_alphabets, args.iv, line_breaks, padding_added
        )
        
        print(f"\nDecrypted message:\n{decrypted_message}")
        print(f"\nCore decryption time: {decryption_time:.5f} seconds")

if __name__ == "__main__":

    main()
