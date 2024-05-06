# -*- coding: utf-8 -*-
"""Triangulation_Encryption_8_bit_Binary.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1Dc_pCbv61Am1l23AOibjD_AWr0b1yt0T
"""

def xnor(a, b):
    return ~(a ^ b) & 1

def triangular_encrypt(bit_stream):
    blocks = [bit_stream]  # Adjusted to work on an 8-bit input
    encrypted_blocks = []
    for block in blocks:
        triangle = [block]
        while len(triangle[-1]) > 1:
            new_level = ''.join(str(xnor(int(triangle[-1][i]), int(triangle[-1][i+1]))) for i in range(len(triangle[-1])-1))
            triangle.append(new_level)

        # Forming the target block from the triangle (example: using MSBs)
        target_block = ''.join(level[0] for level in triangle)
        encrypted_blocks.append(target_block)

    # Combine all encrypted blocks
    encrypted_bit_stream = ''.join(encrypted_blocks)
    return encrypted_bit_stream

# Adjusted for an 8-bit input example
bit_stream = "10010010"  # An 8-bit example bit stream
encrypted_stream = triangular_encrypt(bit_stream)
print(f"Encrypted bit stream: {encrypted_stream}")



def xnor(a, b):
    return ~(a ^ b) & 1

def triangular_encrypt(bit_stream):
    blocks = [bit_stream]  # Adjusted to work on variable-length input
    encrypted_blocks = []
    for block in blocks:
        triangle = [block]
        while len(triangle[-1]) > 1:
            new_level = ''.join(str(xnor(int(triangle[-1][i]), int(triangle[-1][i+1]))) for i in range(len(triangle[-1])-1))
            triangle.append(new_level)

        # Forming the target block from the triangle (example: using MSBs)
        target_block = ''.join(level[0] for level in triangle)
        encrypted_blocks.append(target_block)

    # Combine all encrypted blocks
    encrypted_bit_stream = ''.join(encrypted_blocks)
    return encrypted_bit_stream

# Accept user input for the bit stream
bit_stream = input("Enter an 8-bit stream: ")  # Prompt the user to enter an 8-bit stream

# Ensure the input is of correct length and format
if len(bit_stream) == 8 and all(bit in ['0', '1'] for bit in bit_stream):
    encrypted_stream = triangular_encrypt(bit_stream)
    print(f"Encrypted bit stream: {encrypted_stream}")
else:
    print("Invalid input. Please ensure you enter an 8-bit binary number.")





def triangular_encrypt(bit_stream):
    # Initialize the triangular structure
    triangle = [list(bit_stream)]

    # Generate the triangle using XOR operation for each pair of consecutive bits
    for i in range(len(bit_stream) - 1):
        new_level = []
        for j in range(len(triangle[i]) - 1):
            # XOR operation between consecutive bits
            new_level.append(str(int(triangle[i][j]) ^ int(triangle[i][j + 1])))
        triangle.append(new_level)

    # This step should be adapted based on the specific extraction logic defined in the document
    encrypted_stream = ''.join(row[0] for row in triangle)  # Adjusted to match the example output

    return encrypted_stream

# Accept user input for the bit stream
bit_stream = input("Enter an 8-bit stream: ")

# Ensure the input is of correct length and format
if len(bit_stream) == 8 and all(bit in ['0', '1'] for bit in bit_stream):
    encrypted_stream = triangular_encrypt(bit_stream)
    print(f"Encrypted bit stream: {encrypted_stream}")
else:
    print("Invalid input. Please ensure you enter an 8-bit binary number.")





def triangular_encrypt(bit_stream):
    # Initialize the triangular structure
    triangle = [list(bit_stream)]
    triangle_output = [' '.join(list(bit_stream))]  # Include the source bit stream in the output

    # Generate the triangle using XOR operation for each pair of consecutive bits
    for i in range(len(bit_stream) - 1):
        new_level = []
        for j in range(len(triangle[i]) - 1):
            # XOR operation between consecutive bits
            new_bit = str(int(triangle[i][j]) ^ int(triangle[i][j + 1]))
            new_level.append(new_bit)
        triangle.append(new_level)
        triangle_output.append(' '.join(new_level))

    # This step should be adapted based on the specific extraction logic defined in the document
    encrypted_stream = ''.join(row[0] for row in triangle)  # Adjusted to match the example output

    return encrypted_stream, triangle_output

# Accept user input for the bit stream
bit_stream = input("Enter an 8-bit stream: ")

# Ensure the input is of correct length and format
if len(bit_stream) == 8 and all(bit in ['0', '1'] for bit in bit_stream):
    encrypted_stream, triangle_output = triangular_encrypt(bit_stream)
    print(f"Encrypted bit stream: {encrypted_stream}")
    print("Triangle Structure:")
    for level in triangle_output:
        print(level)
else:
    print("Invalid input. Please ensure you enter an 8-bit binary number.")







def triangular_encrypt(bit_stream):
    # Initialize the triangular structure
    triangle = [list(bit_stream)]
    triangle_output = [f"Level-{1} {' '.join(list(bit_stream))}"]  # Include the source bit stream in the output

    # Generate the triangle using XOR operation for each pair of consecutive bits
    for level_index in range(len(bit_stream) - 1):
        new_level = []
        for j in range(len(triangle[level_index]) - 1):
            # XOR operation between consecutive bits
            new_bit = str(int(triangle[level_index][j]) ^ int(triangle[level_index][j + 1]))
            new_level.append(new_bit)
        triangle.append(new_level)
        triangle_output.append(f"Level-{level_index+2} {' '.join(new_level)}")  # Include the level name

    # This step should be adapted based on the specific extraction logic defined in the document
    encrypted_stream = ''.join(row[0] for row in triangle)  # Adjusted to match the example output

    return encrypted_stream, triangle_output

# Accept user input for the bit stream
bit_stream = input("Enter an 8-bit stream: ")

# Ensure the input is of correct length and format
if len(bit_stream) == 8 and all(bit in ['0', '1'] for bit in bit_stream):
    encrypted_stream, triangle_output = triangular_encrypt(bit_stream)
    print(f"Encrypted bit stream: {encrypted_stream}")
    print("Triangle Structure:")
    for level in triangle_output:
        print(level)
else:
    print("Invalid input. Please ensure you enter an 8-bit binary number.")