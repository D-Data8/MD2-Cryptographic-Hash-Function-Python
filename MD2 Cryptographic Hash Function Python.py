#!/usr/bin/env python
# coding: utf-8

import binascii 

def MD2(input_string):
    """ Calculates the MD2 hash of any string input.
    Arguments:
        input_string
    Returns:
        Hexadecimal MD2 hash of the input string.
    """
    #------------------------------------------------------------------------------------------------
    # Step 1: Append Padding Bytes
    #------------------------------------------------------------------------------------------------
    
    #Convert the input string to a bytearray:
    m_bytes = bytearray(input_string, 'utf-8')
    
    #16-Bytes minus the length of the message in bytes, modulo 16 gives the 
    #length of padding needed (in Bytes):

    len_padding = 16-(len(m_bytes) % 16)

    #The value for each of the padding Bytes is the value of the length of the padding required:
    padding = bytearray(len_padding for i in range(len_padding))

    #Now add the padding to the original message, so that it is divisible by 16:
    padded_message = m_bytes + padding

    S = [41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,98, 167, 5, 243, 192, 199, 
         115, 140, 152, 147, 43, 217, 188, 76, 130, 202,30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 
         24, 138, 23, 229, 18,190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
         169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,128, 127, 93, 154, 90, 144, 
         50, 39, 53, 62, 204, 231, 191, 247, 151, 3,255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 
         172, 86, 170, 198,79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,69, 
         157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,27, 96, 37, 173, 174, 176, 185, 
         246, 28, 70, 97, 105, 52, 64, 126, 15,85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 
         197, 234, 38,44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,106, 220, 55, 
         200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,120, 136, 149, 139, 227, 99, 232, 109, 
         233, 203, 213, 254, 59, 0, 29, 57,242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 
         117, 75, 10,49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20]
    
    #------------------------------------------------------------------------------------------------
    # Step 2: Append a 16-byte checksum to the result of step 1
    #------------------------------------------------------------------------------------------------
    
    # Part A:  Clear the Checksum bytearray of 16 bytes:
    C = bytearray(0 for i in range(16))

    # Part B: Set L to zero:
    L=0 

    # Part C: Process each 16-Byte block:
    M = padded_message
    N = len(M)

    for i in range (0, int(N/16)):
        #Calculate the checksum block i, using each Byte within the 16-Byte block:
        for j in range (0, 16):
            c = M[i * 16 + j]
            C[j] = C[j] ^ (S[c^L])
            L = C[j]

    #Append the calculated checksum to the padded message:
    padded_message_checksum = M + C
    
    #------------------------------------------------------------------------------------------------
    # Step 3: Initialise MD Buffer
    #------------------------------------------------------------------------------------------------
    
    # A 48-Byte buffer is used to compute the message digest and this is initialised to zero.
    
    X = bytearray([0 for i in range(48)])
    
    #------------------------------------------------------------------------------------------------
    # Step 4: Process the Message in 16-Byte Blocks
    #------------------------------------------------------------------------------------------------
    
    M_PC = padded_message_checksum

    # Process each 16-Byte block:
    for i in range(0, int(len(M_PC)/16)):
        #Copy block i into X:
        for j in range(0, 16):
            X[16+j] = M_PC[(i*16) + j]
            X[32+j] = (X[16+j] ^ X[j])
    
        t = 0

        # Do 18 Rounds:
        for j in range(0, 18):
            # Round j:
            for k in range(0, 48):
                t = X[k] = (X[k] ^ S[t])
            t = (t+j) % 256
    
    #------------------------------------------------------------------------------------------------
    # Step 5: Output
    #------------------------------------------------------------------------------------------------

    binary_output = X[:16]
    hex_output = binascii.hexlify(binary_output).decode('utf-8')
    
    return (hex_output)
