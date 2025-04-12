import sys
from mapping import s_box, inv_s_box, r_con


"""
All helper functions for the steps of encryption and decryption
"""
def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


"""
Support for padding input to fit as 16 sized blocks
"""
def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def split_blocks(message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]


"""
Extra helper functions
"""
def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))


"""
Expanding the key for each round
"""
def key_expansion(n_rounds, master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """
    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    i = 1
    while len(key_columns) < (n_rounds + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            
            word.append(word.pop(0))
            word = [s_box[b] for b in word]
            word[0] ^= r_con[i]
            i += 1

        # elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
        #     word = [s_box[b] for b in word]

        word = xor_bytes(word, key_columns[-iteration_size])
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]



def encrypt_block(Nr, plaintext, key):
    '''
    Encryption:

    Plaintext (16 bytes)
            ↓
        AddRoundKey (Round 0)
            ↓
    [Round 1 → 9]
        - SubBytes
        - ShiftRows
        - MixColumns
        - AddRoundKey
            ↓
    [Final Round 10]
        - SubBytes
        - ShiftRows
        - AddRoundKey
            ↓
    Ciphertext (16 bytes)
    '''
    assert len(plaintext) == 16, "Plaintext must be exactly 16 bytes."
    state = bytes2matrix(plaintext)

    k_in_bytes = key.encode('utf-8')
    assert len(k_in_bytes) == 16, "Key must be exactly 16 bytes."

    round_keys = key_expansion(Nr, k_in_bytes)
    add_round_key(state, round_keys[0])

    # Round 1 - 9
    for rnd in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])

    # Final round
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[Nr])

    return matrix2bytes(state)



def decrypt_block(Nr, ciphertext, key):
    '''
    Decryption:

    Ciphertext (in bytes)
            ↓
    Unflatten back to a 4x4 matrix for state
            ↓
    AddRoundKey (Round 0)
            ↓
    [Round 1 → 9]
        - InvSubBytes
        - InvShiftRows
        - InvMixColumns
        - InvAddRoundKey
            ↓
    [Final Round 10]
        - InvSubBytes
        - InvShiftRows
        - AddRoundKey
            ↓
    Plaintext (16 bytes)
    '''
    state = bytes2matrix(ciphertext)

    k_in_bytes = key.encode('utf-8')
    assert len(k_in_bytes) == 16, "Key must be exactly 16 bytes."

    round_keys = key_expansion(Nr, k_in_bytes)
    add_round_key(state, round_keys[Nr])

    # Main rounds (9 through 1)
    for rnd in range(Nr - 1, 0, -1):
        inv_sub_bytes(state)
        inv_shift_rows(state)
        add_round_key(state, round_keys[rnd])
        inv_mix_columns(state)

    # Final round (without InvMixColumns)
    inv_sub_bytes(state)
    inv_shift_rows(state)
    add_round_key(state, round_keys[0])

    return matrix2bytes(state)


# Functions to call
def encrypt(Nr, plaintext, key):
    padded = pad(plaintext.encode('utf-8'))

    encrypted_blocks = []
    for block in split_blocks(padded):
        encrypted_blocks.append(encrypt_block(Nr, block, key))

    ciphertext = b''.join(encrypted_blocks)
    print(ciphertext.hex())
    return ciphertext


def decrypt(Nr, ciphertext, key):
    decrypted_blocks = []
    for block in split_blocks(ciphertext):
        decrypted_blocks.append(decrypt_block(Nr, block, key))

    decrypted_padded = b''.join(decrypted_blocks)
    unpadded = unpad(decrypted_padded)

    print(unpadded.decode('utf-8'))
    return unpadded.decode('utf-8')



def main():
    """
    Current implementation supports AES-128 and ECB mode with PKCS#7 padding.
    """
    plaintext = "example1234567891011111101010101"
    key = "thisisakey123456"
    Nr = 10  # Number of rounds for AES-128

    ciphertext = encrypt(Nr, plaintext, key)
    res = decrypt(Nr, ciphertext, key)


if __name__ == '__main__':
    main()