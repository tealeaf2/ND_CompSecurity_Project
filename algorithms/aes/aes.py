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
For preprocessing
"""
def transform_to_state(plaintext):
  """
  Convert a 16-byte array to a 4x4 AES state matrix.
  """
  text_bytes = plaintext.encode('utf-8')

  state = [[0] * 4 for _ in range(4)]
  for i in range(16):
    row = i % 4
    col = i // 4
    state[row][col] = text_bytes[i]

  return state


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

        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            word = [s_box[b] for b in word]

        word = xor_bytes(word, key_columns[-iteration_size])
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]



def encrypt(Nr, plaintext, key):
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
    state = transform_to_state(plaintext)

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

    # Flattening the 4x4 matrix
    ciphertext = []
    for col in range(4):
        for row in range(4):
            ciphertext.append(state[row][col])
    return ciphertext



def decrypt(Nr, ciphertext, key):
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
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = ciphertext[i]

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

    # Convert state to plaintext (flatten the 4x4 state matrix)
    plaintext = []
    for col in range(4):
        for row in range(4):
            plaintext.append(state[row][col])

    return plaintext


def main():
    plaintext = "example123456789"
    key = "thisisakey123456"

    Nr = 10 # Number of rounds for AES-128

    encrypted_text = encrypt(Nr, plaintext, key)
    ciphertext = ''.join(f'{b:02x}' for b in encrypted_text)
    print(ciphertext)

    ciphertext_bytes = bytes.fromhex(ciphertext)

    decrypted_text = decrypt(Nr, ciphertext_bytes, key)
    print(''.join(chr(b) for b in decrypted_text))


if __name__ == '__main__':
    main()