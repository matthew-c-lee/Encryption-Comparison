# Parameters of S box
S_Box = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]

# Parameters of P box
P_Box = [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]


def generate_key_schedule(secret_key, num_subkeys):  # 32-bit secret key
    # Secret key arrangement algorithm
    key_schedule = []

    for _ in range(num_subkeys):
        ki = secret_key % (2 ** 16)
        key_schedule.insert(0, ki)
        secret_key = secret_key >> 4

    return key_schedule     # list w/ five 16-bit subkeys


def substitution(s_box, ur):    # ur: 16-bit String
    """
    Packet substitution operation
    Param s_box:S box parameter
    Paramur: Input Bit String, 16 Bits
    """
    vr = 0
    for i in range(4):
        uri = ur % (2 ** 4)
        vri = s_box[uri]
        vr = vr + (vri << (4 * i))
        ur = ur >> 4
    return vr   # 16-bit String


def permutation(p_box, vr):
    """
    Single bit permutation operation
    Param p_box: P-box parameter
    Param vr: input bit string, 16 bits
    Return: Output Bit String, 16 Bits
    """
    wr = 0
    for i in range(len(p_box), 0, -1):
        vri = vr % 2
        vr = vr >> 1
        wr = wr + (vri << (16 - p_box[i-1]))
    return wr


def reverse_s_box(s_box):
    """
    Finding the Inverse of S-Box
    Param s_box:S box parameter
    The inverse of return:S box
    """
    reversed_s_box = [None] * len(s_box)
    for i in range(len(s_box)):
        reversed_s_box[s_box[i]] = i

    return reversed_s_box


def reverse_p_box(p_box):
    """
    Finding the Inverse of P-Box
    Param s_box:P-box parameter
    Return: The Inverse of P Box
    """
    reversed_p_box = [None] * len(p_box)  # allocate memory
    for i in range(len(p_box)):
        reversed_p_box[p_box[i] - 1] = i + 1
    return reversed_p_box


def SPN(bits_to_encrypt, s_box, p_box, key_schedule):
    """
    Five rounds of SPN network can be used for encryption or decryption
    Param x: 16 bit input
    Param s_box: S box parameter
    Param p_box: P-box parameter
    Param key_schedule: [k1, k2, k3, k4, k5], five 16-bit subkeys
    Return: 16 bit output
    """
    permuted_bits = bits_to_encrypt
    for r in range(3):
        XORed_bits = permuted_bits ^ key_schedule[r]  # XOR operation
        substituted_bits = substitution(s_box, XORed_bits)  # packet substitution
        permuted_bits = permutation(p_box, substituted_bits)  # single bit permutation

    XORed_bits = permuted_bits ^ key_schedule[3]
    substituted_bits = substitution(s_box, XORed_bits)

    return substituted_bits ^ key_schedule[4]


def encrypt(secret_key, plain_bits, num_subkeys):   # 32 bits, 16 bits
    # Encryption of 16-bit plaintext x based on secret key K

    key_schedule = generate_key_schedule(secret_key, num_subkeys)
    return SPN(plain_bits, S_Box, P_Box, key_schedule)      # 16-bit ciphertext


def decrypt(secret_key, encrypted_bits, num_subkeys):   # 32 bits, 16 bits
    # The 16-bit encrypted_bits are decrypted according to the secret_key.

    key_schedule = generate_key_schedule(secret_key, num_subkeys)
    key_schedule.reverse()  # reverse key schedule

    # Secret key replacement
    key_schedule[1] = permutation(P_Box, key_schedule[1])
    key_schedule[2] = permutation(P_Box, key_schedule[2])
    key_schedule[3] = permutation(P_Box, key_schedule[3])

    # 16-bit plaintext
    return SPN(encrypted_bits, reverse_s_box(S_Box), reverse_p_box(P_Box), key_schedule)


if __name__ == '__main__':
    PLAIN_TEXT = 0b0010011010110111
    plain_text_str = format(PLAIN_TEXT, '016b')
    NUM_SUBKEYS = 5

    SECRET_KEY = 0b00111010100101001101011000111111

    # plain_text = format(encrypt(secret_key, plain_text), '016b')
    encrypted_text = encrypt(SECRET_KEY, PLAIN_TEXT, NUM_SUBKEYS)
    encrypted_text_str = format(encrypted_text, '016b')

    decrypted_text_str = format(
        decrypt(SECRET_KEY, encrypted_text, NUM_SUBKEYS), '016b')

    print(
        f'Initial text:     {plain_text_str[0:4]} {plain_text_str[4:8]} {plain_text_str[8:12]} {plain_text_str[12:16]}')
    print(
        f'Encrypted text:   {encrypted_text_str[0:4]} {encrypted_text_str[4:8]} {encrypted_text_str[8:12]} {encrypted_text_str[12:16]}')
    print(
        f'Decrypted text:   {decrypted_text_str[0:4]} {decrypted_text_str[4:8]} {decrypted_text_str[8:12]} {decrypted_text_str[12:16]}')

    print(
        f'Initial text == Decrypted text: {plain_text_str == decrypted_text_str}')

    # assert decrypt(SECRET_KEY, encrypt(SECRET_KEY, PLAIN_TEXT)) == PLAIN_TEXT
