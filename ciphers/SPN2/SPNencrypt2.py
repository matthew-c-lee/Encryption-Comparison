# Parameters of S box
S_Box = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]

# Parameters of P box
P_Box = [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]


def generate_key_schedule(secret_key, num_subkeys):  # 32-bit secret key
    # Secret key arrangement algorithm
    key_schedule = []

    for _ in range(num_subkeys):
        ki = secret_key % (2^16)
        key_schedule.insert(0, ki)
        secret_key >>= 4    # shift bits to the right 4 places

    return key_schedule     # list w/ five 16-bit subkeys


def substitution(s_box, bytes):    # ur: 16-bit String
    # bytes are taken from key schedule
    """
    Packet substitution operation
    Param s_box:S box parameter
    Paramer ur: Input Bit String, 16 Bits
    """
    

    substituted_bytes = 0
    for i in range(4):
        uri = bytes % (2^4)   # bytes mod 2^4 (16)
        vri = s_box[uri]
        substituted_bytes += (vri << (4 * i))
        bytes >>= 4     # shift bits to the right 4 places

    print(type(substituted_bytes))
    return substituted_bytes   # substituted bytes


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
        vr >>= 1    # shift bits right 1 place
        wr += (vri << (len(p_box) - p_box[i-1]))
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


def SPN(bits_to_encrypt, s_box, p_box, key_schedule):   # 16-bits
    # Five rounds of SPN network can be used for encryption or decryption
    num_rounds = len(key_schedule) - 1

    permuted_bits = bits_to_encrypt
    for round in range(num_rounds):
        if round < num_rounds:  # runs every round except the last
            XORed_bits = permuted_bits ^ key_schedule[round]  # XOR operation
            substituted_bits = substitution(
                s_box, XORed_bits)  # packet substitution

        permuted_bits = permutation(
            p_box, substituted_bits)  # single bit permutation

    key_schedule = substituted_bits ^ key_schedule[num_rounds]
    return key_schedule   # return key schedule w/ 5 16-bit subkeys


def encrypt(secret_key, plain_bits, num_subkeys):   # 32 bits, 16 bits
    # Encryption of 16-bit plaintext x based on secret key K

    key_schedule = generate_key_schedule(secret_key, num_subkeys)
    return SPN(plain_bits, S_Box, P_Box, key_schedule)      # 16-bit ciphertext


def decrypt(secret_key, encrypted_bits, num_subkeys):   # 32 bits, 16 bits
    # The 16-bit encrypted_bits are decrypted according to the secret_key.

    key_schedule = generate_key_schedule(secret_key, num_subkeys)
    key_schedule.reverse()  # reverse key schedule

    print(format(key_schedule[0], '016b'))

    # Secret key replacement
    for i in range(1, 4, 1):
        key_schedule[i] = permutation(P_Box, key_schedule[i])
    # key_schedule[1] = permutation(P_Box, key_schedule[1])
    # key_schedule[2] = permutation(P_Box, key_schedule[2])
    # key_schedule[3] = permutation(P_Box, key_schedule[3])

    # 16-bit plaintext
    return SPN(encrypted_bits, reverse_s_box(S_Box), reverse_p_box(P_Box), key_schedule)


def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8], 2)) for i in range(len(s)//8))


def add_byte_spaces(str, byte_size):
    output_str = ''

    for i in range(len(str)):
        # if it's divisible by 8
        if i % byte_size == 0:
            output_str += ' '

        output_str += str[i]

    return output_str[1:]  # return all except first space


if __name__ == '__main__':
    # PLAIN_TEXT = 0b0010011010110111     # block size: 16 bits
    # block size: 16 bits (message says "hi")
    PLAIN_TEXT = 0b0110100001101001
    plain_text_str = format(PLAIN_TEXT, '016b')
    NUM_SUBKEYS = 5

    SECRET_KEY = 0b00111010100101001101011000111111     # 32 bits

    # plain_text = format(encrypt(secret_key, plain_text), '016b')
    encrypted_text = encrypt(SECRET_KEY, PLAIN_TEXT, NUM_SUBKEYS)
    encrypted_text_str = format(encrypted_text, '016b')

    decrypted_text_str = format(decrypt(SECRET_KEY, encrypted_text, NUM_SUBKEYS), '016b')

    print(f'Initial text:      {add_byte_spaces(plain_text_str, 8)}')
    print(f'Encrypted text:    {add_byte_spaces(encrypted_text_str, 8)}')
    print(f'Decrypted text:    {add_byte_spaces(decrypted_text_str, 8)}')

    print(f'Initial text == Decrypted text: {plain_text_str == decrypted_text_str}')

    print(decode_binary_string(decrypted_text_str))

    # assert decrypt(SECRET_KEY, encrypt(SECRET_KEY, PLAIN_TEXT)) == PLAIN_TEXT
