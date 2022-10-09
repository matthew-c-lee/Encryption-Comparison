import timeit # used to measure timings


# Parameters of S box
S_Box = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]

# Parameters of P box
P_Box = [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]


def generate_key_schedule(secret_key, num_subkeys):  # 32-bit secret key
    # Secret key arrangement algorithm
    key_schedule = []

    for _ in range(num_subkeys):
        ki = secret_key % (2 ^ 16)
        key_schedule.insert(0, ki)
        print(key_schedule)
        secret_key >>= 4    # remove 4 bits from the end

    return key_schedule     # list w/ five 16-bit subkeys


def substitution(s_box, bytes):    # bytes: 16-bit String
    # Packet substitution operation
    # bytes are taken from key schedule

    substituted_bytes = 0
    for i in range(4):
        bits_modded = bytes % (2**4)   # bytes mod 2^4 (16)
        vri = s_box[bits_modded]
        substituted_bytes += (vri << (4*i))
        bytes >>= 4     # shift bits to the right 4 places

    return substituted_bytes   # substituted bytes


def permutation(p_box, bits):  # bits: 16 bits
    # Single bit permutation operation
    permutation_result = 0
    for i in range(len(p_box), 0, -1):
        bits_mod_2 = bits % 2
        bits >>= 1    # shift bits right 1 place
        permutation_result += (bits_mod_2 << (len(p_box) - p_box[i-1]))
    return permutation_result   # 16 bits


def reverse_s_box(s_box):
    # Returns inverse of S-Box
    reversed_s_box = [None] * len(s_box)
    for i in range(len(s_box)):
        reversed_s_box[s_box[i]] = i

    return reversed_s_box


def reverse_p_box(p_box):
    # Finding the Inverse of P-Box
    reversed_p_box = [None] * len(p_box)  # allocate memory

    for i in range(len(p_box)):
        reversed_p_box[p_box[i] - 1] = i + 1
    return reversed_p_box       # Inverse of p-box


def SPN(bits_to_encrypt, s_box, p_box, key_schedule):   # 16-bits
    # Five rounds of SPN network can be used for encryption or decryption
    num_rounds = len(key_schedule) - 1

    permuted_bits = bits_to_encrypt
    for round in range(num_rounds):
        if round < num_rounds:  # runs every round except the last
            XORed_bits = permuted_bits ^ key_schedule[round]  # XOR operation
            substituted_bits = substitution(s_box, XORed_bits)  # packet substitution

        permuted_bits = permutation(p_box, substituted_bits)  # single bit permutation

    key_schedule = substituted_bits ^ key_schedule[num_rounds]
    return key_schedule   # return key schedule w/ 5 16-bit subkeys


def encrypt(plain_bits, key_schedule):   # 32 bits, 16 bits
    # Encryption of 16-bit plaintext x based on secret key K
    # key_schedule = generate_key_schedule(secret_key, num_subkeys)
    ciphertext = SPN(plain_bits, S_Box, P_Box, key_schedule)

    return ciphertext      # 16-bit ciphertext


# def decrypt(encrypted_bits, key_schedule):   # 32 bits, 16 bits
def decrypt(secret_key, encrypted_bits, num_subkeys):   # 32 bits, 16 bits
#     The 16-bit encrypted_bits are decrypted according to the secret_key.

    key_schedule = generate_key_schedule(secret_key, num_subkeys)
    key_schedule.reverse()  # reverse key schedule

    # Secret key replacement
    # i (1-3)
    for i in range(3):
        key_schedule[i+1] = permutation(P_Box, key_schedule[i+1])

    # 16-bit plaintext
    plaintext = SPN(encrypted_bits, reverse_s_box(S_Box), reverse_p_box(P_Box), key_schedule)
    return plaintext


def text_to_bits(text):
    encoding = 'utf-8'
    errors = 'surrogatepass'
    bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def text_from_bits(bits):
    encoding = 'utf-8'
    errors = 'surrogatepass'
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'


def add_byte_spaces(str, byte_size):
    # add spaces to bytes for readability
    output_str = ''

    for i in range(len(str)):
        # if it's divisible by byte size (typically 8)
        if i % byte_size == 0:
            output_str += ' '

        output_str += str[i]

    return output_str[1:]  # return all except first space


def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8], 2)) for i in range(len(s)//8))


def toAscii(letter):
    number = ord(letter)
    return number


def loopThrough(message):
    for n in message:
        print(n)
        print(toAscii(n))
        print('{0:b}\n'.format(toAscii(n)))


if __name__ == '__main__':
    SECRET_KEY = 0b00111010100101001101011000111111     # 32 bits
    NUM_SUBKEYS = 5

    key_schedule = generate_key_schedule(SECRET_KEY, NUM_SUBKEYS)

    plaintext = """
    Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.
    """

    result = [format(ord(plaintext[i]), '08b') + format(ord(plaintext[i+1]), '08b')
              for i in range(0, len(plaintext), 2)]

    result_in_binary = [int(i, 2) for i in result]

    # Encrypt data
    start1 = timeit.default_timer() # start timer
    encrypted_result = [encrypt(i, key_schedule)
                        for i in result_in_binary]
    end1 = timeit.default_timer() # start timer
    encryption_time = '{0:.4f}'.format((end1 - start1)*1000)

    # Decrypt data
    start = timeit.default_timer() # start timer
    decrypted_result = [decrypt(SECRET_KEY, i, NUM_SUBKEYS)
                        for i in encrypted_result]


    # key_schedule = generate_key_schedule(SECRET_KEY, NUM_SUBKEYS)
    # decrypted_result = [decrypt(i, key_schedule)
    #                     for i in encrypted_result]

    end = timeit.default_timer() # stop timer
    decryption_time = '{0:.4f}'.format((end - start)*1000)

    print(decrypted_result)

    final_text = ''.join(text_from_bits(format(i, '016b'))
                         for i in decrypted_result)
    
    print(final_text)
    print('Encryption time:', encryption_time, 'ms')
    print('Decryption time:', decryption_time, 'ms')
