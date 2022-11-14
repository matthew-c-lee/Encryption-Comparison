import timeit  # used to measure timings
from scipy.spatial.distance import hamming

# Parameters of S box
S_Box = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]

# Parameters of P box
P_Box = [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]


def generate_key_schedule(secret_key, num_subkeys):  # 32-bit secret key
    # Secret key arrangement algorithm
    key_schedule = [None] * num_subkeys

    for i in range(num_subkeys, 0, -1):
        subkey = secret_key % 12
        key_schedule[i-1] = subkey  # assign
        secret_key >>= 4    # remove 4 bits from the end

    return key_schedule     # list w/ five 16-bit subkeys


def substitution(s_box, bytes):    # bytes: 16-bit String
    # Packet substitution operation
    # bytes are taken from key schedule
    block_size = len(s_box)  # s_box length is same as block length

    substituted_bytes = 0
    for i in range(0, block_size, 4):
        substituted_bytes += s_box[bytes % block_size] << i
        bytes >>= 4     # shift bits to the right 4 places

    return substituted_bytes   # substituted bytes


def permutation(p_box, bytes):  # bits: 16 bits
    # Single bit permutation operation
    block_size = len(p_box)  # block size is same as p_box

    permuted_bytes = 0
    for i in range(block_size - 1, -1, -1):
        permuted_bytes += (bytes % 2) << (block_size - p_box[i])
        bytes >>= 1    # shift bits right 1 place
    return permuted_bytes   # 16 bits


# Returns inverse of S-Box
def reverse_s_box(s_box):
    reversed_s_box = [None] * len(s_box)

    for i in range(len(s_box)):
        reversed_s_box[s_box[i]] = i
        
    return reversed_s_box


def reverse_p_box(p_box):
    # Finding the Inverse of P-Box

    reversed_p_box = [None] * len(p_box)
    for i in range(len(p_box)):
        reversed_p_box[p_box[i] - 1] = i + 1
        
    return reversed_p_box


def SPN(bits_to_encrypt, s_box, p_box, key_schedule):   # 16-bits
    # Five rounds of SPN network can be used for encryption or decryption
    num_rounds = len(key_schedule) - 1

    permuted_bits = bits_to_encrypt
    for i in range(num_rounds):
        if i < num_rounds:  # runs every round except the last
            XORed_bits = permuted_bits ^ key_schedule[i]  # XOR operation
            substituted_bits = substitution(
                s_box, XORed_bits)  # packet substitution

        permuted_bits = permutation(
            p_box, substituted_bits)  # single bit permutation

    transformed_bits = substituted_bits ^ key_schedule[num_rounds]
    return transformed_bits   # return key schedule w/ 5 16-bit subkeys


def encrypt(plain_bits, key_schedule):   # 32 bits, 16 bits
    # Encryption of 16-bit plaintext x based on secret key K
    # key_schedule = generate_key_schedule(secret_key, num_subkeys)
    ciphertext = SPN(plain_bits, S_Box, P_Box, key_schedule)

    return ciphertext      # 16-bit ciphertext


# def decrypt(encrypted_bits, key_schedule):   # 32 bits, 16 bits
def decrypt(secret_key, encrypted_bits, num_subkeys):   # 32 bits, 16 bits
    # The 16-bit encrypted_bits are decrypted according to the secret_key.

    key_schedule = generate_key_schedule(secret_key, num_subkeys)
    key_schedule.reverse()  # reverse key schedule

    # Secret key replacement
    # i (1-3)
    for i in range(1, 4):
        key_schedule[i] = permutation(P_Box, key_schedule[i])

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


def one_timing(key, num_subkeys, plaintext):
    key_schedule = generate_key_schedule(key, num_subkeys)

    message = [format(ord(plaintext[i]), '08b') + format(ord(plaintext[i+1]), '08b')
               for i in range(0, len(plaintext), 2)]

    message_in_binary = [int(i, 2) for i in message]

    # Encrypt data
    start1 = timeit.default_timer()  # start timer
    encrypted_result = [encrypt(i, key_schedule)
                        for i in message_in_binary]
    end1 = timeit.default_timer()  # start timer
    encryption_time = (end1 - start1)*1000

    # Decrypt data
    start = timeit.default_timer()  # start timer
    decrypted_result = [decrypt(SECRET_KEY, i, NUM_SUBKEYS)
                        for i in encrypted_result]
    end = timeit.default_timer()  # stop timer
    decryption_time = (end - start)*1000

    final_text = ''.join(text_from_bits(format(i, '016b'))
                         for i in decrypted_result)

    return [encryption_time, decryption_time]


def measure_all_timings(key, num_subkeys, n, message):
    all_encryption_times = []
    all_decryption_times = []

    # n = 100000

    for _ in range(n):
        times = one_timing(key, num_subkeys, message)

        all_encryption_times.append(times[0])
        all_decryption_times.append(times[1])

    encryption_average = sum(all_encryption_times) / len(all_encryption_times)
    decryption_average = sum(all_decryption_times) / len(all_decryption_times)

    return [encryption_average, decryption_average]


def measure_hamming(key, num_subkeys, plaintext):
    key_schedule = generate_key_schedule(key, num_subkeys)

    message = [format(ord(plaintext[i]), '08b') + format(ord(plaintext[i+1]), '08b')
               for i in range(0, len(plaintext), 2)]

    message_in_binary = [int(i, 2) for i in message]

    # Encrypt data
    encrypted_result = [encrypt(i, key_schedule)
                        for i in message_in_binary]

    # Decrypt data
    decrypted_result = [decrypt(SECRET_KEY, i, NUM_SUBKEYS)
                        for i in encrypted_result]

    encrypted_bytes_string = ''.join(format(i, '016b')
                                     for i in encrypted_result)
    decrypted_bytes_string = ''.join(format(i, '016b')
                                     for i in decrypted_result)
    return hamming(list(encrypted_bytes_string), list(decrypted_bytes_string)) * 100


def get_average_hamming(KEY, num_subkeys, message, n):
    hamming_distances = []
    for _ in range(n):
        hamming_distance = measure_hamming(KEY, num_subkeys, message)
        hamming_distances.append(hamming_distance)

    return sum(hamming_distances) / len(hamming_distances)


if __name__ == '__main__':
    SECRET_KEY = 0b00111010100101001101011000111111     # 32 bits
    NUM_SUBKEYS = 5

    plaintext = 'Lorem Ipsum is simply dummy text of the printing and typesetting industry.'

    key_schedule = generate_key_schedule(SECRET_KEY, NUM_SUBKEYS)

    message = [format(ord(plaintext[i]), '08b') + format(ord(plaintext[i+1]), '08b')
               for i in range(0, len(plaintext), 2)]

    message_in_binary = [int(i, 2) for i in message]

    # Encrypt data
    encrypted_result = [encrypt(i, key_schedule)
                        for i in message_in_binary]

    # Decrypt data
    decrypted_result = [decrypt(SECRET_KEY, i, NUM_SUBKEYS)
                        for i in encrypted_result]

    # Get string versions
    encrypted_bytes_string = ''.join(format(i, '016b')
                                     for i in encrypted_result)
    decrypted_bytes_string = ''.join(format(i, '016b')
                                     for i in decrypted_result)

    final_text = ''.join(text_from_bits(format(i, '16b'))
                         for i in decrypted_result)

    print(final_text)

    n = 10000

    hamming_average = get_average_hamming(
        SECRET_KEY, NUM_SUBKEYS, plaintext, n)
    encryption_average, decryption_average = measure_all_timings(
        SECRET_KEY, NUM_SUBKEYS, n, plaintext)
    print('Average hamming distance:', hamming_average)
    print('Average encryption time:', '{0:.4f}'.format(encryption_average))
    print('Average decryption time:', '{0:.4f}'.format(decryption_average))
