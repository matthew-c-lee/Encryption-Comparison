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


# Finding the Inverse of P-Box
def reverse_p_box(p_box):
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