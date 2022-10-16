# most important: create a very good bit generator that cannot be found out based on patterns
# interesting: if you only wanted to decrypt say, the first 10,000 bits, we could do that

# diffusion is very low
# very easy to find key - just XOR the ciphertext and plaintext to obtain it

# create random bits based on plaintext, then XOR them

import random
import timeit
from scipy.spatial.distance import hamming

def encrypt(key, message):
    message_bytes = bytes(message, 'utf-8')

    random.seed(key)
    keystream = random.randbytes(len(message)) # keystream is same size as message

    return XOR(keystream, message_bytes)

def decrypt(key, encrypted_bytes):
    random.seed(key)
    keystream = random.randbytes(len(message)) # keystream is same size as message

    return XOR(keystream, encrypted_bytes)

def XOR(keystream, message_bytes):
    return bytes([a ^ b for a, b in zip(keystream, message_bytes)])



def stream_cipher_test(key, message):
    encrypted_bytes = encrypt(key, message)
    decrypted_bytes = decrypt(key, message)
    
    # decrypted_string = str(decrypted_bytes, 'utf-8')    
    
    # print(f'\nKeystream: {keystream}')
    # print(format(int.from_bytes(keystream, 'big'), '016b'), '\n')
    
    # print(f'Encrypted bits: {encrypted_bytes}')
    # print(format(int.from_bytes(encrypted_bytes, 'big'), '016b'), '\n')
    
    # print(f'Decrypted bits: {decrypted_bytes}')
    # print(format(int.from_bytes(decrypted_bytes, 'big'), '016b'), '\n')

    # print(decrypted_string)

    return format(int.from_bytes(encrypted_bytes, 'big'), '016b')

def one_timing(key, message):
    start1 = timeit.default_timer() # start timer
    encrypted_bytes = encrypt(key, message)
    end1 = timeit.default_timer() # end timer
    
    encryption_time = float('{0:.4f}'.format((end1 - start1)*1000))
    
    start2 = timeit.default_timer() # start timer
    decrypted_bytes = decrypt(key, encrypted_bytes)
    end2 = timeit.default_timer() # end timer

    decryption_time = float('{0:.4f}'.format((end2 - start2)*1000))

    return [encryption_time, decryption_time]

def measure_hamming(key, message):
    encrypted_bytes = encrypt(key, message)
    decrypted_bytes = decrypt(key, encrypted_bytes)

    bit_string_length = '0' + str(len(message) * 8) + 'b'

    encrypted_bytes_str = format(int.from_bytes(encrypted_bytes, 'big'), bit_string_length)
    decrypted_bytes_str = format(int.from_bytes(decrypted_bytes, 'big'), bit_string_length)

    # decrypted_string = str(decrypted_bytes, 'utf-8')

    # calculate hamming distance: divide by number of bits, multiply by 100
    return hamming(list(encrypted_bytes_str), list(decrypted_bytes_str)) * 100


def get_average_timings(key, n, message):
    all_encryption_times = []
    all_decryption_times = []

    # n = 100000

    for _ in range(n):
        times = one_timing(key, message)

        all_encryption_times.append(times[0])
        all_decryption_times.append(times[1])

    encryption_average = sum(all_encryption_times) / len(all_encryption_times)
    decryption_average = sum(all_decryption_times) / len(all_decryption_times)

    return [encryption_average, decryption_average]

def get_average_hamming(KEY, message, n):
    hamming_distances = []
    for _ in range(n):
        hamming_distance = measure_hamming(KEY, message)
        hamming_distances.append(hamming_distance)

    return sum(hamming_distances) / len(hamming_distances)
    

if __name__ == '__main__':
    KEY = 'wowzers'
    message = 'Here is the message'
    
    encrypted_bytes = encrypt(KEY, message)
    decrypted_bytes = decrypt(KEY, encrypted_bytes)

    bit_string_length = '0' + str(len(message) * 8) + 'b'

    encrypted_bytes_str = format(int.from_bytes(encrypted_bytes, 'big'), bit_string_length)
    decrypted_bytes_str = format(int.from_bytes(decrypted_bytes, 'big'), bit_string_length)

    decrypted_string = str(decrypted_bytes, 'utf-8')
    print(decrypted_string)

    # calculate hamming distance: divide by number of bits, multiply by 100
    n = 10000
    
    timings_test_message = 'Lorem Ipsum is simply dummy text of the printing and typesetting industry.'
    
    hamming_average = get_average_hamming(KEY, message, n)
    encryption_average, decryption_average = get_average_timings(KEY, n, timings_test_message) # calculate average times
    print('Average hamming distance:', hamming_average)
    print('Average encryption time:', '{0:.4f}'.format(encryption_average))
    print('Average decryption time:', '{0:.4f}'.format(decryption_average))
