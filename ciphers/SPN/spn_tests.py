from spn_cipher import *

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
    decryption_time = (end - start) * 1000

    return [encryption_time, decryption_time]


def measure_all_timings(key, num_subkeys, n, message):
    all_encryption_times = []
    all_decryption_times = []

    # loop n times, adding to lists each time
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
