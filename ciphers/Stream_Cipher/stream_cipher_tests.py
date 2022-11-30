from stream_cipher import *

def one_timing(key, message):
    # calculate timing of encryption
    start1 = timeit.default_timer() # start timer
    encrypted_bytes = encrypt(key, message)
    end1 = timeit.default_timer() # end timer
    
    # format time
    encryption_time = float('{0:.4f}'.format((end1 - start1)*1000))
    
    # calculate timing of decryption
    start2 = timeit.default_timer() # start timer
    decrypted_bytes = decrypt(key, encrypted_bytes)
    end2 = timeit.default_timer() # end timer

    # format time
    decryption_time = float('{0:.4f}'.format((end2 - start2)*1000))

    return [encryption_time, decryption_time]


# calculate hamming distance: divide by number of bits, multiply by 100
def measure_hamming(key, message):
    encrypted_bytes = encrypt(key, message)
    decrypted_bytes = decrypt(key, encrypted_bytes)

    # converting to string so it can be used with format()
    bit_string_length = '0' + str(len(message) * 8) + 'b'

    encrypted_bytes_str = format(int.from_bytes(encrypted_bytes, 'big'), bit_string_length)
    decrypted_bytes_str = format(int.from_bytes(decrypted_bytes, 'big'), bit_string_length)

    # return hamming distance between encrypted and decrypted bytes
    return hamming(list(encrypted_bytes_str), list(decrypted_bytes_str)) * 100


def get_average_timings(key, n, message):
    all_encryption_times = []
    all_decryption_times = []

    for _ in range(n):
        times = one_timing(key, message)

        all_encryption_times.append(times[0])
        all_decryption_times.append(times[1])

    encryption_average = sum(all_encryption_times) / len(all_encryption_times)
    decryption_average = sum(all_decryption_times) / len(all_decryption_times)

    return [encryption_average, decryption_average]

# calculate hamming distance: divide by number of bits, multiply by 100
def get_average_hamming(KEY, message, n):
    hamming_distances = []
    for _ in range(n):
        hamming_distance = measure_hamming(KEY, message)
        hamming_distances.append(hamming_distance)

    return sum(hamming_distances) / len(hamming_distances)
    

if __name__ == '__main__':
    KEY = 'test_key'
    message = 'Lorem Ipsum is simply dummy text of the printing and typesetting industry.'
    
    encrypted_bytes = encrypt(KEY, message)
    decrypted_bytes = decrypt(KEY, encrypted_bytes)

    bit_string_length = '0' + str(len(message) * 8) + 'b'

    # format bytes
    encrypted_bytes_str = format(int.from_bytes(encrypted_bytes, 'big'), bit_string_length)
    decrypted_bytes_str = format(int.from_bytes(decrypted_bytes, 'big'), bit_string_length)

    decrypted_string = str(decrypted_bytes, 'utf-8')
    print(decrypted_string)

    # how many tests used
    n = 10000
    
    timings_test_message = 'Lorem Ipsum is simply dummy text of the printing and typesetting industry.'
    
    # calculate hamming distance: divide by number of bits, multiply by 100
    hamming_average = get_average_hamming(KEY, message, n)
    encryption_average, decryption_average = get_average_timings(KEY, n, timings_test_message) # calculate average times
    print('Average hamming distance:', hamming_average)
    print('Average encryption time:', '{0:.4f}'.format(encryption_average))
    print('Average decryption time:', '{0:.4f}'.format(decryption_average))