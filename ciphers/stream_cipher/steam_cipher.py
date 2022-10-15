# most important: create a very good bit generator that cannot be found out based on patterns
# interesting: if you only wanted to decrypt say, the first 10,000 bits, we could do that

# diffusion is very low
# very easy to find key - just XOR the ciphertext and plaintext to obtain it

# create random bits based on plaintext, then XOR them

import random

def stream_cipher_test(key):
    random.seed(key)

    message = 'I like turtlesss!'
    message_bytes = bytes(message, 'utf-8')

    keystream = random.randbytes(len(message)) # keystream is same size as message

    print(f'\nKeystream: {keystream}')
    print(format(int.from_bytes(keystream, 'big'), '016b'), '\n')

    encrypted_bytes = bytes([a ^ b for a, b in zip(keystream, message_bytes)])
    print(f'Encrypted bits: {encrypted_bytes}')
    print(format(int.from_bytes(encrypted_bytes, 'big'), '016b'), '\n')

    # print encryoted bytes in string format
    decrypted_bytes = bytes([a ^ b for a, b in zip(keystream, encrypted_bytes)])
    print(f'Decrypted bits: {decrypted_bytes}')
    print(format(int.from_bytes(decrypted_bytes, 'big'), '016b'), '\n')

    decrypted_string = str(decrypted_bytes, 'utf-8')

    print(decrypted_string)

    return format(int.from_bytes(encrypted_bytes, 'big'), '016b')

if __name__ == '__main__':
    test1 = stream_cipher_test('test')
    test2 = stream_cipher_test('test1234')

    print(test1)
    print(test2)

