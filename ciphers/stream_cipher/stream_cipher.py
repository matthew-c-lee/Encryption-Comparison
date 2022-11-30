import random
from scipy.spatial.distance import hamming

def encrypt(key, message):
    message_bytes = bytes(message, 'utf-8')

    # key is used to generate seed to get a unique keystream with Random library
    random.seed(key)
    keystream = random.randbytes(len(message)) # keystream is same size as message

    return XOR(keystream, message_bytes)

def decrypt(key, encrypted_bytes):
    # key is used to generate seed to get a unique keystream with Random library
    random.seed(key)
    keystream = random.randbytes(len(encrypted_bytes)) # keystream is same size as message

    return XOR(keystream, encrypted_bytes)

def XOR(keystream, message_bytes):
    return bytes([a ^ b for a, b in zip(keystream, message_bytes)])
