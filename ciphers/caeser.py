def encrypt(message, num):
    # initialize encrypted text
    encrypted_message = ''

    for letter in message:
        # get unicode
        unicode = ord(letter)

        # shift the unicode by a certain amount
        new_unicode = unicode - num

        # convert from unicode to char
        new_letter = chr(new_unicode)

        # add new letter to cipher text
        encrypted_message += new_letter

    return encrypted_message
    
def decrypt(message, num):
    return encrypt(message, -num)

if __name__ == '__main__':
    message = "This is a test."
    KEY = 15

    encrypted_message = encrypt(message, KEY)
    print(encrypted_message)

    decrypted_message = decrypt(encrypted_message, KEY)
    print(decrypted_message)