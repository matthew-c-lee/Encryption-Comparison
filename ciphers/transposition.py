import math


def encrypt(message, key):
    ciphertext = [''] * key

    for col in range(key):
        pointer = col

        while pointer < len(message):
            ciphertext[col] += message[pointer]

            pointer += key

    return ''.join(ciphertext)


def decrypt(message, key):
    numOfColumns = math.ceil(len(message) / key)
    numOfRows = key
    numOfShadedBoxes = (numOfColumns * numOfRows) - len(message)

    plaintext = [''] * numOfColumns

    col = 0
    row = 0

    for symbol in message:
        plaintext[col] += symbol
        col += 1

        if (col == numOfColumns) or (col == numOfColumns - 1 and row >= numOfRows - numOfShadedBoxes):
            col = 0
            row += 1

    return ''.join(plaintext)


def main():
    message = 'This is a test.'
    KEY = 8

    ciphertext = encrypt(message, KEY)
    print(ciphertext)

    plaintext = decrypt(ciphertext, KEY)
    print(plaintext)


if __name__ == '__main__':
    main()
