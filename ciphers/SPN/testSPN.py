import SPNencrypt


def main():

    plain = [
        "0010011010110111",
        "1111111111111111",
        "0000000000000000",
        "1111111111111110",
        "1110111111011110",
        "1110101011011110",
        "1110101000011110",
        "0101010101010101",
        "0101010101010101",
        "0101000000000101",
        "0101000010100101",
        "1110111111110101",
        "0000000100001000",
        "0001000100001001",
        "0110111001110111",
        "1111011111011101"
    ]

    for plainText in plain:
        cipherText = SPNencrypt.spn(plainText)
        print(f'Plaintext: \t{plainText[0:4]} {plainText[4:8]} {plainText[8:12]} {plainText[12:16]}')
        print(f'Ciphertext: \t{cipherText[0:4]} {cipherText[4:8]} {cipherText[8:12]} {cipherText[12:16]}')

        newPlainText = SPNencrypt.spn(cipherText)
        print(f'Back: \t\t{newPlainText[0:4]} {newPlainText[4:8]} {newPlainText[8:12]} {newPlainText[12:16]}')
        

        print('-----------------------------------')

main()
