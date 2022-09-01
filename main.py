import ciphers.caeser as caeser
import ciphers.columnar as columnar


def main():
    # CAESER CIPHER
    text = "ATTACK AT ONCE"
    s = 3
    print(f'Original\n{text}\n')
    print(f'Shift\n{s}\n')

    encrypted = caeser.encrypt(text, s)
    print(f'Encrypted\n{encrypted}\n')

    decrypted = caeser.encrypt(encrypted, -s)
    print(f'Decrypted\n{decrypted}\n')

    print('Columnar Transposition:')
    encrypted = columnar.encrypt("message", 'keyword')
    print(encrypted)

    decrypted = columnar.decrypt(encrypted, 'keyword')
    print(decrypted)
    


if __name__ == '__main__':
    main()
