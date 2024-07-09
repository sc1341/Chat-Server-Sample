#!/usr/bin/env python3

import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptographyHandler:

    def __init__(self):
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'\xab\x83\xfb\xb5\xe8\xd5\xf5\xd5\xd0\xbc\xe4\xbd\t2\xb3n',
            iterations=480000
        )

    def break_fernet(self, ciphertext : str, wordlist : str):
        with open(wordlist, 'r', encoding='latin-1', errors='replace') as file:
            for line in file:
                line = line.strip()
                print(line)
                try:
                    key = base64.urlsafe_b64encode(self.kdf.derive(line.encode())) # This is where the key is derived from the wordlist word
                    if self.try_decrypt(key, ciphertext):
                        print(f"Found the key! {line}")
                        print(self.decrypt(key, ciphertext))
                        break
                except Exception as e:
                    continue

    def try_decrypt(self, key: bytes, message: str):
        try:
            Fernet(key).decrypt(message.encode())
            return True
        except InvalidToken:
            return False

    def encrypt(self, key: bytes, message: str):
        return Fernet(key).encrypt(message.encode())

    def decrypt(self, key: bytes, message: str):
        return Fernet(key).decrypt(message.encode()).decode()

def main():
    c = CryptographyHandler()
    ciphertext_1 = 'gAAAAABmiDdMzuHbsweg-BbjvimbnotFEixMe5PMwdFHuMEoYjpHzKhHzpdeZPmj5SlMjs8WF7iCtRhAkVM7oumKeW8otGwh3g=='
    c.break_fernet(ciphertext_1, 'mini.txt')

if __name__ == "__main__":
    main()
