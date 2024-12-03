import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

@dataclass
class Encrypted:
    data: bytes
    sha256: bytes
    iv: bytes

def __complete_key(key: bytes) -> bytes:
    if len(key) < 32:
        return (key * (32 // len(key) + 1))[:32]
    return key[:32]

def encrypt(key_str: str, data: bytes) -> Encrypted:
    iv = os.urandom(16)
    key = __complete_key(key_str.encode('utf-8'))

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    sha256 = hashlib.sha256(data).digest()

    return Encrypted(
        data=encrypted_data,
        sha256=sha256,
        iv=iv
    )

def decrypt(key_str: str, encrypted: Encrypted) -> bytes:
    key = __complete_key(key_str.encode('utf-8'))

    cipher = Cipher(algorithms.AES(key), modes.CBC(encrypted.iv))
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted.data) + decryptor.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    sha256 = hashlib.sha256(data).digest()
    if sha256 != encrypted.sha256:
        raise Exception("Hashes don't match! Files may have been replaced by bad actors!")

    return data


if __name__ == "__main__":
    # Тестовые данные
    _key = "my_secure_password"
    original_data = b"This is a secret message!"

    print("Original data:", original_data)

    # Шифрование
    _encrypted = encrypt(_key, original_data)
    print("\nEncryption:")
    print("Encrypted data:", _encrypted.data)
    print("SHA256 checksum:", _encrypted.sha256)
    print("Initialization vector (IV):", _encrypted.iv)

    # Дешифрование
    try:
        decrypted_data = decrypt(_key, _encrypted)
        print("\nDecryption:")
        print("Decrypted data:", decrypted_data)
    except Exception as e:
        print("\nDecryption failed:", e)
        exit(1)

    # Проверка корректности
    if original_data == decrypted_data:
        print("\nTest passed: The decrypted data matches the original.")
    else:
        print("\nTest failed: The decrypted data does not match the original.")

