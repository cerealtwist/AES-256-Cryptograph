import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

KEY_SIZE = 32
BLOCK_SIZE = 128
SALT_SIZE = 16
IV_SIZE = 16

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return salt + iv + ciphertext

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE : SALT_SIZE + IV_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + IV_SIZE:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    original_data = unpadder.update(padded_data) + unpadder.finalize()

    return original_data
