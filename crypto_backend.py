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
    #Generate Random Salt 
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)

    key = derive_key(password, salt)

    #Cipher AES 256
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    #Padding PKCS7
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt Padded Data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Merge Salt + IV + Ciphertext for Decryption
    return salt + iv + ciphertext

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    try:
        # Extract salt + iv 
        salt = encrypted_data[:SALT_SIZE]
        iv = encrypted_data[SALT_SIZE : SALT_SIZE + IV_SIZE]
        ciphertext = encrypted_data[SALT_SIZE + IV_SIZE:]

        # Derive key
        key = derive_key(password, salt)

        # Decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt Data
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpadding
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()

        return original_data

    except Exception as e:
        raise ValueError("Decryption failed!")
    
# Unit testing
if __name__ == "__main__":
    csv_content = "ID,Name,Score\n1,gres,90\n2,faiz,85"
    password_input = "rahasia123"

    print(f"[TEST] Original Data:\n{csv_content}")
    print("-" * 20)
    encrypted = encrypt_data(csv_content.encode(), password_input)
    print(f"[TEST] Encryped ({len(encrypted)} bytes): {encrypted.hex()[:30]}...")
    
    try:
        decrypted = decrypt_data(encrypted, password_input)
        print("-" * 20)
        print(f"[TEST] Decryption output:\n{decrypted.decode()}")
        
        if csv_content == decrypted.decode():
            print("\n[SUCCESS] Data integrity (terjaga)")
        else:
            print("\n[FAIL] Data changed")
    except ValueError as ve:
        print(f"[ERROR] {ve}")