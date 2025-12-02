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
    
# Unit testing (manual input)
if __name__ == "__main__":
    import os

    filename = "xxxx.csv"
    
    #create dummy if not exist
    if not os.path.exists(filename):
        print(f"[SETUP] Create dummy file '{filename}'...")
        with open(filename, "w") as f:
            f.write("ID,Name,GPA,Subject\n")
            f.write("101,Gres,3.5,Data Science\n")
            f.write("102,Faiz,3.8,Informatika\n")
            f.write("103,Haikal,3.2,Sistem Informasi")
    
    password_input = "kelompokkeamanannyadata##"

    print(f"\n{'='*40}")
    print("   TESTING ENKRIPSI FILE (AES-256)")
    print(f"{'='*40}")

