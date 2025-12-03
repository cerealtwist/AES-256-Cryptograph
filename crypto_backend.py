import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# CONFIGURATION
MAGIC_HEADER = b"DATASEC02" 
VERSION = 1    
KEY_SIZE = 32
HMAC_KEY_SIZE = 32
SALT_SIZE = 16
IV_SIZE = 16
PBKDF2_ITERATIONS = 200000
BLOCK_SIZE = 128

# KEY DERIVATION (SPLIT KEY)
def derive_keys(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE + HMAC_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    full_key = kdf.derive(password.encode())
    
    # Slicing key
    enc_key = full_key[:KEY_SIZE] # first 32 bytes
    mac_key = full_key[KEY_SIZE:] # rest 32 bytes

    return enc_key, mac_key

# MAIN FUNCTIONS
def encrypt_data(data: bytes, password: str) -> bytes:
    # Generate Random Salt & IV
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)

    # Derive Split Keys
    enc_key, mac_key = derive_keys(password, salt)

    #Padding PKCS7
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()

    #AES-CBC Encryption
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Message (HEADER + META + CIPHER)
    message = MAGIC_HEADER + struct.pack("B", VERSION) + salt + iv + ciphertext

    # Calculate HMAC (Integrity Check)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(message)
    hmac_tag = h.finalize()

    # Merge Message + HMAC Tag
    return message + hmac_tag

def decrypt_data(data: bytes, password: str) -> bytes:
    try:
        # HEADER VALIDATION
        if not data.startswith(MAGIC_HEADER):
            raise ValueError("Format file unrecognized (Magic Header Mismatch!).")

        cursor = len(MAGIC_HEADER)

        # VERSION VALIDATION
        version_byte = data[cursor]
        if version_byte != VERSION:
            raise ValueError(f"File version unsupported: {version_byte}")
        cursor += 1

        # Extract Component
        salt = data[cursor : cursor + SALT_SIZE]
        cursor += SALT_SIZE

        iv = data[cursor : cursor + IV_SIZE]
        cursor += IV_SIZE

        # fetch HMAC (last 32 byte)
        hmac_tag = data[-32:]

        # fetch ciphertext (before HMAC)
        ciphertext = data[cursor:-32]

        # Derive key
        enc_key, mac_key = derive_keys(password, salt)

        # HMAC Verification
        verify_content = data[:-32]
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(verify_content)

        # raise InvalidSignature if different from tag
        h.verify(hmac_tag)

        # AES Decryptor
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpadding
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        return plaintext

    except Exception as e:
        raise ValueError(f"Decryption failed!: {str(e)}")
    
# Unit testing (manual input)
if __name__ == "__main__":
    # Call dummy function from crypto_dummy.py
    try:
        from crypto_dummy import create_dummy_csv
    except ImportError:
        print("Error: File 'crypto_dummy.py' not found.")
        exit()
        
    # FOLDER NAME CONFIGURATION
    TARGET_FOLDER = "crypt_output"
    filepath = create_dummy_csv("student_data.csv", folder=TARGET_FOLDER)

    password_input = "kelompokkeamanannyadata##"

    print(f"\n{'='*40}")
    print("   TESTING FILE ENCRYPTION(AES-256 + HMAC)")
    print(f"{'='*40}")

    try:
        # read file
        print(f"1. read original file: {filepath}")
        with open(filepath, "rb") as f:
            original_bytes = f.read()
        print(f"   -> size: {len(original_bytes)} bytes")

        # encrypt
        print(f"2. encrypt with password: '{password_input}'")
        encrypted_bytes = encrypt_data(original_bytes, password_input)
        
        # save to .enc (encoded file)
        enc_filepath = filepath + ".enc"
        with open(enc_filepath, "wb") as f:
            f.write(encrypted_bytes)
        print(f"    -> (encrypted) file saved: {enc_filepath}")
        print(f"    -> (Magic Header Check): {encrypted_bytes[:10]}")

        # decryption process
        print(f"3. decrypting file...")
        # read .enc from disk
        with open(enc_filepath, "rb") as f:
            read_encrypted_bytes = f.read()
            
        decrypted_bytes = decrypt_data(read_encrypted_bytes, password_input)
        
        # save .decrypted
        # separate folder path and file name
        folder_path, file_name = os.path.split(filepath)
        dec_filename = "recovered_" + file_name
        dec_filepath = os.path.join(folder_path, dec_filename)

        with open(dec_filepath, "wb") as f:
            f.write(decrypted_bytes)
        print(f"    -> file recovery saved: {dec_filename}")

        # validate integrity
        print(f"Compare original data vs decrypted")
        if original_bytes == decrypted_bytes:
            print("\n[SUCCESS]")
            print("file recovered in folder '{TARGET_FOLDER}'!")
            print("-" * 20)
            print(decrypted_bytes.decode()[:100]) # decode bytes to string
            print("-" * 20)
        else:
            print("\n[FAIL].")

    except ValueError as ve:
        print(f"\n[ERROR] Failed: {ve}")
    except Exception as e:
        print(f"\n[ERROR] System fail: {e}")
