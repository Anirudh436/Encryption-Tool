import os
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

MAGIC_HEADER = b'ENCX'  # Unique identifier for encrypted files
SALT_SIZE = 16          # Salt size in bytes
KEY_SIZE = 32           # 256-bit key for AES-256 and ChaCha20
PBKDF2_ITERATIONS = 100_000  # High iteration count for better security

def derive_key_from_password(password, salt):
    """
    Derive a secure 256-bit encryption key from a password using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def add_metadata(encrypted_data, algorithm, salt):
    """
    Embed metadata (algorithm name & salt) at the start of the encrypted file.
    """
    return MAGIC_HEADER + algorithm.encode() + b'\n' + base64.b64encode(salt) + b'\n' + encrypted_data

def extract_metadata(encrypted_file_path):
    """
    Read metadata from an encrypted file to detect the encryption algorithm and retrieve the salt.
    """
    try:
        with open(encrypted_file_path, "rb") as f:
            header = f.read(4)
            if header != MAGIC_HEADER:
                return None, None  # No metadata found

            algo_name = b""
            while True:
                byte = f.read(1)
                if byte == b'\n' or not byte:
                    break
                algo_name += byte

            salt_base64 = b""
            while True:
                byte = f.read(1)
                if byte == b'\n' or not byte:
                    break
                salt_base64 += byte
            
            salt = base64.b64decode(salt_base64)
            return algo_name.decode(), salt
    except Exception as e:
        return None, None 

def save_encrypted_file(file_path, encrypted_data, algorithm, salt):
    """
    Save encrypted data to a file with metadata (algorithm + salt).
    """
    encrypted_data_with_metadata = add_metadata(encrypted_data, algorithm, salt)
    encrypted_file_path = file_path + ".enc"

    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data_with_metadata)

    return encrypted_file_path

def load_encrypted_file(file_path):
    """
    Load encrypted data and return its contents (excluding metadata).
    """
    with open(file_path, "rb") as f:
        header = f.read(4)
        if header != MAGIC_HEADER:
            return None, None, None  # No metadata found

        algo_name = b""
        while True:
            byte = f.read(1)
            if byte == b'\n' or not byte:
                break
            algo_name += byte

        salt_base64 = b""
        while True:
            byte = f.read(1)
            if byte == b'\n' or not byte:
                break
            salt_base64 += byte

        salt = base64.b64decode(salt_base64)
        encrypted_data = f.read()  # The actual encrypted content
        return algo_name.decode(), salt, encrypted_data

def generate_salt():
    """Generate a random salt for key derivation."""
    return os.urandom(SALT_SIZE)
