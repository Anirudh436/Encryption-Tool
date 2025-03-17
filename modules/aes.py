import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from modules.utils import derive_key_from_password, generate_salt, save_encrypted_file, load_encrypted_file

IV_SIZE = 16  # AES block size (128 bits)
KEY_SIZE = 32  # 256-bit key for AES-256

def encrypt_file_aes(file_path, password):
    """
    Encrypts a file using AES-256 (CBC mode) with PBKDF2-derived key.
    """
    # Generate a random salt & key from the password
    salt = generate_salt()
    key = derive_key_from_password(password, salt)
    
    # Generate a random IV
    iv = os.urandom(IV_SIZE)

    # Read the file contents
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Ensure padding (AES requires blocks of 16 bytes)
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)

    # Encrypt using AES-256 in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Save the encrypted file with metadata
    encrypted_data = iv + ciphertext  # Store IV at the start
    encrypted_file = save_encrypted_file(file_path, encrypted_data, "AES", salt)

    return encrypted_file

def decrypt_file_aes(encrypted_file_path, password):
    """
    Decrypts an AES-256 encrypted file using the stored metadata.
    """
    # Load metadata & encrypted content
    algorithm, salt, encrypted_data = load_encrypted_file(encrypted_file_path)
    if algorithm != "AES":
        raise ValueError("Incorrect decryption algorithm selected!")

    # Derive the same key from the password
    key = derive_key_from_password(password, salt)

    # Extract IV (first 16 bytes)
    iv = encrypted_data[:IV_SIZE]
    ciphertext = encrypted_data[IV_SIZE:]

    # Decrypt using AES-256 in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]

    # Save the decrypted file
    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(decrypted_file_path, "wb") as f:
        f.write(plaintext)

    return decrypted_file_path
