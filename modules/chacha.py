import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from modules.utils import derive_key_from_password, generate_salt, save_encrypted_file, load_encrypted_file

NONCE_SIZE = 16  # ✅ Corrected nonce size
KEY_SIZE = 32    # 256-bit key

def encrypt_file_chacha(file_path, password):
    """
    Encrypts a file using ChaCha20 with a PBKDF2-derived key.
    """
    salt = generate_salt()
    key = derive_key_from_password(password, salt)
    nonce = os.urandom(NONCE_SIZE)  # ✅ Generate a 16-byte nonce

    with open(file_path, "rb") as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)

    encrypted_data = nonce + ciphertext  # Store nonce at the start
    encrypted_file = save_encrypted_file(file_path, encrypted_data, "ChaCha20", salt)

    return encrypted_file

def decrypt_file_chacha(encrypted_file_path, password):
    """
    Decrypts a ChaCha20-encrypted file.
    """
    algorithm, salt, encrypted_data = load_encrypted_file(encrypted_file_path)
    if algorithm != "ChaCha20":
        raise ValueError("Incorrect decryption algorithm selected!")

    key = derive_key_from_password(password, salt)

    nonce = encrypted_data[:NONCE_SIZE]  # ✅ Extract 16-byte nonce
    ciphertext = encrypted_data[NONCE_SIZE:]

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)

    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(decrypted_file_path, "wb") as f:
        f.write(plaintext)

    return decrypted_file_path
