from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

KEY_SIZE = 2048  # RSA Key Size (2048-bit recommended)

def generate_rsa_keys():
    """Generate an RSA public-private key pair and save them to files."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE
    )
    public_key = private_key.public_key()

    # Save the private key
    with open("rsa_private.pem", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the public key
    with open("rsa_public.pem", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return "rsa_private.pem", "rsa_public.pem"

def encrypt_file_rsa(file_path, public_key_path):
    """Encrypt a file using RSA public key."""
    # Load the public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Read plaintext data
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Encrypt the file (RSA can only encrypt small chunks, so we use padding)
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_file = file_path + ".rsa.enc"
    with open(encrypted_file, "wb") as f:
        f.write(ciphertext)

    return encrypted_file

def decrypt_file_rsa(encrypted_file_path, private_key_path):
    """Decrypt an RSA-encrypted file using the private key."""
    # Load the private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Read the encrypted data
    with open(encrypted_file_path, "rb") as f:
        ciphertext = f.read()

    # Decrypt using RSA private key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypted_file_path = encrypted_file_path.replace(".rsa.enc", ".rsa.dec")
    with open(decrypted_file_path, "wb") as f:
        f.write(plaintext)

    return decrypted_file_path
