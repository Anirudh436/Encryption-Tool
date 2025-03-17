from modules.utils import (
    generate_salt, derive_key_from_password, save_encrypted_file, 
    load_encrypted_file, extract_metadata
)
from modules.aes import encrypt_file_aes, decrypt_file_aes
from modules.chacha import encrypt_file_chacha, decrypt_file_chacha
from modules.rsa import generate_rsa_keys, encrypt_file_rsa, decrypt_file_rsa
import os

def test_utils():
    """Test utility functions like salt generation, key derivation, and metadata handling."""
    print("🔹 Testing utils.py functions...\n")

    salt = generate_salt()
    print(f"✅ Salt Generated: {salt.hex()}")

    password = "securepassword123"
    key = derive_key_from_password(password, salt)
    print(f"✅ Derived Key (PBKDF2): {key.hex()}")

    sample_data = b"Secret test data"
    algorithm = "AES"
    encrypted_file = save_encrypted_file("testfile", sample_data, algorithm, salt)
    print(f"✅ Encrypted file saved as: {encrypted_file}")

    detected_algo, detected_salt, encrypted_data = load_encrypted_file(encrypted_file)
    print(f"✅ Extracted Metadata - Algorithm: {detected_algo}, Salt: {detected_salt.hex()}")
    print(f"✅ Extracted Encrypted Data: {encrypted_data}")

    extracted_algo, extracted_salt = extract_metadata(encrypted_file)
    print(f"✅ Metadata Extraction - Algorithm: {extracted_algo}, Salt: {extracted_salt.hex()}")

    assert detected_algo == algorithm, "❌ Algorithm mismatch!"
    assert detected_salt == salt, "❌ Salt mismatch!"
    assert encrypted_data == sample_data, "❌ Encrypted data mismatch!"

    print("\n🎉 Utils module tests passed successfully!\n")

    os.remove(encrypted_file)

def test_aes_encryption():
    """Test AES-256 encryption and decryption."""
    print("🔹 Testing AES-256 Encryption & Decryption...\n")

    password = "strongpassword123"
    test_file = "testfile.txt"

    with open(test_file, "w") as f:
        f.write("This is a secret message.")

    encrypted_file = encrypt_file_aes(test_file, password)
    print(f"✅ Encrypted file saved as: {encrypted_file}")

    decrypted_file = decrypt_file_aes(encrypted_file, password)
    print(f"✅ Decrypted file saved as: {decrypted_file}")

    with open(decrypted_file, "r") as f:
        decrypted_text = f.read()
    
    assert decrypted_text == "This is a secret message.", "❌ Decryption failed! Data mismatch."

    print("\n🎉 AES-256 Encryption & Decryption Tests Passed Successfully!\n")

    os.remove(test_file)
    os.remove(encrypted_file)
    os.remove(decrypted_file)

def test_chacha_encryption():
    """Test ChaCha20 encryption and decryption."""
    print("🔹 Testing ChaCha20 Encryption & Decryption...\n")

    password = "securepassword123"
    test_file = "testfile_chacha.txt"

    with open(test_file, "w") as f:
        f.write("This is a secret message encrypted with ChaCha20.")

    encrypted_file = encrypt_file_chacha(test_file, password)
    print(f"✅ Encrypted file saved as: {encrypted_file}")

    decrypted_file = decrypt_file_chacha(encrypted_file, password)
    print(f"✅ Decrypted file saved as: {decrypted_file}")

    with open(decrypted_file, "r") as f:
        decrypted_text = f.read()
    
    assert decrypted_text == "This is a secret message encrypted with ChaCha20.", "❌ Decryption failed! Data mismatch."

    print("\n🎉 ChaCha20 Encryption & Decryption Tests Passed Successfully!\n")

    os.remove(test_file)
    os.remove(encrypted_file)
    os.remove(decrypted_file)

def test_rsa_encryption():
    """Test RSA encryption and decryption."""
    print("🔹 Testing RSA Encryption & Decryption...\n")

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()
    print(f"✅ RSA Keys Generated: {private_key}, {public_key}")

    password = "securepassword123"
    test_file = "testfile_rsa.txt"

    # Create a test file
    with open(test_file, "w") as f:
        f.write("This is a secret message encrypted with RSA.")

    # Encrypt the file using RSA
    encrypted_file = encrypt_file_rsa(test_file, public_key)
    print(f"✅ Encrypted file saved as: {encrypted_file}")

    # Decrypt the file using RSA
    decrypted_file = decrypt_file_rsa(encrypted_file, private_key)
    print(f"✅ Decrypted file saved as: {decrypted_file}")

    # Validate correctness
    with open(decrypted_file, "r") as f:
        decrypted_text = f.read()
    
    assert decrypted_text == "This is a secret message encrypted with RSA.", "❌ RSA Decryption failed! Data mismatch."

    print("\n🎉 RSA Encryption & Decryption Tests Passed Successfully!\n")

    # Cleanup test files
    os.remove(test_file)
    os.remove(encrypted_file)
    os.remove(decrypted_file)
    os.remove(private_key)
    os.remove(public_key)

if __name__ == "__main__":
    test_utils()
    test_aes_encryption()
    test_chacha_encryption()
    test_rsa_encryption()
