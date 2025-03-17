***File Encryption and Decryption Tool using Python***

*COMPANY* : CODTECH IT SOLUTIONS

*NAME* : ANIRUDH ANILKUMAR

*INTERN ID* :  CT08VAI

*DOMAIN* : CYBER SECURITY AND ETHICAL HACKING

*DURATION* : 4 WEEKS

*MENTOR* : NEELA SANTHOSH

***DESCRIPTION***:

The **File Encryption Tool** is a **secure, user-friendly** application designed to encrypt and decrypt files using **advanced cryptographic algorithms**. This tool provides **AES-256 (CBC Mode)**, **ChaCha20**, and **RSA encryption**, ensuring strong data protection for sensitive files.  

The **Tkinter-based GUI** allows users to **easily select files, choose encryption algorithms, and securely manage passwords and keys.** The tool also includes **metadata handling**, which allows **automatic detection of encryption methods** during decryption, ensuring a seamless user experience.  

***All Components***:

1. *AES-256 Encryption*:

AES-256 (Advanced Encryption Standard) is a **widely used encryption algorithm** providing **high security** and **performance**. It is used for encrypting files with a **password-derived key**.

**Implementation**:- 
- Uses **CBC (Cipher Block Chaining) mode** for added security.

- **Password-based key derivation (PBKDF2)** ensures a strong encryption key.

- Includes **metadata storage** (algorithm type, salt, IV) in the encrypted file.


2. *ChaCha20 Encryption*:

ChaCha20 is a **stream cipher** known for its **speed and security**. It is an alternative to AES, offering excellent performance **without requiring specialized hardware**.

**Implementation**:-
- Uses a **random nonce (12 bytes) + password-derived key** for encryption.

- Includes **metadata handling** for auto-detecting the encryption scheme.

- Provides **efficient decryption** with fast processing times.


3. *RSA Encryption*:

RSA (Rivest-Shamir-Adleman) is an **asymmetric encryption algorithm** that uses **public and private keys** to securely encrypt and decrypt files.

**Implementation**:-
- **Key Generation:** Users can generate **2048-bit or 4096-bit RSA keys**.

- **File Encryption:** Encrypts files using the **public key**.

- **File Decryption:** Requires the **private key** for decryption.

- **Metadata Handling:** Encrypted files store **key fingerprints** to verify integrity.


4. *Metadata Handling*:

The tool **automatically embeds metadata** in encrypted files to enable **automatic decryption**.  
If metadata is missing, users can manually **select the correct algorithm** for decryption.

**Implementation**:-

- Stores **encryption algorithm, salt, IV (AES), nonce (ChaCha20)** in a file header.

- **Extracts metadata** before decryption to auto-select the algorithm.

- Provides a **manual decryption option** if metadata is unavailable.


5. *GUI Features(Tkinter)*:

The **GUI-based interface** provides a simple and interactive way to encrypt and decrypt files.

**Implementation**:-

- **Main Menu:** Allows users to select **Encryption or Decryption**.

- **Encryption Page:** Users select a file, **choose an algorithm**, and enter a password.

- **Decryption Page:** Attempts **automatic detection** or allows **manual algorithm selection**.

- **RSA Key Generation:** Generates and **displays file paths** for private and public keys.



***Steps for Testing***:

-Ensure that your system has Python above version 3.6 installed.
-Create a virtual environment if necessary and install the dependencies with:
        
        pip install -r requirements.txt

-Run the tool with the command:
 python main.py

-Test the GUI features by selecting **Encryption** and **Decryption** options.

-For *AES-256 ENCRYPTION*:

Select ENCRYPTION --> AES-256 --> Enter password --> Select a file --> Click Encrypt --> Verify that encrypted file has been created.

-For *ChaCha20 Encryption*:

Select ENCRYPTION --> ChaCha20 --> Enter password --> Select a file --> Click Encrypt --> Verify that encrypted file has been created.

-for *RSA Key Generation*:

-Click on *Generate RSA Keys*
-Verify that private and public key files have been created.

-For *RSA Encryption*:

Select ENCRYPTION --> RSA --> Select a file --> Select Public Key --> Click Done --> Verify that encrypted file has been created.

For *Decryption*:
Select DECRYPTION --> Select a file --> Enter Password(Not for RSA) --> Click Decrypt --> Select private key(If RSA) --> Verify that decrypted file has been created.

If Encryption type not found in metadata, then user can select the encryption type manually.

***Dependencies Required***:

cryptography

tk


***FINAL THOUGHTS***:

The File Encryption Tool provides a secure and efficient way to encrypt and decrypt files using AES-256, ChaCha20, and RSA.
With automatic algorithm detection, metadata-based handling, and a user-friendly GUI, this tool ensures strong security while maintaining ease of use.

