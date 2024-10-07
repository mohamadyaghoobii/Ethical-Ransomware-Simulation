Ethical Ransomware Simulation
This project demonstrates advanced file encryption using Fernet (symmetric encryption) and RSA (asymmetric encryption), featuring secure key management, parallel processing, and file integrity checks via SHA-256 hashing.

Features
Fernet Encryption: Fast, symmetric encryption for files.
RSA Encryption: Asymmetric encryption for secure key storage.
Parallel Processing: Concurrent encryption/decryption for better performance.
File Integrity: SHA-256 hashing to verify files are untampered.
Logging: Detailed logs of encryption, decryption, and integrity checks.
Prerequisites
Python 3.x
Pip (Python package installer)
Installation
For Bash (Linux/macOS)
git clone https://github.com/mohamadyaghoobii/Ethical-Ransomware-Simulation.git
cd python-advanced-encryption
pip install -r requirements.txt


For PowerShell (Windows)
git clone https://github.com/mohamadyaghoobii/Ethical-Ransomware-Simulation.git
cd python-advanced-encryption
pip install -r requirements.txt


Usage
Create a data_files directory in the project root and add files to encrypt.

Run the Python script:

Bash (Linux/macOS): python3 main.py
PowerShell (Windows): python main.py
The script will encrypt and decrypt files in data_files/. Logs will detail the process.

Key Process Overview
RSA Key Generation: Creates an RSA key pair saved as private_key.pem and public_key.pem.
Fernet Key Encryption: Generates a Fernet key, encrypts it with RSA, and stores it as encrypted_fernet_key.bin.
Parallel File Encryption/Decryption: Files in data_files are encrypted/decrypted in parallel.
File Integrity Check: SHA-256 hashes ensure files remain unchanged.
Security Considerations
Key Management: Keep the RSA private key secure to protect the Fernet key.
File Integrity: SHA-256 ensures files are not altered during encryption.
