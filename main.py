import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor
import base64
import logging


# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Generate RSA public/private key pair for asymmetric encryption (key management)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    logging.info("[*] RSA public/private keys generated.")


# Load RSA keys
def load_rsa_keys():
    with open("private_key.pem", "rb") as priv_file:
        private_key = serialization.load_pem_private_key(priv_file.read(), password=None, backend=default_backend())
    
    with open("public_key.pem", "rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())
    
    return private_key, public_key


# Encrypt the Fernet key using RSA public key
def encrypt_key_rsa(key, public_key):
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


# Decrypt the Fernet key using RSA private key
def decrypt_key_rsa(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key


# Generate a Fernet encryption key (symmetric encryption)
def generate_fernet_key():
    key = Fernet.generate_key()
    with open("fernet_key.key", "wb") as key_file:
        key_file.write(key)
    return key


# Load the Fernet encryption key
def load_fernet_key():
    return open("fernet_key.key", "rb").read()


# Hash a file using SHA-256 (for integrity check)
def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# Encrypt a file using Fernet encryption
def encrypt_file(file_path, fernet_key):
    fernet = Fernet(fernet_key)
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path, "wb") as file:
        file.write(encrypted_data)
    logging.info(f"[+] {file_path} has been encrypted.")


# Decrypt a file using Fernet encryption
def decrypt_file(file_path, fernet_key):
    fernet = Fernet(fernet_key)
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path, "wb") as file:
        file.write(decrypted_data)
    logging.info(f"[+] {file_path} has been decrypted.")


# Encrypt all files in a directory using threading for parallel processing
def encrypt_files_in_directory(directory, fernet_key):
    with ThreadPoolExecutor() as executor:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                executor.submit(encrypt_file, file_path, fernet_key)


# Decrypt all files in a directory using threading
def decrypt_files_in_directory(directory, fernet_key):
    with ThreadPoolExecutor() as executor:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                executor.submit(decrypt_file, file_path, fernet_key)


def main():
    target_directory = "data_files"  # Directory containing the files to encrypt

    # Step 1: Generate or load RSA key pair (for securing Fernet key)
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        generate_rsa_keys()
    
    private_key, public_key = load_rsa_keys()

    # Step 2: Generate or load Fernet encryption key
    if not os.path.exists("fernet_key.key"):
        fernet_key = generate_fernet_key()  # Generate new Fernet key
        encrypted_fernet_key = encrypt_key_rsa(fernet_key, public_key)  # Encrypt Fernet key with RSA public key
        with open("encrypted_fernet_key.bin", "wb") as f:
            f.write(encrypted_fernet_key)  # Store encrypted Fernet key
    else:
        encrypted_fernet_key = open("encrypted_fernet_key.bin", "rb").read()  # Load encrypted Fernet key
        fernet_key = decrypt_key_rsa(encrypted_fernet_key, private_key)  # Decrypt Fernet key with RSA private key

    # Step 3: Encrypt all files in the target directory
    logging.info("[*] Encrypting files in the directory...")
    encrypt_files_in_directory(target_directory, fernet_key)

    # For demonstration purposes, decrypting files after encryption
    logging.info("[*] Decrypting files in the directory...")
    decrypt_files_in_directory(target_directory, fernet_key)


if __name__ == "__main__":
    main()
