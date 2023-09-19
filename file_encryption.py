from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_file(file_path, key, salt):
    print(f"Inside encrypt_file function for {file_path}")
    print(f"Key length in bits: {len(key) * 8}")
    # Initialize AES-GCM
    iv = os.urandom(12)  # 96 bits
    encryptor = ciphers.Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Mix in the salt and read and encrypt file
    ciphertext = b""
    with open(file_path, "rb") as f:
        while chunk := f.read(64 * 1024):
            chunk += salt  # Add salt to each chunk to make encryption unique
            ciphertext += encryptor.update(chunk)
    ciphertext += encryptor.finalize()
    
    # Write encrypted content to a new file
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(ciphertext)

    # Retrieve tag
    tag = encryptor.tag
    print("Encryption completed.")
    return iv, tag

def decrypt_file(file_path, key, iv, tag, salt):
    print(f"Inside decrypt_file function for {file_path}")
    # Initialize AES-GCM
    decryptor = ciphers.Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    

    # Decrypt and write file
    with open(file_path, "wb") as f:
        with open(file_path + ".enc", "rb") as enc_file:
            while chunk := enc_file.read(64 * 1024):
                decrypted_chunk = decryptor.update(chunk)
                f.write(decrypted_chunk[:-len(salt)])  # Remove salt
    decryptor.finalize()
    print("Decryption completed.")

def generate_unique_salt():
    return os.urandom(16)  # Generate a random 128-bit salt
