from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
import os

def generate_rsa_keys():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    private_key_path = os.path.join(current_dir, "private_key.pem")
    public_key_path = os.path.join(current_dir, "public_key.pem")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, "wb") as f:
        f.write(pem_private)

    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, "wb") as f:
        f.write(pem_public)

def load_key(full_path):
    with open(full_path, "rb") as f:
        return f.read()

def encrypt_aes_key(aes_key, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

def decrypt_aes_key(encrypted_aes_key, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_aes_key
