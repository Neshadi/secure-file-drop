import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_file_key():
    return secrets.token_bytes(32)

def encrypt_file(file_data, key):
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag
    return nonce + tag + encrypted_data

def decrypt_file(encrypted_package, key):
    nonce = encrypted_package[:12]
    tag = encrypted_package[12:28]
    encrypted_data = encrypted_package[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def generate_link_token():
    return secrets.token_urlsafe(32)

def hash_token_for_storage(token):
    return hashlib.sha256(token.encode()).hexdigest()

def compute_file_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()

def verify_file_hash(file_data, expected_hash):
    return compute_file_hash(file_data) == expected_hash
