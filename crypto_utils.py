import hashlib
import secrets
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


# =========================
# AES ENCRYPTION
# =========================

def generate_file_key():
    return secrets.token_bytes(32)


def encrypt_file(file_data, key):
    nonce = secrets.token_bytes(12)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    encrypted = encryptor.update(file_data) + encryptor.finalize()

    return nonce + encryptor.tag + encrypted


def decrypt_file(encrypted_package, key):
    nonce = encrypted_package[:12]
    tag = encrypted_package[12:28]
    encrypted_data = encrypted_package[28:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()

    return decryptor.update(encrypted_data) + decryptor.finalize()


# =========================
# TOKEN FUNCTIONS
# =========================

def generate_link_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    """USED EVERYWHERE (ONLY ONE VERSION)"""
    return hashlib.sha256(token.encode()).hexdigest()


def compute_file_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()


def verify_file_hash(file_data, expected_hash):
    return compute_file_hash(file_data) == expected_hash


# =========================
# RSA ENCRYPTION
# =========================

def encrypt_link_with_receiver_public_key(link_data, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem)

    encrypted = public_key.encrypt(
        link_data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.urlsafe_b64encode(encrypted).decode().rstrip("=")


def decrypt_link_with_receiver_private_key(encrypted_token, private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )

    encrypted_token = ''.join(encrypted_token.split())
    encrypted_token += '=' * (-len(encrypted_token) % 4)

    ciphertext = base64.urlsafe_b64decode(encrypted_token)

    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted.decode()