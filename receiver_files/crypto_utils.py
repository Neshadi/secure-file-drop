import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
import base64

# ============================================
# SYMMETRIC ENCRYPTION (AES-256-GCM)
# ============================================

def generate_file_key():
    """Generate a random 256-bit key for file encryption"""
    return secrets.token_bytes(32)

def encrypt_file(file_data, key):
    """Encrypt file using AES-256-GCM"""
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag
    return nonce + tag + encrypted_data

def decrypt_file(encrypted_package, key):
    """Decrypt file using AES-256-GCM"""
    nonce = encrypted_package[:12]
    tag = encrypted_package[12:28]
    encrypted_data = encrypted_package[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def generate_link_token():
    """Generate a secure random token for file access"""
    return secrets.token_urlsafe(32)

def hash_token_for_storage(token):
    """Hash token before storing (defense against DB leak)"""
    return hashlib.sha256(token.encode()).hexdigest()

def compute_file_hash(file_data):
    """Compute SHA-256 hash for integrity checking"""
    return hashlib.sha256(file_data).hexdigest()

def verify_file_hash(file_data, expected_hash):
    """Verify file integrity"""
    return compute_file_hash(file_data) == expected_hash

# ============================================
# ASYMMETRIC ENCRYPTION (RSA) - For Secure Link Sharing
# ============================================

def encrypt_link_with_receiver_public_key(link_data, public_key_pem):
    """
    Encrypt the download token using Receiver's public key
    Only Receiver can decrypt with their private key
    """
    # Load receiver's public key
    public_key = serialization.load_pem_public_key(public_key_pem)
    
    # Encrypt the data
    encrypted_data = public_key.encrypt(
        link_data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Return base64 encoded encrypted data
    return base64.b64encode(encrypted_data).decode()

def decrypt_link_with_receiver_private_key(encrypted_link_data, private_key_pem):
    """
    Decrypt the download token using Receiver's private key
    Only Receiver can do this
    """
    # Load receiver's private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    
    # Decrypt the data
    decrypted_data = private_key.decrypt(
        base64.b64decode(encrypted_link_data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted_data.decode()