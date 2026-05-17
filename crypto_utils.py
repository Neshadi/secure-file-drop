# =========================
# SENDER FILE SIGNING & VERIFICATION
# =========================

def sign_file_with_private_key(file_data, sender_private_key_pem):
    """
    Returns base64-encoded RSA signature for the file data using sender's private key.
    """
    private_key = load_pem_private_key(sender_private_key_pem, password=None, backend=default_backend())
    signature = private_key.sign(
        file_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_file_signature(file_data, signature_b64, sender_public_key_pem):
    """
    Verifies the RSA signature for the file data using sender's public key.
    Returns True if valid, False otherwise.
    """
    public_key = load_pem_public_key(sender_public_key_pem, backend=default_backend())
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            file_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
import hashlib
import hmac
import os
import secrets
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, BestAvailableEncryption, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


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
# METADATA ENCRYPTION
# =========================

def _metadata_key_path():
    return os.path.join(os.path.dirname(__file__), 'metadata_master.key')


def _load_or_create_metadata_key():
    key_path = _metadata_key_path()

    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            return key_file.read()

    key = Fernet.generate_key()
    with open(key_path, 'wb') as key_file:
        key_file.write(key)
    return key


def encrypt_metadata_value(value):
    fernet = Fernet(_load_or_create_metadata_key())
    return fernet.encrypt(value.encode()).decode()


def decrypt_metadata_value(value):
    fernet = Fernet(_load_or_create_metadata_key())
    return fernet.decrypt(value.encode()).decode()


# =========================
# AUDIT SIGNING (RSA)
# =========================

_PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), 'audit_signing_private.pem')
_PUBLIC_KEY_PATH = os.path.join(os.path.dirname(__file__), 'audit_signing_public.pem')

def _load_or_create_rsa_keypair():
    if os.path.exists(_PRIVATE_KEY_PATH) and os.path.exists(_PUBLIC_KEY_PATH):
        with open(_PRIVATE_KEY_PATH, 'rb') as priv_file:
            private_key = load_pem_private_key(priv_file.read(), password=None, backend=default_backend())
        with open(_PUBLIC_KEY_PATH, 'rb') as pub_file:
            public_key = load_pem_public_key(pub_file.read(), backend=default_backend())
        return private_key, public_key
    # Generate new key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    # Save private key
    with open(_PRIVATE_KEY_PATH, 'wb') as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))
    # Save public key
    with open(_PUBLIC_KEY_PATH, 'wb') as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, public_key

def sign_audit_event(event_type, file_id, details, created_at=None):
    """
    Returns base64-encoded RSA signature for the audit event payload.
    """
    private_key, _ = _load_or_create_rsa_keypair()
    timestamp = created_at or ''
    payload = f'{event_type}|{file_id}|{details}|{timestamp}'.encode()
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_audit_event_signature(event_type, file_id, details, signature, created_at=None):
    """
    Verifies the RSA signature for the audit event payload.
    Returns True if valid, False otherwise.
    """
    _, public_key = _load_or_create_rsa_keypair()
    timestamp = created_at or ''
    payload = f'{event_type}|{file_id}|{details}|{timestamp}'.encode()
    try:
        public_key.verify(
            base64.b64decode(signature),
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

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


def compute_public_key_fingerprint(public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem)
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_key_der).hexdigest()