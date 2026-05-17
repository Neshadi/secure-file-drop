import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def generate_key_pair():
    """
    Generates an RSA key pair and returns (private_key_pem, public_key_pem, fingerprint)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = compute_public_key_fingerprint(public_pem)
    return private_pem, public_pem, fingerprint

def compute_public_key_fingerprint(public_key_pem: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_key_pem)
    fingerprint = base64.urlsafe_b64encode(digest.finalize()).decode()[:16]
    return fingerprint

if __name__ == "__main__":
    print("Generating Sender Key Pair...")
    sender_priv, sender_pub, sender_fp = generate_key_pair()
    with open("sender_private.pem", "wb") as f:
        f.write(sender_priv)
    with open("sender_public.pem", "wb") as f:
        f.write(sender_pub)
    print(f"Sender Fingerprint: {sender_fp}")

    print("Generating Receiver Key Pair...")
    receiver_priv, receiver_pub, receiver_fp = generate_key_pair()
    with open("receiver_private.pem", "wb") as f:
        f.write(receiver_priv)
    with open("receiver_public.pem", "wb") as f:
        f.write(receiver_pub)
    print(f"Receiver Fingerprint: {receiver_fp}")
