from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_receiver_keypair():
    print("🔐 Generating RSA key pair (4096 bits)...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    public_key = private_key.public_key()
    
    with open("receiver_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("receiver_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("="*50)
    print("✅ RECEIVER KEYS CREATED!")
    print("="*50)
    print("📁 receiver_private.pem - KEEP SECRET")
    print("📤 receiver_public.pem - SEND TO SENDER")
    print("="*50)

if __name__ == "__main__":
    generate_receiver_keypair()