import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import decrypt_link_with_receiver_private_key

def download_secure_file():
    print("="*50)
    print("🔐 SECURE FILE DOWNLOADER")
    print("="*50)
    
    server_url = input("Server URL (default: http://localhost:5000): ").strip()
    if not server_url:
        server_url = "http://localhost:5000"
    
    print("\n📋 Paste the encrypted token:")
    encrypted_token = input("> ").strip()
    
    # Remove spaces and newlines
    encrypted_token = ''.join(encrypted_token.split())
    
    if not encrypted_token:
        print("❌ No token provided!")
        return
    
    private_key_path = "receiver_private.pem"
    if not os.path.exists(private_key_path):
        print(f"❌ Private key not found! Run receiver_keygen.py first")
        return
    
    try:
        with open(private_key_path, "rb") as f:
            private_key_pem = f.read()
        
        print("\n🔓 Decrypting token...")
        decrypted_token = decrypt_link_with_receiver_private_key(encrypted_token, private_key_pem)
        print("✅ Token decrypted!")
        
        print("\n📥 Downloading file...")
        response = requests.get(f"{server_url}/do_download/{decrypted_token}")
        
        if response.status_code == 200:
            filename = "downloaded_file"
            if 'Content-Disposition' in response.headers:
                content = response.headers['Content-Disposition']
                if 'filename=' in content:
                    filename = content.split('filename=')[1].strip('"')
            
            with open(filename, "wb") as f:
                f.write(response.content)
            
            print("\n" + "="*50)
            print("✅ FILE DOWNLOADED!")
            print("="*50)
            print(f"📁 Saved as: {filename}")
            print(f"📏 Size: {len(response.content)} bytes")
            print("="*50)
        else:
            print(f"❌ Download failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    download_secure_file()