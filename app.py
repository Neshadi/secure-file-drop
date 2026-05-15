from flask import Flask, render_template, request, send_file, redirect
import os
import io
import base64
import secrets
import socket
from werkzeug.utils import secure_filename
from crypto_utils import *
from database import FileDatabase

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'

db = FileDatabase()
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ============================================
# HELPER FUNCTION: Get Local IP Address
# ============================================
def get_local_ip():
    """Get the local IP address of your computer"""
    try:
        # Create a socket to get the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ============================================
# HOME PAGE
# ============================================
@app.route('/')
def index():
    return render_template('upload.html')

# ============================================
# UPLOAD FILE
# ============================================
@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if file was uploaded
    if 'file' not in request.files:
        return "No file uploaded", 400
    file = request.files['file']
    if file.filename == '':
        return "No file selected", 400
    
    # Check if public key was uploaded
    if 'receiver_public_key' not in request.files:
        return "Receiver's public key is required", 400
    
    receiver_public_key_file = request.files['receiver_public_key']
    if receiver_public_key_file.filename == '':
        return "Please upload receiver's public key file", 400
    
    receiver_public_key_pem = receiver_public_key_file.read()
    
    # Get user selections
    expires_in_hours = int(request.form.get('expires', 24))
    max_downloads = int(request.form.get('max_downloads', 1))
    
    # Read file data
    file_data = file.read()
    original_filename = secure_filename(file.filename)
    file_size = len(file_data)
    
    # Generate random encryption key for this file
    file_key = generate_file_key()
    
    # Encrypt the file using AES-256-GCM
    encrypted_data = encrypt_file(file_data, file_key)
    
    # Save encrypted file to disk
    encrypted_filename = secrets.token_urlsafe(16) + '.enc'
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)
    
    # Generate download token and create secure link
    download_token = generate_link_token()
    token_hash = hash_token_for_storage(download_token)
    
    # Combine key and token into a single URL
    combined = file_key.hex() + '.' + download_token
    final_token = base64.urlsafe_b64encode(combined.encode()).decode()
    
    # Encrypt the token with receiver's public key
    encrypted_token = encrypt_link_with_receiver_public_key(final_token, receiver_public_key_pem)
    
    # Calculate file hash for integrity verification
    file_hash = compute_file_hash(file_data)
    
    # Store file metadata in database
    db.store_file_metadata(token_hash, original_filename, file_size, file_hash, encrypted_path, expires_in_hours, max_downloads)
    
    # Create download URL with IP address (NOT localhost)
    local_ip = get_local_ip()
    download_url = f'http://{local_ip}:5000/download?token=' + encrypted_token
    
    return render_template('upload_success.html', 
                         download_url=download_url, 
                         expires_in=expires_in_hours, 
                         max_downloads=max_downloads)

# ============================================
# DOWNLOAD PAGE - Shows UI for private key upload
# ============================================
@app.route('/download')
def download_page():
    encrypted_token = request.args.get('token', '')
    if not encrypted_token:
        return "No token provided", 400
    return render_template('download_instructions.html', encrypted_token=encrypted_token)

# ============================================
# DECRYPT AND DOWNLOAD - Receiver uploads private key
# ============================================
@app.route('/decrypt_and_download', methods=['POST'])
def decrypt_and_download():
    try:
        encrypted_token = request.form.get('encrypted_token', '')
        private_key_file = request.files.get('private_key')
        
        # CRITICAL: Remove ALL whitespace from token
        encrypted_token = ''.join(encrypted_token.split())
        
        # Fix base64 padding
        while len(encrypted_token) % 4 != 0:
            encrypted_token += '='
        
        # Fix extra equals signs
        if encrypted_token.endswith('===='):
            encrypted_token = encrypted_token[:-2]
        
        print(f"Token length after cleaning: {len(encrypted_token)}")
        print(f"Token first 50 chars: {encrypted_token[:50]}")
        
        if not encrypted_token or not private_key_file:
            return render_template('download_instructions.html', 
                                 encrypted_token=request.form.get('encrypted_token', ''),
                                 error="Please provide both token and private key")
        
        private_key_pem = private_key_file.read()
        
        # Decrypt token
        decrypted_token = decrypt_link_with_receiver_private_key(encrypted_token, private_key_pem)
        
        print(f"Decrypted successfully!")
        
        # Redirect to download
        return redirect(f'/do_download/{decrypted_token}')
        
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return render_template('download_instructions.html', 
                             encrypted_token=request.form.get('encrypted_token', ''),
                             error=f"Decryption failed: {str(e)}")
    try:
        encrypted_token = request.form.get('encrypted_token', '')
        private_key_file = request.files.get('private_key')
        
        # Clean the token - remove ALL whitespace
        encrypted_token = ''.join(encrypted_token.split())
        
        # Fix base64 padding (add = signs if needed)
        missing_padding = len(encrypted_token) % 4
        if missing_padding:
            encrypted_token += '=' * (4 - missing_padding)
        
        print(f"Token length after cleaning: {len(encrypted_token)}")
        print(f"Token starts with: {encrypted_token[:50]}...")
        
        if not encrypted_token or not private_key_file:
            return render_template('download_instructions.html', 
                                 encrypted_token=request.form.get('encrypted_token', ''),
                                 error="Please provide both token and private key")
        
        private_key_pem = private_key_file.read()
        
        # Decrypt token using receiver's private key
        decrypted_token = decrypt_link_with_receiver_private_key(encrypted_token, private_key_pem)
        
        print(f"Decrypted successfully!")
        
        # Redirect to download with decrypted token
        return redirect(f'/do_download/{decrypted_token}')
        
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return render_template('download_instructions.html', 
                             encrypted_token=request.form.get('encrypted_token', ''),
                             error=f"Decryption failed: {str(e)}")

# ============================================
# ACTUAL DOWNLOAD - Sends the file to user
# ============================================
@app.route('/do_download/<decrypted_token>')
def do_download(decrypted_token):
    try:
        # Decode the token
        decoded = base64.urlsafe_b64decode(decrypted_token.encode()).decode()
        key_hex, token_part = decoded.split('.')
        file_key = bytes.fromhex(key_hex)
        token_hash = hash_token_for_storage(token_part)
        
        # Get metadata from database
        metadata = db.get_file_metadata(token_hash)
        if not metadata:
            return "Link has expired", 404
        
        # Check download limit
        if metadata['download_count'] >= metadata['max_downloads']:
            return "Download limit reached", 410
        
        # Read encrypted file from disk
        with open(metadata['encrypted_path'], 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt the file
        decrypted_data = decrypt_file(encrypted_data, file_key)
        
        # Verify file integrity
        if not verify_file_hash(decrypted_data, metadata['file_hash']):
            return "Integrity check failed! File may be corrupted.", 500
        
        # Update download count
        db.increment_download_count(metadata['id'])
        
        # Delete encrypted file if max downloads reached
        if metadata['download_count'] + 1 >= metadata['max_downloads']:
            os.remove(metadata['encrypted_path'])
        
        # Send the decrypted file to user
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=metadata['filename'],
            as_attachment=True
        )
    except Exception as e:
        return f"Download failed: {str(e)}", 400

# ============================================
# START THE SERVER
# ============================================
if __name__ == '__main__':
    db.delete_expired_files()
    local_ip = get_local_ip()
    print("="*50)
    print("🔒 SECURE FILE DROP SYSTEM")
    print("="*50)
    print(f"📍 Local URL: http://localhost:5000")
    print(f"📍 Network URL: http://{local_ip}:5000")
    print("="*50)
    print("📤 Give this link to receiver (Sender's IP):")
    print(f"   http://{local_ip}:5000")
    print("="*50)
    app.run(host='0.0.0.0', port=5000, debug=True)