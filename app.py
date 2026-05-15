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

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file uploaded", 400
    file = request.files['file']
    if file.filename == '':
        return "No file selected", 400
    
    if 'receiver_public_key' not in request.files:
        return "Receiver's public key is required", 400
    
    receiver_public_key_file = request.files['receiver_public_key']
    if receiver_public_key_file.filename == '':
        return "Please upload receiver's public key file", 400
    
    receiver_public_key_pem = receiver_public_key_file.read()
    
    expires_in_hours = int(request.form.get('expires', 24))
    max_downloads = int(request.form.get('max_downloads', 1))
    
    file_data = file.read()
    original_filename = secure_filename(file.filename)
    file_size = len(file_data)
    
    file_key = generate_file_key()
    encrypted_data = encrypt_file(file_data, file_key)
    
    encrypted_filename = secrets.token_urlsafe(16) + '.enc'
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)
    
    download_token = generate_link_token()
    token_hash = hash_token_for_storage(download_token)
    
    combined = file_key.hex() + '.' + download_token
    final_token = base64.urlsafe_b64encode(combined.encode()).decode()
    
    encrypted_token = encrypt_link_with_receiver_public_key(final_token, receiver_public_key_pem)
    
    file_hash = compute_file_hash(file_data)
    
    db.store_file_metadata(token_hash, original_filename, file_size, file_hash, encrypted_path, expires_in_hours, max_downloads)
    
    local_ip = get_local_ip()
    download_url = f'http://{local_ip}:5000/download?token=' + encrypted_token
    
    return render_template('upload_success.html', 
                         download_url=download_url, 
                         expires_in=expires_in_hours, 
                         max_downloads=max_downloads)

@app.route('/download')
def download_page():
    encrypted_token = request.args.get('token', '')
    if not encrypted_token:
        return "No token provided", 400
    return render_template('download_instructions.html', encrypted_token=encrypted_token)

# SINGLE CLEAN FUNCTION - NO DUPLICATES
@app.route('/decrypt_and_download', methods=['POST'])
def decrypt_and_download():
    try:
        encrypted_token = request.form.get('encrypted_token', '')
        private_key_file = request.files.get('private_key')
        
        # Remove ALL whitespace
        encrypted_token = ''.join(encrypted_token.split())
        
        # Remove trailing equals and fix padding
        encrypted_token = encrypted_token.rstrip('=')
        missing_padding = len(encrypted_token) % 4
        if missing_padding:
            encrypted_token += '=' * (4 - missing_padding)
        
        # Remove extra equals if more than 2
        while encrypted_token.endswith('===='):
            encrypted_token = encrypted_token[:-2]
        
        print(f"Token length: {len(encrypted_token)}")
        
        if not encrypted_token or not private_key_file:
            return render_template('download_instructions.html', 
                                 encrypted_token=request.form.get('encrypted_token', ''),
                                 error="Please provide both token and private key")
        
        private_key_pem = private_key_file.read()
        
        decrypted_token = decrypt_link_with_receiver_private_key(encrypted_token, private_key_pem)
        
        print("Decrypted successfully!")
        
        return redirect(f'/do_download/{decrypted_token}')
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return render_template('download_instructions.html', 
                             encrypted_token=request.form.get('encrypted_token', ''),
                             error=f"Decryption failed: {str(e)}")

@app.route('/do_download/<decrypted_token>')
def do_download(decrypted_token):
    try:
        decoded = base64.urlsafe_b64decode(decrypted_token.encode()).decode()
        key_hex, token_part = decoded.split('.')
        file_key = bytes.fromhex(key_hex)
        token_hash = hash_token_for_storage(token_part)
        
        metadata = db.get_file_metadata(token_hash)
        if not metadata:
            return "Link has expired", 404
        
        if metadata['download_count'] >= metadata['max_downloads']:
            return "Download limit reached", 410
        
        with open(metadata['encrypted_path'], 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data, file_key)
        
        if not verify_file_hash(decrypted_data, metadata['file_hash']):
            return "Integrity check failed!", 500
        
        db.increment_download_count(metadata['id'])
        
        if metadata['download_count'] + 1 >= metadata['max_downloads']:
            os.remove(metadata['encrypted_path'])
        
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=metadata['filename'],
            as_attachment=True
        )
    except Exception as e:
        return f"Download failed: {str(e)}", 400

if __name__ == '__main__':
    db.delete_expired_files()
    local_ip = get_local_ip()
    print("="*50)
    print("🔒 SECURE FILE DROP SYSTEM")
    print("="*50)
    print(f"📍 Local URL: http://localhost:5000")
    print(f"📍 Network URL: http://{local_ip}:5000")
    print("="*50)
    app.run(host='0.0.0.0', port=5000, debug=True)