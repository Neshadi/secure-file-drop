from flask import Flask, render_template, request, send_file
import os
import io
import base64
import secrets
from werkzeug.utils import secure_filename
from crypto_utils import *
from database import FileDatabase

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'

db = FileDatabase()
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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
    file_hash = compute_file_hash(file_data)
    db.store_file_metadata(token_hash, original_filename, file_size, file_hash, encrypted_path, expires_in_hours, max_downloads)
    download_url = request.host_url + 'download/' + final_token
    return render_template('upload_success.html', download_url=download_url, expires_in=expires_in_hours, max_downloads=max_downloads)

@app.route('/download/<token>')
def download_page(token):
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        key_hex, token_part = decoded.split('.')
        token_hash = hash_token_for_storage(token_part)
        metadata = db.get_file_metadata(token_hash)
        if not metadata:
            return "Link has expired", 404
        return render_template('download.html', filename=metadata['filename'], file_size=metadata['file_size'], token=token)
    except:
        return "Invalid link", 400

@app.route('/do_download/<token>')
def do_download(token):
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        key_hex, token_part = decoded.split('.')
        file_key = bytes.fromhex(key_hex)
        token_hash = hash_token_for_storage(token_part)
        metadata = db.get_file_metadata(token_hash)
        if not metadata:
            return "Link expired", 404
        with open(metadata['encrypted_path'], 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = decrypt_file(encrypted_data, file_key)
        if not verify_file_hash(decrypted_data, metadata['file_hash']):
            return "Integrity check failed", 500
        db.increment_download_count(metadata['id'])
        if metadata['download_count'] + 1 >= metadata['max_downloads']:
            os.remove(metadata['encrypted_path'])
        return send_file(io.BytesIO(decrypted_data), download_name=metadata['filename'], as_attachment=True)
    except Exception as e:
        return f"Download failed: {str(e)}", 500

if __name__ == '__main__':
    db.delete_expired_files()
    print("="*50)
    print("Secure File Drop System Started")
    print("="*50)
    print("URL: http://localhost:5000")
    print("="*50)
    app.run(host='0.0.0.0', port=5000, debug=True)
