from flask import Flask, render_template, request, send_file, redirect
import os
import io
import base64
import secrets
import socket
import threading
import time

from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from crypto_utils import *
from database import FileDatabase


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PREFERRED_URL_SCHEME'] = 'https'

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

db = FileDatabase()
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

cleanup_started = False


# =========================
# GET LOCAL IP
# =========================

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def start_cleanup_worker():
    global cleanup_started

    if cleanup_started:
        return

    cleanup_started = True

    def cleanup_loop():
        while True:
            try:
                db.delete_expired_files()
            except Exception:
                pass
            time.sleep(3600)

    worker = threading.Thread(target=cleanup_loop, daemon=True)
    worker.start()


@app.after_request
def add_security_headers(response):
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


# =========================
# HOME
# =========================

@app.route('/')
def index():
    return render_template('upload.html')


# =========================
# UPLOAD FILE
# =========================

@app.route('/upload', methods=['POST'])
@limiter.limit("50 per hour")
def upload_file():

    if 'file' not in request.files:
        return "No file uploaded", 400

    file = request.files['file']

    if file.filename == '':
        return "No file selected", 400


    if 'receiver_public_key' not in request.files:
        return "Receiver public key missing", 400
    if 'sender_public_key' not in request.files:
        return "Sender public key missing", 400

    receiver_public_key_file = request.files['receiver_public_key']
    receiver_public_key_pem = receiver_public_key_file.read()
    receiver_key_fingerprint = compute_public_key_fingerprint(receiver_public_key_pem)

    sender_public_key_file = request.files['sender_public_key']
    sender_public_key_pem = sender_public_key_file.read()
    sender_key_fingerprint = compute_public_key_fingerprint(sender_public_key_pem)

    sender_signature = request.form.get('sender_signature', '')

    expires_in_hours = int(request.form.get('expires', 24))
    max_downloads = int(request.form.get('max_downloads', 1))

    file_data = file.read()
    original_filename = secure_filename(file.filename)
    file_size = len(file_data)

    # =========================
    # AES ENCRYPT FILE
    # =========================
    file_key = generate_file_key()
    encrypted_data = encrypt_file(file_data, file_key)

    encrypted_filename = secrets.token_urlsafe(16) + '.enc'
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)

    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)

    # Signature is now generated client-side and sent in the form

    # =========================
    # TOKEN GENERATION
    # =========================
    link_id = secrets.token_urlsafe(16)
    download_token = generate_link_token()

    token_hash = hash_token(download_token)

    combined = file_key.hex() + '.' + download_token
    final_token = base64.urlsafe_b64encode(combined.encode()).decode()

    encrypted_token = encrypt_link_with_receiver_public_key(
        final_token,
        receiver_public_key_pem
    )

    file_hash = compute_file_hash(file_data)

    file_id = db.store_file_metadata(
        link_id,
        token_hash,
        original_filename,
        file_size,
        file_hash,
        encrypted_path,
        encrypted_token,
        sender_public_key_pem.decode(),
        receiver_public_key_pem.decode(),
        sender_signature,
        expires_in_hours,
        max_downloads
    )

    audit_receipt = db.log_audit_event(
        'upload',
        file_id,
        {
            'link_id': link_id,
            'filename': original_filename,
            'file_size': file_size,
            'expires_in_hours': expires_in_hours,
            'max_downloads': max_downloads,
            'receiver_key_fingerprint': receiver_key_fingerprint,
            'sender_key_fingerprint': sender_key_fingerprint
        }
    )

    local_ip = get_local_ip()
    download_url = request.host_url.rstrip('/') + f'/download/{link_id}'

    return render_template(
        'upload_success.html',
        download_url=download_url,
        link_id=link_id,
        encrypted_token=encrypted_token,
        audit_receipt=audit_receipt,
        receiver_key_fingerprint=receiver_key_fingerprint,
        expires_in=expires_in_hours,
        max_downloads=max_downloads
    )


# =========================
# DOWNLOAD PAGE
# =========================

@app.route('/download/<link_id>')
@limiter.limit("50 per hour")
def download_page(link_id):
    metadata = db.get_file_metadata_by_link(link_id)

    if not metadata:
        return "Link expired or invalid", 404

    return render_template(
        'download_instructions.html',
        encrypted_token=metadata['encrypted_token'],
        link_id=link_id,
        sender_key_fingerprint=compute_public_key_fingerprint(metadata['sender_public_key'].encode()),
        receiver_key_fingerprint=compute_public_key_fingerprint(metadata['receiver_public_key'].encode()),
    )


# =========================
# DECRYPT TOKEN + REDIRECT
# =========================

# =========================
# FINAL FILE DOWNLOAD
# =========================

@app.route('/do_download/<link_id>', methods=['POST'])
@limiter.limit("50 per hour")
def do_download(link_id):

    try:
        decrypted_token = request.form.get('decrypted_token', '')

        if not decrypted_token:
            return "Missing decrypted token", 400

        decoded = base64.urlsafe_b64decode(
            decrypted_token.encode() + b'=' * (-len(decrypted_token) % 4)
        ).decode()

        key_hex, token_part = decoded.split('.')

        file_key = bytes.fromhex(key_hex)

        token_hash = hash_token(token_part)

        metadata = db.get_file_metadata_by_link(link_id)

        if not metadata:
            return "Link expired or invalid", 404

        if metadata['link_id'] != link_id:
            return "Link mismatch", 403

        if token_hash != metadata['token_hash']:
            return "Invalid token", 403

        if metadata['download_count'] >= metadata['max_downloads']:
            return "Download limit reached", 410

        with open(metadata['encrypted_path'], 'rb') as f:
            encrypted_data = f.read()


        decrypted_data = decrypt_file(encrypted_data, file_key)

        # Verify sender's signature
        sender_signature = metadata.get('sender_signature', '')
        sender_public_key_pem = metadata.get('sender_public_key', '').encode()
        if not verify_file_signature(decrypted_data, sender_signature, sender_public_key_pem):
            return "Sender signature verification failed! Possible tampering detected.", 403

        if not verify_file_hash(decrypted_data, metadata['file_hash']):
            return "Integrity check failed!", 500

        db.increment_download_count(metadata['id'])

        db.log_audit_event(
            'download',
            metadata['id'],
            {
                'link_id': link_id,
                'filename': db.decrypt_filename(metadata['filename']),
                'download_count': metadata['download_count'] + 1
            }
        )

        if metadata['download_count'] + 1 >= metadata['max_downloads']:
            os.remove(metadata['encrypted_path'])

        return send_file(
            io.BytesIO(decrypted_data),
            download_name=db.decrypt_filename(metadata['filename']),
            as_attachment=True
        )

    except Exception as e:
        return f"Download failed: {str(e)}", 400


# =========================
# RUN SERVER
# =========================

if __name__ == '__main__':
    db.delete_expired_files()
    start_cleanup_worker()

    local_ip = get_local_ip()

    print("=" * 50)
    print("🔒 SECURE FILE DROP SYSTEM")
    print("=" * 50)
    print("Local: https://localhost:5000")
    print(f"Network: https://{local_ip}:5000")
    print("=" * 50)

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        
    )