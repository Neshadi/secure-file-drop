import sqlite3
import os
import json
from datetime import datetime, timedelta

from crypto_utils import encrypt_metadata_value, decrypt_metadata_value, sign_audit_event, verify_audit_event_signature

class FileDatabase:
    def __init__(self, db_path="file_metadata.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id TEXT UNIQUE NOT NULL DEFAULT '',
                token_hash TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                encrypted_file_path TEXT NOT NULL,
                encrypted_token TEXT NOT NULL DEFAULT '',
                sender_public_key TEXT NOT NULL,
                receiver_public_key TEXT NOT NULL,
                sender_signature TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                download_count INTEGER DEFAULT 0,
                max_downloads INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                file_id INTEGER,
                details TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('PRAGMA table_info(files)')
        existing_columns = {row[1] for row in cursor.fetchall()}
        # Add new columns if missing (for upgrades)
        if 'sender_public_key' not in existing_columns:
            cursor.execute("ALTER TABLE files ADD COLUMN sender_public_key TEXT NOT NULL DEFAULT ''")
        if 'receiver_public_key' not in existing_columns:
            cursor.execute("ALTER TABLE files ADD COLUMN receiver_public_key TEXT NOT NULL DEFAULT ''")
        if 'sender_signature' not in existing_columns:
            cursor.execute("ALTER TABLE files ADD COLUMN sender_signature TEXT NOT NULL DEFAULT ''")

        conn.commit()
        conn.close()
    
    def store_file_metadata(self, link_id, token_hash, filename, file_size, file_hash, 
                           encrypted_path, encrypted_token, sender_public_key, receiver_public_key, sender_signature, expires_in_hours=24, max_downloads=1):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        expires_at = datetime.now() + timedelta(hours=expires_in_hours)
        encrypted_filename = encrypt_metadata_value(filename)
        encrypted_file_hash = encrypt_metadata_value(file_hash)
        encrypted_path_value = encrypt_metadata_value(encrypted_path)
        encrypted_token_value = encrypt_metadata_value(encrypted_token)
        encrypted_sender_pub = encrypt_metadata_value(sender_public_key)
        encrypted_receiver_pub = encrypt_metadata_value(receiver_public_key)
        encrypted_sig = encrypt_metadata_value(sender_signature)
        cursor.execute('''
            INSERT INTO files (link_id, token_hash, filename, file_size, file_hash, 
                             encrypted_file_path, encrypted_token, sender_public_key, receiver_public_key, sender_signature, expires_at, max_downloads)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (link_id, token_hash, encrypted_filename, file_size, encrypted_file_hash, encrypted_path_value, 
              encrypted_token_value, encrypted_sender_pub, encrypted_receiver_pub, encrypted_sig, expires_at, max_downloads))
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return file_id
    
    def get_file_metadata_by_link(self, link_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, link_id, filename, file_size, file_hash, encrypted_file_path, 
                     token_hash, encrypted_token, sender_public_key, receiver_public_key, sender_signature, expires_at, download_count, max_downloads
            FROM files 
            WHERE link_id = ? AND expires_at > CURRENT_TIMESTAMP
        ''', (link_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return {
                'id': result[0],
                'link_id': result[1],
                'filename': decrypt_metadata_value(result[2]),
                'file_size': result[3],
                'file_hash': decrypt_metadata_value(result[4]),
                'encrypted_path': decrypt_metadata_value(result[5]),
                'token_hash': result[6],
                'encrypted_token': decrypt_metadata_value(result[7]),
                'sender_public_key': decrypt_metadata_value(result[8]),
                'receiver_public_key': decrypt_metadata_value(result[9]),
                'sender_signature': decrypt_metadata_value(result[10]),
                'expires_at': result[11],
                'download_count': result[12],
                'max_downloads': result[13]
            }
        return None

    def get_file_metadata_by_token(self, token_hash):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, link_id, filename, file_size, file_hash, encrypted_file_path, 
                     token_hash, encrypted_token, expires_at, download_count, max_downloads
            FROM files 
            WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP
        ''', (token_hash,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return {
                'id': result[0],
                'link_id': result[1],
                'filename': decrypt_metadata_value(result[2]),
                'file_size': result[3],
                'file_hash': decrypt_metadata_value(result[4]),
                'encrypted_path': decrypt_metadata_value(result[5]),
                'token_hash': result[6],
                'encrypted_token': decrypt_metadata_value(result[7]),
                'expires_at': result[8],
                'download_count': result[9],
                'max_downloads': result[10]
            }
        return None

    def decrypt_filename(self, encrypted_filename):
        try:
            return decrypt_metadata_value(encrypted_filename)
        except Exception:
            return encrypted_filename
    
    def increment_download_count(self, file_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE files SET download_count = download_count + 1 WHERE id = ?', (file_id,))
        conn.commit()
        conn.close()
    
    def delete_expired_files(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT encrypted_file_path
            FROM files
            WHERE expires_at <= CURRENT_TIMESTAMP OR download_count >= max_downloads
        ''')
        paths = [row[0] for row in cursor.fetchall()]

        cursor.execute('''
            DELETE FROM files
            WHERE expires_at <= CURRENT_TIMESTAMP OR download_count >= max_downloads
        ''')
        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        for path in paths:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

        return deleted

    def log_audit_event(self, event_type, file_id, details):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        details_text = json.dumps(details, sort_keys=True)
        signature = sign_audit_event(event_type, file_id, details_text)

        cursor.execute('''
            INSERT INTO audit_events (event_type, file_id, details, signature)
            VALUES (?, ?, ?, ?)
        ''', (event_type, file_id, details_text, signature))

        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return {
            'event_id': event_id,
            'signature': signature
        }
