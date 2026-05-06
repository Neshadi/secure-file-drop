import sqlite3
from datetime import datetime, timedelta

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
                token_hash TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                encrypted_file_path TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                download_count INTEGER DEFAULT 0,
                max_downloads INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def store_file_metadata(self, token_hash, filename, file_size, file_hash, 
                           encrypted_path, expires_in_hours=24, max_downloads=1):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        expires_at = datetime.now() + timedelta(hours=expires_in_hours)
        cursor.execute('''
            INSERT INTO files (token_hash, filename, file_size, file_hash, 
                             encrypted_file_path, expires_at, max_downloads)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (token_hash, filename, file_size, file_hash, encrypted_path, 
              expires_at, max_downloads))
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return file_id
    
    def get_file_metadata(self, token_hash):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, filename, file_size, file_hash, encrypted_file_path, 
                   expires_at, download_count, max_downloads
            FROM files 
            WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP
        ''', (token_hash,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return {
                'id': result[0],
                'filename': result[1],
                'file_size': result[2],
                'file_hash': result[3],
                'encrypted_path': result[4],
                'expires_at': result[5],
                'download_count': result[6],
                'max_downloads': result[7]
            }
        return None
    
    def increment_download_count(self, file_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE files SET download_count = download_count + 1 WHERE id = ?', (file_id,))
        conn.commit()
        conn.close()
    
    def delete_expired_files(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM files WHERE expires_at <= CURRENT_TIMESTAMP')
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted
