# Secure File Drop System

## Installation

1. Install Python 3.11+
2. Run: pip install -r requirements.txt
3. Run: python app.py
4. Open: http://localhost:5000

## Production Deployment

1. Run the app behind a reverse proxy such as Nginx.
2. Serve traffic over HTTPS only.
3. Use Gunicorn instead of the Flask development server.
4. Keep `debug=False` in production.

Example:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Recommended Nginx settings:

- Terminate TLS at Nginx.
- Forward requests to Gunicorn on localhost.
- Set `Referrer-Policy: no-referrer` and other security headers.

## Security Features

- AES-256-GCM Encryption
- One-time download links
- Automatic expiration
- No user private keys stored on server
- Browser-side private key decryption
- Signed audit receipts
- Rate limiting on upload and download endpoints
- Receiver public key fingerprint display

py receiver_keygen.py
py app.py
