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

## Security: Digital Signatures for Audit Events

This project uses RSA-based digital signatures to ensure non-repudiation and integrity of audit logs. Each audit event is signed with a private RSA key, and the signature can be verified using the corresponding public key. This ensures that audit records cannot be forged or tampered with, and actions can be attributed to the system holding the private key.

**Key files:**

- `audit_signing_private.pem`: Private RSA key for signing audit events (kept secret).
- `audit_signing_public.pem`: Public RSA key for verifying audit event signatures.

**How it works:**

- When an audit event is logged, a digital signature is generated using the private key and stored with the event.
- Anyone with the public key can verify the authenticity and integrity of the audit event.

This mechanism provides strong non-repudiation and integrity guarantees for audit trails in the system.

py receiver_keygen.py
py app.py
