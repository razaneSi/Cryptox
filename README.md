https://cryptox.ddns.net

to run locally python app.py
```

**Live Deployment**: https://cryptox.ddns.net/ (WireGuard VPN access required)

**Local**: Open http://127.0.0.1:5000 in your browser.


## Features

**Authentication & Management**
- User registration/login/logout
- Profile: Update username/password, account deletion
- Password Analyzer: Real-time strength (length>12, uppercase, alphanumeric, special)

**Cryptography Tools**
- Caesar Cipher: Printable ASCII encrypt/decrypt w/ shift
- Vigenère Cipher: Polyalphabetic w/ keyword (±spaces option)

**Hashing Labs**
- Password Hashing: Scrypt generate/verify
- TXT File Hashing: MD5/SHA256/Scrypt upload & integrity verify

**Secure Messenger**
- End-to-end E2EE chats (1:1/groups/files/voice/text)
- RSA public-key crypto for AES-256-GCM session keys
- X.509 PKI: User certs issuance/verify/revocation (CRL)
- User blocks, group mgmt (create/join/leave/add members)
- Dashboard overview of all tools


## Project Structure

```
Cryptox-1/
├── app.py                 # Flask + SocketIO backend, all routes/crypto/DB logic
├── requirements.txt       # flask>=3, cryptography>=42, flask-socketio>=5.3
├── cryptox.db            # SQLite: users/messages/conversations/certs/CRL/blocks
├── certs/                # X.509 PKI (CA self-signed)
│   ├── ca_certificate.pem
│   └── ca_private_key.pem
├── static/               # Frontend assets
│   ├── app.js           # Utilities/animations/profile
│   ├── messenger.js     # E2EE client logic
│   ├── style.css
│   └── bg.jpg
├── templates/            # Jinja2 pages
│   ├── base.html        # Layout/sidebar
│   ├── [login/register/dashboard/password/caesar/vigenere/hashing/file_hashing/messenger].html
├── check_time.py         # Utility
├── TODO.md               # Tasks
└── README.md
```


## API Endpoints

**Tools**
| Endpoint | Method | Description |
|---|---|---|
| `/api/password-check` | POST | `{"password": "..."}` → strength checks/score |
| `/api/caesar` | POST | `{"text","shift","mode"}` → cipher result |
| `/api/vigenere` | POST | `{"text","key","mode","count_spaces"}` → cipher result |
| `/api/hash-password` | POST | `{"password": "..."}` → scrypt hash |
| `/api/verify-password` | POST | `{"password": "...", "hash": "..."}` → valid? |
| `/api/hash-text-file` | POST | TXT upload + method → hash/bytes |
| `/api/verify-text-file-hash` | POST | TXT + expected/method → valid? |

**Account**
| `/api/account/profile` | GET | Profile status |
| `/api/account/update-username` | POST | New name + current pwd |
| `/api/account/update-password` | POST | New/confirm + current |
| `/api/account/delete` | POST | Current pwd |

**Messenger** (JSON; requires login/keys)
| Endpoint | Method | Description |
|---|---|---|
| `/api/messenger/users` | GET | All users w/ key/cert status/blocks |
| `/api/messenger/blocks` | GET/POST | Manage blocks |
| `/api/messenger/get-key/<username>` | GET | Pub keys/certs/valid? |
| `/api/messenger/register-key` | POST | Pub enc/sign keys → certs |
| `/api/messenger/ca` | GET | CA cert/details |
| `/api/messenger/ca/crl` | GET | CRL PEM/revoked list |
| `/api/messenger/ca/revoke` | POST | Username + reason |
| `/api/messenger/conversations` | GET/POST | List/create direct/group |
| `/api/messenger/conversations/<id>/messages` | GET | Decryptable msgs/blocks |
| `/api/messenger/messages` | POST/DELETE | Send rich msg/delete |

## Cryptography Tools & Methods

- **Hashes**: SHA256/MD5 (hashlib), Scrypt (werkzeug.security)
- **Ciphers**: Custom Caesar/Vigenère
- **E2EE Messenger**:
  | Layer | Algorithm |
  |-------|-----------|
  | Symmetric | AES-256-GCM (payload/nonce/tag) |
  | Key Exchange | RSA-OAEP (wrap AES keys) |
  | Signatures | RSA-PSS |
  | PKI | X.509 v3 certs (cryptography.hazmat), CA/CRL revocation |
  | Auth | Scrypt (passwords)

**Deployment**: Cloud-hosted at https://cryptox.ddns.net/ with WireGuard VPN for secure access.


