# CryptoX — Security Suite

A full-stack cryptography dashboard with Flask backend and vanilla HTML/CSS/JS frontend.

## Setup

```bash
cd cryptox
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

## Features

- **Dashboard** — Overview of all tools
- **Password Intelligence** — Real-time strength analysis with 4 security checks:
  - Length > 12 characters
  - At least 1 uppercase letter
  - Contains letters and numbers
  - At least 1 special character
- **Caesar Cipher** — Encrypt/decrypt with configurable shift vector
- **Vigenère Cipher** — Polyalphabetic encryption with keyword matrix

## Structure

```
cryptox/
├── app.py               # Flask backend + API routes
├── requirements.txt
├── static/
│   ├── bg.jpg           # Background image
│   ├── style.css
│   └── app.js
└── templates/
    ├── base.html        # Sidebar + layout
    ├── dashboard.html
    ├── password.html
    ├── caesar.html
    └── vigenere.html
```

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/password-check` | POST | `{"password": "..."}` → score, label, checks |
| `/api/caesar` | POST | `{"text","shift","mode"}` → result |
| `/api/vigenere` | POST | `{"text","key","mode"}` → result |
