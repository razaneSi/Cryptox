from flask import Flask, render_template, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
CAESAR_ALPHABET = ''.join(chr(i) for i in range(32, 127))  

# ── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    return render_template('dashboard.html', active='dashboard')

@app.route('/password-strength')
def password_strength():
    return render_template('password.html', active='password')

@app.route('/caesar-cipher')
def caesar_cipher():
    return render_template('caesar.html', active='caesar')

@app.route('/vigenere-cipher')
def vigenere_cipher():
    return render_template('vigenere.html', active='vigenere')

@app.route('/hashing-exercise')
def hashing_exercise():
    return render_template('hashing.html', active='hashing')

# ── API ──────────────────────────────────────────────────────────────────────

@app.route('/api/caesar', methods=['POST'])
def api_caesar():
    data = request.get_json()
    text = data.get('text', '')
    try:
        shift = int(data.get('shift', 3))
    except (TypeError, ValueError):
        shift = 3
    mode = data.get('mode', 'encrypt')  # 'encrypt' | 'decrypt'
    if mode == 'decrypt':
        shift = -shift

    alphabet_len = len(CAESAR_ALPHABET)
    result = []
    for ch in text:

        if ch in CAESAR_ALPHABET:
            idx = CAESAR_ALPHABET.index(ch)
            result.append(CAESAR_ALPHABET[(idx + shift) % alphabet_len])

        else:
            result.append(ch)
    return jsonify({'result': ''.join(result)})


@app.route('/api/hash-password', methods=['POST'])
def api_hash_password():
    data = request.get_json() or {}
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'Password is required.'}), 400

    hashed_password = generate_password_hash(password, method='scrypt')
    return jsonify({
        'algorithm': 'scrypt',
        'hash': hashed_password
    })


@app.route('/api/verify-password', methods=['POST'])
def api_verify_password():
    data = request.get_json() or {}
    password = data.get('password', '')
    hashed_password = data.get('hash', '')
    if not password or not hashed_password:
        return jsonify({'error': 'Password and hash are required.'}), 400

    is_valid = check_password_hash(hashed_password, password)
    return jsonify({'valid': is_valid})


@app.route('/api/vigenere', methods=['POST'])
def api_vigenere():
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '').upper()
    mode = data.get('mode', 'encrypt')
    count_spaces = bool(data.get('count_spaces', True))
    if not key:
        return jsonify({'result': text})

    result = []
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            # Use 1-based key indexing (A=1 ... Z=26) to match expected output.
            k = (ord(key[key_idx % len(key)]) - ord('A')) + 1
            if mode == 'decrypt':
                k = -k
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + k) % 26 + base))
            key_idx += 1
        elif ch == ' ':
            result.append(ch)
            if count_spaces:
                # Keep spaces unchanged but optionally advance key position.
                key_idx += 1
        else:
            result.append(ch)
    return jsonify({'result': ''.join(result)})


@app.route('/api/password-check', methods=['POST'])
def api_password_check():
    data = request.get_json()
    pwd = data.get('password', '')

    checks = {
        'length': len(pwd) > 12,
        'uppercase': any(c.isupper() for c in pwd),
        'alphanumeric': any(c.isalpha() for c in pwd) and any(c.isdigit() for c in pwd),
        'special': any(not c.isalnum() for c in pwd),
    }
    score = sum(checks.values()) * 25
    if score == 100:
        label = 'STRONG'
    elif score >= 75:
        label = 'GOOD'
    elif score >= 50:
        label = 'MODERATE'
    else:
        label = 'WEAK'
    return jsonify({'checks': checks, 'score': score, 'label': label})




if __name__ == '__main__':
    app.run(debug=True)