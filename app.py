import base64
import hashlib
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import lru_cache, wraps

from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.x509.oid import NameOID
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cryptox-secret-key-change-in-production")
app.config["DATABASE"] = os.path.join(app.root_path, "cryptox.db")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

CAESAR_ALPHABET = "".join(chr(i) for i in range(32, 127))
CERTS_DIR = os.path.join(app.root_path, "certs")
CA_KEY_PATH = os.path.join(CERTS_DIR, "ca_private_key.pem")
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca_certificate.pem")
CA_CERT_VALID_YEARS = 10
USER_CERT_VALID_DAYS = 365


def user_room(user_id):
    return f"user:{user_id}"


def conversation_room(conversation_id):
    return f"conversation:{conversation_id}"


def emit_user_refresh(user_id, reason):
    socketio.emit("messenger:refresh", {"reason": reason}, to=user_room(user_id))


def emit_conversation_refresh(conversation_id, reason):
    socketio.emit("messenger:conversation_refresh", {"conversation_id": conversation_id, "reason": reason}, to=conversation_room(conversation_id))


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def ensure_column_exists(db, table_name, column_name, column_type):
    columns = {row[1] for row in db.execute(f"PRAGMA table_info({table_name})").fetchall()}
    if column_name not in columns:
        db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


def load_pem_certificate(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_pem_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def write_pem_file(path, pem_bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_bytes)


def create_ca_material():
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DZ"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoX Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CryptoX Root CA"),
        ]
    )
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 * CA_CERT_VALID_YEARS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    key_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = ca_certificate.public_bytes(serialization.Encoding.PEM)
    write_pem_file(CA_KEY_PATH, key_pem)
    write_pem_file(CA_CERT_PATH, cert_pem)
    return ca_private_key, ca_certificate


def get_ca_material():
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        return load_pem_private_key(CA_KEY_PATH), load_pem_certificate(CA_CERT_PATH)
    return create_ca_material()


def issue_user_certificate(username, public_key_base64, key_purpose):
    try:
        user_public_key = load_der_public_key(base64.b64decode(public_key_base64))
    except Exception as exc:
        raise ValueError("Invalid public key format; expected base64-encoded SPKI.") from exc

    ca_private_key, ca_certificate = get_ca_material()
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoX Messenger Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, key_purpose),
        ]
    )

    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=USER_CERT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def verify_user_certificate(certificate_pem, expected_username, expected_public_key_base64):
    if not certificate_pem or not expected_public_key_base64:
        return False

    try:
        _, ca_certificate = get_ca_material()
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        now = datetime.now(timezone.utc)
        if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc < now:
            return False

        if certificate.issuer != ca_certificate.subject:
            return False

        common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if common_name != expected_username:
            return False

        expected_public_key = load_der_public_key(base64.b64decode(expected_public_key_base64))
        cert_public_key_der = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_public_key_der = expected_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_public_key_der != expected_public_key_der:
            return False

        ca_public_key = ca_certificate.public_key()
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        if is_certificate_revoked(certificate_pem):
            return False
        return True
    except Exception:
        return False


def parse_db_timestamp_utc(ts):
    if not ts:
        return datetime.now(timezone.utc)
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


@lru_cache(maxsize=1000)
def certificate_serial_from_pem(certificate_pem):
    if not certificate_pem:
        return None
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        return str(cert.serial_number)
    except Exception:
        return None


def is_certificate_serial_revoked(cert_serial):
    if not cert_serial:
        return False
    row = get_db().execute(
        "SELECT 1 FROM certificate_revocations WHERE cert_serial = ?",
        (cert_serial,),
    ).fetchone()
    return row is not None


def is_certificate_revoked(certificate_pem):
    cert_serial = certificate_serial_from_pem(certificate_pem)
    return is_certificate_serial_revoked(cert_serial)


def is_user_revoked(user):
    return is_certificate_revoked(user["encryption_certificate"]) or is_certificate_revoked(user["signing_certificate"])


def revoke_user_certificates(user, reason):
    db = get_db()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    for cert_type, cert_pem in (("encryption", user["encryption_certificate"]), ("signing", user["signing_certificate"])):
        cert_serial = certificate_serial_from_pem(cert_pem)
        if not cert_serial:
            continue
        db.execute(
            """
            INSERT OR REPLACE INTO certificate_revocations (cert_serial, username, cert_type, reason, revoked_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (cert_serial, user["username"], cert_type, reason, now),
        )
    db.commit()


def unrevoke_user_certificates(user):
    db = get_db()
    serials = [
        certificate_serial_from_pem(user["encryption_certificate"]),
        certificate_serial_from_pem(user["signing_certificate"]),
    ]
    serials = [serial for serial in serials if serial]
    if not serials:
        return 0
    placeholders = ",".join("?" for _ in serials)
    result = db.execute(
        f"DELETE FROM certificate_revocations WHERE cert_serial IN ({placeholders})",
        serials,
    )
    db.commit()
    return result.rowcount


def build_ca_crl():
    ca_private_key, ca_certificate = get_ca_material()
    rows = get_db().execute(
        """
        SELECT cert_serial, username, cert_type, reason, revoked_at
        FROM certificate_revocations
        ORDER BY revoked_at DESC
        """
    ).fetchall()

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_certificate.subject)
        .last_update(now)
        .next_update(now + timedelta(days=7))
    )
    for row in rows:
        revoked_at = parse_db_timestamp_utc(row["revoked_at"])
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(row["cert_serial"]))
            .revocation_date(revoked_at)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    return crl, rows


def init_db():
    db = sqlite3.connect(app.config["DATABASE"])
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS messenger_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            public_encryption_key TEXT,
            public_signing_key TEXT,
            encryption_certificate TEXT,
            signing_certificate TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            encrypted_message TEXT NOT NULL,
            encrypted_aes_key TEXT NOT NULL,
            nonce TEXT NOT NULL,
            tag TEXT NOT NULL,
            signature TEXT,
            algorithm TEXT DEFAULT 'AES-256-GCM / RSA-OAEP / RSA-PSS',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES messenger_users(id),
            FOREIGN KEY (receiver_id) REFERENCES messenger_users(id)
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            is_group INTEGER NOT NULL DEFAULT 0,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES messenger_users(id)
        );

        CREATE TABLE IF NOT EXISTS conversation_members (
            conversation_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (conversation_id, user_id),
            FOREIGN KEY (conversation_id) REFERENCES conversations(id),
            FOREIGN KEY (user_id) REFERENCES messenger_users(id)
        );

        CREATE TABLE IF NOT EXISTS secure_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            message_type TEXT NOT NULL DEFAULT 'text',
            encrypted_payload TEXT NOT NULL,
            nonce TEXT NOT NULL,
            tag TEXT NOT NULL,
            signature TEXT NOT NULL,
            algorithm TEXT DEFAULT 'AES-256-GCM / RSA-OAEP / RSA-PSS',
            file_name TEXT,
            file_mime_type TEXT,
            file_size INTEGER,
            file_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conversation_id) REFERENCES conversations(id),
            FOREIGN KEY (sender_id) REFERENCES messenger_users(id)
        );

        CREATE TABLE IF NOT EXISTS message_recipients (
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            encrypted_aes_key TEXT NOT NULL,
            PRIMARY KEY (message_id, user_id),
            FOREIGN KEY (message_id) REFERENCES secure_messages(id),
            FOREIGN KEY (user_id) REFERENCES messenger_users(id)
        );

        CREATE TABLE IF NOT EXISTS certificate_revocations (
            cert_serial TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            cert_type TEXT NOT NULL,
            reason TEXT,
            revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS user_blocks (
            blocker_id INTEGER NOT NULL,
            blocked_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (blocker_id, blocked_id),
            FOREIGN KEY (blocker_id) REFERENCES messenger_users(id),
            FOREIGN KEY (blocked_id) REFERENCES messenger_users(id)
        );
        """
    )
    ensure_column_exists(db, "messenger_users", "encryption_certificate", "TEXT")
    ensure_column_exists(db, "messenger_users", "signing_certificate", "TEXT")
    db.commit()
    db.close()


def fetch_user_by_username(username):
    return get_db().execute(
        """
        SELECT
            id,
            username,
            password_hash,
            public_encryption_key,
            public_signing_key,
            encryption_certificate,
            signing_certificate,
            created_at
        FROM messenger_users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()


def current_user():
    username = session.get("username")
    if not username:
        return None
    return fetch_user_by_username(username)


def fetch_conversation(conversation_id):
    return get_db().execute(
        """
        SELECT id, name, is_group, created_by, created_at, updated_at
        FROM conversations
        WHERE id = ?
        """,
        (conversation_id,),
    ).fetchone()


def fetch_conversation_members(conversation_id):
    return get_db().execute(
        """
        SELECT
            u.id,
            u.username,
            u.public_encryption_key,
            u.public_signing_key,
            u.encryption_certificate,
            u.signing_certificate
        FROM conversation_members cm
        JOIN messenger_users u ON u.id = cm.user_id
        WHERE cm.conversation_id = ?
        ORDER BY u.username COLLATE NOCASE
        """,
        (conversation_id,),
    ).fetchall()


def ensure_user_in_conversation(conversation_id, user_id):
    membership = get_db().execute(
        """
        SELECT 1
        FROM conversation_members
        WHERE conversation_id = ? AND user_id = ?
        """,
        (conversation_id, user_id),
    ).fetchone()
    return membership is not None


def is_blocked_by(blocker_id, blocked_id):
    if not blocker_id or not blocked_id:
        return False
    row = get_db().execute(
        """
        SELECT 1
        FROM user_blocks
        WHERE blocker_id = ? AND blocked_id = ?
        """,
        (blocker_id, blocked_id),
    ).fetchone()
    return row is not None


def is_blocked_pair(user_a_id, user_b_id):
    if not user_a_id or not user_b_id or user_a_id == user_b_id:
        return False
    return is_blocked_by(user_a_id, user_b_id) or is_blocked_by(user_b_id, user_a_id)


def fetch_visible_conversation_members_for_user(conversation_id, viewer_id):
    members = fetch_conversation_members(conversation_id)
    return [member for member in members if member["id"] == viewer_id or not is_blocked_pair(viewer_id, member["id"])]


def count_hidden_members_for_user(conversation_id, viewer_id):
    members = fetch_conversation_members(conversation_id)
    return sum(1 for member in members if member["id"] != viewer_id and is_blocked_pair(viewer_id, member["id"]))


def serialize_conversation_for_user(conversation):
    viewer_id = session.get("user_id")
    all_members = fetch_conversation_members(conversation["id"])
    visible_members = fetch_visible_conversation_members_for_user(conversation["id"], viewer_id)
    usernames = [member["username"] for member in (visible_members if conversation["is_group"] else all_members)]
    hidden_member_count = count_hidden_members_for_user(conversation["id"], viewer_id)
    sending_blocked = False
    if conversation["is_group"]:
        title = conversation["name"] or "Group chat"
    else:
        title = next((member["username"] for member in all_members if member["username"] != session["username"]), session["username"])
        direct_partner = next((member for member in all_members if member["id"] != viewer_id), None)
        if direct_partner and is_blocked_pair(viewer_id, direct_partner["id"]):
            sending_blocked = True

    visibility_notice = None
    if hidden_member_count > 0 and conversation["is_group"]:
        label = "account" if hidden_member_count == 1 else "accounts"
        visibility_notice = (
            f"{hidden_member_count} blocked {label} hidden in this group. "
            "Use block controls if you want to keep conversations away."
        )

    return {
        "id": conversation["id"],
        "name": title,
        "custom_name": conversation["name"],
        "is_group": bool(conversation["is_group"]),
        "updated_at": conversation["updated_at"],
        "members": usernames,
        "member_count": len(usernames),
        "can_add_members": bool(conversation["is_group"]),
        "hidden_member_count": hidden_member_count,
        "visibility_notice": visibility_notice,
        "sending_blocked": sending_blocked,
    }


def find_direct_conversation(user_id, partner_id):
    return get_db().execute(
        """
        SELECT c.id, c.name, c.is_group, c.created_by, c.created_at, c.updated_at
        FROM conversations c
        JOIN conversation_members cm1 ON cm1.conversation_id = c.id AND cm1.user_id = ?
        JOIN conversation_members cm2 ON cm2.conversation_id = c.id AND cm2.user_id = ?
        WHERE c.is_group = 0
          AND (
            SELECT COUNT(*)
            FROM conversation_members cm
            WHERE cm.conversation_id = c.id
          ) = 2
        LIMIT 1
        """,
        (user_id, partner_id),
    ).fetchone()


def create_direct_conversation(user_id, partner_id):
    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO conversations (name, is_group, created_by)
        VALUES (?, 0, ?)
        """,
        (None, user_id),
    )
    conversation_id = cursor.lastrowid
    db.executemany(
        """
        INSERT INTO conversation_members (conversation_id, user_id)
        VALUES (?, ?)
        """,
        [(conversation_id, user_id), (conversation_id, partner_id)],
    )
    db.commit()
    return fetch_conversation(conversation_id)


def evaluate_password_strength(password):
    checks = {
        "length": len(password) > 12,
        "uppercase": any(c.isupper() for c in password),
        "alphanumeric": any(c.isalpha() for c in password) and any(c.isdigit() for c in password),
        "special": any(not c.isalnum() for c in password),
    }
    score = sum(checks.values()) * 25
    if score == 100:
        label = "STRONG"
    elif score >= 75:
        label = "GOOD"
    elif score >= 50:
        label = "MODERATE"
    else:
        label = "WEAK"
    return {"checks": checks, "score": score, "label": label}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Your session expired. Sign in again to continue."}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


@socketio.on("connect")
def socket_connect():
    if not session.get("logged_in") or not session.get("user_id"):
        return False
    join_room(user_room(session["user_id"]))
    emit("messenger:connected", {"ok": True})


@socketio.on("messenger:join_conversation")
def socket_join_conversation(data):
    if not session.get("logged_in") or not session.get("user_id"):
        return
    try:
        conversation_id = int((data or {}).get("conversation_id"))
    except (TypeError, ValueError):
        return
    if ensure_user_in_conversation(conversation_id, session["user_id"]):
        join_room(conversation_room(conversation_id))


@socketio.on("messenger:leave_conversation")
def socket_leave_conversation(data):
    try:
        conversation_id = int((data or {}).get("conversation_id"))
    except (TypeError, ValueError):
        return
    leave_room(conversation_room(conversation_id))


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        strength = evaluate_password_strength(password)

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return redirect(url_for("register"))
        if strength["label"] != "STRONG":
            flash("Choose a stronger password that passes all CryptoX checks.", "error")
            return redirect(url_for("register"))
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))
        if fetch_user_by_username(username):
            flash("That username is already taken.", "error")
            return redirect(url_for("register"))

        get_db().execute(
            "INSERT INTO messenger_users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password, method="scrypt")),
        )
        get_db().commit()
        flash("Account created. Sign in to open the messenger lab.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = fetch_user_by_username(username)

        if user and check_password_hash(user["password_hash"], password):
            session["logged_in"] = True
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    password = request.form.get("password", "")
    user = current_user()

    if not user or not check_password_hash(user["password_hash"], password):
        flash("Account deletion failed. Enter your current password to confirm.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    db = get_db()
    db.execute(
        "DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?",
        (user["id"], user["id"]),
    )
    db.execute("DELETE FROM messenger_users WHERE id = ?", (user["id"],))
    db.commit()

    session.clear()
    flash("Your account and encrypted message history were deleted.", "success")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@app.route("/password-strength")
@login_required
def password_strength():
    return render_template("password.html", active="password")


@app.route("/caesar-cipher")
@login_required
def caesar_cipher():
    return render_template("caesar.html", active="caesar")


@app.route("/vigenere-cipher")
@login_required
def vigenere_cipher():
    return render_template("vigenere.html", active="vigenere")


@app.route("/hashing-exercise")
@login_required
def hashing_exercise():
    return render_template("hashing.html", active="hashing")


@app.route("/file-hash-exercise")
@login_required
def file_hash_exercise():
    return render_template("file_hashing.html", active="filehash")


@app.route("/secure-messenger-exercise")
@login_required
def secure_messenger_exercise():
    return render_template("messenger.html", active="messenger", username=session.get("username"))


@app.route("/api/account/profile")
@login_required
def api_account_profile():
    user = current_user()
    return jsonify(
        {
            "username": user["username"],
            "has_encryption_key": bool(user["public_encryption_key"]),
            "has_signing_key": bool(user["public_signing_key"]),
            "has_encryption_certificate": bool(user["encryption_certificate"]),
            "has_signing_certificate": bool(user["signing_certificate"]),
            "revoked_by_ca": is_user_revoked(user),
        }
    )


@app.route("/api/account/update-username", methods=["POST"])
@login_required
def api_update_username():
    data = request.get_json() or {}
    new_username = (data.get("username") or "").strip()
    current_password = data.get("current_password") or ""
    user = current_user()

    if not new_username or len(new_username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400
    if fetch_user_by_username(new_username) and new_username != user["username"]:
        return jsonify({"error": "That username is already in use."}), 400
    if not check_password_hash(user["password_hash"], current_password):
        return jsonify({"error": "Current password is incorrect."}), 400

    get_db().execute(
        "UPDATE messenger_users SET username = ? WHERE id = ?",
        (new_username, user["id"]),
    )
    get_db().commit()
    session["username"] = new_username
    return jsonify({"message": "Username updated successfully.", "username": new_username})


@app.route("/api/account/update-password", methods=["POST"])
@login_required
def api_update_password():
    data = request.get_json() or {}
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    confirm_password = data.get("confirm_password") or ""
    user = current_user()
    strength = evaluate_password_strength(new_password)

    if not check_password_hash(user["password_hash"], current_password):
        return jsonify({"error": "Current password is incorrect."}), 400
    if new_password != confirm_password:
        return jsonify({"error": "New password confirmation does not match."}), 400
    if strength["label"] != "STRONG":
        return jsonify({"error": "New password must satisfy all CryptoX strength checks."}), 400

    get_db().execute(
        "UPDATE messenger_users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password, method="scrypt"), user["id"]),
    )
    get_db().commit()
    return jsonify({"message": "Password updated successfully."})


@app.route("/api/account/delete", methods=["POST"])
@login_required
def api_delete_account():
    data = request.get_json() or {}
    current_password = data.get("current_password") or ""
    user = current_user()

    if not check_password_hash(user["password_hash"], current_password):
        return jsonify({"error": "Current password is incorrect."}), 400

    db = get_db()
    sender_message_ids = [
        row["id"]
        for row in db.execute(
            "SELECT id FROM secure_messages WHERE sender_id = ?",
            (user["id"],),
        ).fetchall()
    ]
    if sender_message_ids:
        placeholders = ",".join("?" for _ in sender_message_ids)
        db.execute(
            f"DELETE FROM message_recipients WHERE message_id IN ({placeholders})",
            sender_message_ids,
        )
        db.execute(
            f"DELETE FROM secure_messages WHERE id IN ({placeholders})",
            sender_message_ids,
        )

    db.execute("DELETE FROM conversation_members WHERE user_id = ?", (user["id"],))
    db.execute("DELETE FROM messenger_users WHERE id = ?", (user["id"],))
    db.commit()

    session.clear()
    return jsonify({"message": "Your account has been deleted."})


@app.route("/api/messenger/users")
@login_required
def api_messenger_users():
    rows = get_db().execute(
        """
        SELECT
            id,
            username,
            public_encryption_key,
            public_signing_key,
            encryption_certificate,
            signing_certificate,
            public_encryption_key IS NOT NULL AS has_encryption_key,
            public_signing_key IS NOT NULL AS has_signing_key
        FROM messenger_users
        WHERE username != ?
        ORDER BY username COLLATE NOCASE
        """,
        (session["username"],),
    ).fetchall()
    return jsonify(
        {
            "users": [
                {
                    "id": row["id"],
                    "username": row["username"],
                    "ready": bool(
                        row["has_encryption_key"]
                        and row["has_signing_key"]
                        and verify_user_certificate(
                            row["encryption_certificate"],
                            row["username"],
                            row["public_encryption_key"],
                        )
                        and verify_user_certificate(
                            row["signing_certificate"],
                            row["username"],
                            row["public_signing_key"],
                        )
                    ),
                    "blocked_by_you": bool(is_blocked_by(session["user_id"], row["id"])),
                    "blocked_you": bool(is_blocked_by(row["id"], session["user_id"])),
                }
                for row in rows
            ]
        }
    )


@app.route("/api/messenger/blocks")
@login_required
def api_messenger_blocks():
    rows = get_db().execute(
        """
        SELECT u.username, ub.created_at
        FROM user_blocks ub
        JOIN messenger_users u ON u.id = ub.blocked_id
        WHERE ub.blocker_id = ?
        ORDER BY u.username COLLATE NOCASE
        """,
        (session["user_id"],),
    ).fetchall()
    return jsonify(
        {
            "blocked_users": [
                {"username": row["username"], "created_at": row["created_at"]}
                for row in rows
            ]
        }
    )


@app.route("/api/messenger/block", methods=["POST"])
@login_required
def api_messenger_block_user():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username is required."}), 400
    if username == session["username"]:
        return jsonify({"error": "You cannot block yourself."}), 400

    target = fetch_user_by_username(username)
    if not target:
        return jsonify({"error": "User not found."}), 404

    get_db().execute(
        """
        INSERT OR IGNORE INTO user_blocks (blocker_id, blocked_id)
        VALUES (?, ?)
        """,
        (session["user_id"], target["id"]),
    )
    get_db().commit()

    shared_groups = get_db().execute(
        """
        SELECT COUNT(*) AS total
        FROM conversations c
        JOIN conversation_members cm1 ON cm1.conversation_id = c.id AND cm1.user_id = ?
        JOIN conversation_members cm2 ON cm2.conversation_id = c.id AND cm2.user_id = ?
        WHERE c.is_group = 1
        """,
        (session["user_id"], target["id"]),
    ).fetchone()["total"]

    return jsonify(
        {
            "message": f"{username} was blocked.",
            "username": username,
            "group_notice": (
                f"Privacy notice: {username} is now hidden from your view in {shared_groups} group chat(s)."
                if shared_groups
                else None
            ),
        }
    )


@app.route("/api/messenger/unblock", methods=["POST"])
@login_required
def api_messenger_unblock_user():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username is required."}), 400

    target = fetch_user_by_username(username)
    if not target:
        return jsonify({"error": "User not found."}), 404

    result = get_db().execute(
        """
        DELETE FROM user_blocks
        WHERE blocker_id = ? AND blocked_id = ?
        """,
        (session["user_id"], target["id"]),
    )
    get_db().commit()
    return jsonify(
        {
            "message": f"{username} was unblocked.",
            "username": username,
            "removed_entries": result.rowcount,
        }
    )


@app.route("/api/messenger/get-key/<username>")
@login_required
def api_messenger_get_key(username):
    user = fetch_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found."}), 404
    return jsonify(
        {
            "username": user["username"],
            "public_encryption_key": user["public_encryption_key"],
            "public_signing_key": user["public_signing_key"],
            "encryption_certificate": user["encryption_certificate"],
            "signing_certificate": user["signing_certificate"],
            "encryption_certificate_valid": verify_user_certificate(
                user["encryption_certificate"],
                user["username"],
                user["public_encryption_key"],
            ),
            "signing_certificate_valid": verify_user_certificate(
                user["signing_certificate"],
                user["username"],
                user["public_signing_key"],
            ),
            "revoked_by_ca": is_user_revoked(user),
        }
    )


@app.route("/api/messenger/register-key", methods=["POST"])
@login_required
def api_messenger_register_key():
    data = request.get_json() or {}
    public_encryption_key = (data.get("public_encryption_key") or "").strip()
    public_signing_key = (data.get("public_signing_key") or "").strip()

    if not public_encryption_key or not public_signing_key:
        return jsonify({"error": "Both public keys are required."}), 400

    username = session.get("username")
    try:
        encryption_certificate = issue_user_certificate(username, public_encryption_key, "ENCRYPTION")
        signing_certificate = issue_user_certificate(username, public_signing_key, "SIGNING")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    get_db().execute(
        """
        UPDATE messenger_users
        SET
            public_encryption_key = ?,
            public_signing_key = ?,
            encryption_certificate = ?,
            signing_certificate = ?
        WHERE id = ?
        """,
        (
            public_encryption_key,
            public_signing_key,
            encryption_certificate,
            signing_certificate,
            session["user_id"],
        ),
    )
    get_db().commit()
    return jsonify(
        {
            "message": "Keys and X.509 certificates registered successfully.",
            "encryption_certificate": encryption_certificate,
            "signing_certificate": signing_certificate,
        }
    )


@app.route("/api/messenger/ca")
@login_required
def api_messenger_ca_certificate():
    _, ca_certificate = get_ca_material()
    _crl, revoked_rows = build_ca_crl()
    return jsonify(
        {
            "ca_certificate": ca_certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            "issuer": ca_certificate.subject.rfc4514_string(),
            "serial_number": str(ca_certificate.serial_number),
            "not_valid_before": ca_certificate.not_valid_before_utc.isoformat(),
            "not_valid_after": ca_certificate.not_valid_after_utc.isoformat(),
            "revoked_certificates_count": len(revoked_rows),
        }
    )


@app.route("/api/messenger/certificate/<username>")
@login_required
def api_messenger_user_certificate(username):
    user = fetch_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found."}), 404

    return jsonify(
        {
            "username": user["username"],
            "encryption_certificate": user["encryption_certificate"],
            "signing_certificate": user["signing_certificate"],
            "encryption_certificate_valid": verify_user_certificate(
                user["encryption_certificate"],
                user["username"],
                user["public_encryption_key"],
            ),
            "signing_certificate_valid": verify_user_certificate(
                user["signing_certificate"],
                user["username"],
                user["public_signing_key"],
            ),
            "revoked_by_ca": is_user_revoked(user),
        }
    )


@app.route("/api/messenger/ca/crl")
@login_required
def api_messenger_ca_crl():
    crl, rows = build_ca_crl()
    return jsonify(
        {
            "crl_pem": crl.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            "issuer": crl.issuer.rfc4514_string(),
            "last_update": crl.last_update_utc.isoformat(),
            "next_update": crl.next_update_utc.isoformat(),
            "revoked": [
                {
                    "cert_serial": row["cert_serial"],
                    "username": row["username"],
                    "cert_type": row["cert_type"],
                    "reason": row["reason"],
                    "revoked_at": row["revoked_at"],
                }
                for row in rows
            ],
        }
    )


@app.route("/api/messenger/ca/revoke", methods=["POST"])
@login_required
def api_messenger_ca_revoke_user():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    reason = (data.get("reason") or "Revoked by CA policy").strip()
    if not username:
        return jsonify({"error": "username is required."}), 400

    user = fetch_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found."}), 404

    revoke_user_certificates(user, reason)
    return jsonify({"message": f"{username} certificates revoked by CA.", "username": username})


@app.route("/api/messenger/ca/unrevoke", methods=["POST"])
@login_required
def api_messenger_ca_unrevoke_user():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username is required."}), 400

    user = fetch_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found."}), 404

    deleted = unrevoke_user_certificates(user)
    return jsonify(
        {
            "message": f"{username} certificates removed from CRL.",
            "username": username,
            "removed_entries": deleted,
        }
    )


@app.route("/api/messenger/conversations")
@login_required
def api_messenger_conversations():
    rows = get_db().execute(
        """
        SELECT c.id, c.name, c.is_group, c.created_by, c.created_at, c.updated_at
        FROM conversations c
        JOIN conversation_members cm ON cm.conversation_id = c.id
        WHERE cm.user_id = ?
        ORDER BY c.updated_at DESC, c.id DESC
        """,
        (session["user_id"],),
    ).fetchall()
    serialized = []
    for row in rows:
        item = serialize_conversation_for_user(row)
        if item:
            serialized.append(item)
    return jsonify({"conversations": serialized})


@app.route("/api/messenger/conversations/direct", methods=["POST"])
@login_required
def api_create_direct_conversation():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    partner = fetch_user_by_username(username)
    if not partner:
        return jsonify({"error": "User not found."}), 404
    if partner["id"] == session["user_id"]:
        return jsonify({"error": "Choose another user."}), 400
    conversation = find_direct_conversation(session["user_id"], partner["id"])
    if not conversation and is_blocked_pair(session["user_id"], partner["id"]):
        return jsonify({"error": "You cannot start a new chat while one side is blocked."}), 403
    if not conversation:
        conversation = create_direct_conversation(session["user_id"], partner["id"])
        emit_user_refresh(session["user_id"], "direct_conversation_created")
        emit_user_refresh(partner["id"], "direct_conversation_created")

    serialized = serialize_conversation_for_user(conversation)
    return jsonify({"conversation": serialized})


@app.route("/api/messenger/conversations/group", methods=["POST"])
@login_required
def api_create_group_conversation():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if len(name) < 3:
        return jsonify({"error": "Group name must be at least 3 characters."}), 400

    member_ids = {session["user_id"]}

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO conversations (name, is_group, created_by)
        VALUES (?, 1, ?)
        """,
        (name, session["user_id"]),
    )
    conversation_id = cursor.lastrowid
    db.executemany(
        "INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)",
        [(conversation_id, member_id) for member_id in member_ids],
    )
    db.commit()
    for member_id in member_ids:
        emit_user_refresh(member_id, "group_conversation_created")

    return jsonify({"conversation": serialize_conversation_for_user(fetch_conversation(conversation_id))})


@app.route("/api/messenger/conversations/<int:conversation_id>/members", methods=["POST"])
@login_required
def api_add_group_member(conversation_id):
    if not ensure_user_in_conversation(conversation_id, session["user_id"]):
        return jsonify({"error": "Conversation not found."}), 404

    conversation = fetch_conversation(conversation_id)
    if not conversation or not conversation["is_group"]:
        return jsonify({"error": "Members can only be added to group chats."}), 400

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    user = fetch_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found."}), 404
    if is_blocked_pair(session["user_id"], user["id"]):
        return jsonify({"error": "This account is unavailable."}), 403

    membership = get_db().execute(
        """
        SELECT 1
        FROM conversation_members
        WHERE conversation_id = ? AND user_id = ?
        """,
        (conversation_id, user["id"]),
    ).fetchone()
    if membership:
        return jsonify({"error": "That user is already in the group."}), 400

    get_db().execute(
        "INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)",
        (conversation_id, user["id"]),
    )
    get_db().execute(
        "UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (conversation_id,),
    )
    get_db().commit()
    join_room_name = conversation_room(conversation_id)
    socketio.emit("messenger:member_added", {"conversation_id": conversation_id, "username": user["username"]}, to=join_room_name)
    emit_user_refresh(user["id"], "added_to_group")
    emit_conversation_refresh(conversation_id, "group_members_changed")
    return jsonify({"message": "Member added successfully."})


@app.route("/api/messenger/conversations/<int:conversation_id>/leave", methods=["POST"])
@login_required
def api_leave_group_conversation(conversation_id):
    if not ensure_user_in_conversation(conversation_id, session["user_id"]):
        return jsonify({"error": "Conversation not found."}), 404

    conversation = fetch_conversation(conversation_id)
    if not conversation or not conversation["is_group"]:
        return jsonify({"error": "Only group chats can be left."}), 400

    db = get_db()
    db.execute(
        """
        DELETE FROM conversation_members
        WHERE conversation_id = ? AND user_id = ?
        """,
        (conversation_id, session["user_id"]),
    )

    remaining_count = db.execute(
        """
        SELECT COUNT(*) AS total
        FROM conversation_members
        WHERE conversation_id = ?
        """,
        (conversation_id,),
    ).fetchone()["total"]

    if remaining_count == 0:
        message_ids = [
            row["id"]
            for row in db.execute(
                "SELECT id FROM secure_messages WHERE conversation_id = ?",
                (conversation_id,),
            ).fetchall()
        ]
        if message_ids:
            placeholders = ",".join("?" for _ in message_ids)
            db.execute(
                f"DELETE FROM message_recipients WHERE message_id IN ({placeholders})",
                message_ids,
            )
        db.execute("DELETE FROM secure_messages WHERE conversation_id = ?", (conversation_id,))
        db.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
    else:
        db.execute(
            "UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (conversation_id,),
        )

    db.commit()
    emit_user_refresh(session["user_id"], "left_group")
    if remaining_count > 0:
        emit_conversation_refresh(conversation_id, "group_members_changed")
    return jsonify({"message": "You left the group conversation."})


@app.route("/api/messenger/conversations/<int:conversation_id>/messages")
@login_required
def api_conversation_messages(conversation_id):
    if not ensure_user_in_conversation(conversation_id, session["user_id"]):
        return jsonify({"error": "Conversation not found."}), 404

    conversation = fetch_conversation(conversation_id)
    serialized_conversation = serialize_conversation_for_user(conversation)
    rows = get_db().execute(
        """
        SELECT
            m.id,
            m.message_type,
            m.encrypted_payload,
            m.nonce,
            m.tag,
            m.signature,
            m.algorithm,
            m.file_name,
            m.file_mime_type,
            m.file_size,
            m.file_hash,
            m.created_at,
            sender.username AS sender,
            sender.id AS sender_id,
            sender.encryption_certificate AS sender_encryption_certificate,
            sender.signing_certificate AS sender_signing_certificate,
            mr.encrypted_aes_key
        FROM secure_messages m
        JOIN messenger_users sender ON sender.id = m.sender_id
        LEFT JOIN message_recipients mr ON mr.message_id = m.id AND mr.user_id = ?
        WHERE m.conversation_id = ?
        ORDER BY m.created_at ASC, m.id ASC
        """,
        (session["user_id"], conversation_id),
    ).fetchall()

    messages = []
    blocked_by_ca_count = 0
    blocked_by_user_count = 0
    is_group = bool(serialized_conversation["is_group"])
    viewer_id = session["user_id"]
    sender_statuses = {}

    for row in rows:
        sender_id = row["sender_id"]
        if sender_id not in sender_statuses:
            # Check revocation once per sender
            revoked = (
                is_certificate_revoked(row["sender_encryption_certificate"]) or
                is_certificate_revoked(row["sender_signing_certificate"])
            )
            # Check blocking once per sender
            blocked = False
            if is_group:
                blocked = is_blocked_pair(viewer_id, sender_id)
            
            sender_statuses[sender_id] = {"revoked": revoked, "blocked": blocked}

        status = sender_statuses[sender_id]
        if status["revoked"]:
            blocked_by_ca_count += 1
            continue
        if status["blocked"]:
            blocked_by_user_count += 1
            continue
        if not row["encrypted_aes_key"]:
            blocked_by_user_count += 1
            continue

        messages.append(
            {
                "id": row["id"],
                "sender": row["sender"],
                "message_type": row["message_type"],
                "encrypted_payload": row["encrypted_payload"],
                "encrypted_aes_key": row["encrypted_aes_key"],
                "nonce": row["nonce"],
                "tag": row["tag"],
                "signature": row["signature"],
                "algorithm": row["algorithm"],
                "file_name": row["file_name"],
                "file_mime_type": row["file_mime_type"],
                "file_size": row["file_size"],
                "file_hash": row["file_hash"],
                "created_at": row["created_at"],
            }
        )

    return jsonify(
        {
            "conversation": serialized_conversation,
            "messages": messages,
            "blocked_by_ca_count": blocked_by_ca_count,
            "blocked_by_user_count": blocked_by_user_count,
        }
    )


@app.route("/api/messenger/messages", methods=["POST"])
@login_required
def api_send_rich_message():
    data = request.get_json() or {}
    conversation_id = data.get("conversation_id")
    message_type = (data.get("message_type") or "text").strip().lower()
    encrypted_payload = (data.get("encrypted_payload") or "").strip()
    nonce = (data.get("nonce") or "").strip()
    tag = (data.get("tag") or "").strip()
    signature = (data.get("signature") or "").strip()
    recipients = data.get("recipients") or []
    file_name = (data.get("file_name") or "").strip() or None
    file_mime_type = (data.get("file_mime_type") or "").strip() or None
    file_size = data.get("file_size")
    file_hash = (data.get("file_hash") or "").strip() or None

    if not conversation_id or not encrypted_payload or not nonce or not tag or not signature:
        return jsonify({"error": "Encrypted payload, nonce, tag, signature, and conversation are required."}), 400
    if message_type not in {"text", "file", "voice"}:
        return jsonify({"error": "Unsupported message type."}), 400
    if not ensure_user_in_conversation(conversation_id, session["user_id"]):
        return jsonify({"error": "Conversation not found."}), 404
    sender = current_user()
    if is_user_revoked(sender):
        return jsonify({"error": "Your certificate is revoked by CA. Sending is blocked."}), 403

    conversation = fetch_conversation(conversation_id)
    all_members = fetch_conversation_members(conversation_id)
    if not conversation["is_group"]:
        direct_partner = next((member for member in all_members if member["id"] != session["user_id"]), None)
        if direct_partner and is_blocked_pair(session["user_id"], direct_partner["id"]):
            return jsonify({"error": "This direct chat is blocked. You cannot send new messages."}), 403

    members = fetch_visible_conversation_members_for_user(conversation_id, session["user_id"])
    if len(members) <= 1:
        return jsonify({"error": "No visible recipients in this conversation."}), 403
    member_lookup = {member["username"]: member for member in members}
    expected_names = set(member_lookup.keys())
    provided_names = {item.get("username") for item in recipients}
    if provided_names != expected_names:
        return jsonify({"error": "Recipients must match the current conversation members exactly."}), 400

    for item in recipients:
        encrypted_aes_key = (item.get("encrypted_aes_key") or "").strip()
        if not encrypted_aes_key:
            return jsonify({"error": f"Missing wrapped AES key for {item.get('username')}."}), 400

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO secure_messages (
            conversation_id,
            sender_id,
            message_type,
            encrypted_payload,
            nonce,
            tag,
            signature,
            file_name,
            file_mime_type,
            file_size,
            file_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            conversation_id,
            session["user_id"],
            message_type,
            encrypted_payload,
            nonce,
            tag,
            signature,
            file_name,
            file_mime_type,
            file_size,
            file_hash,
        ),
    )
    message_id = cursor.lastrowid
    db.executemany(
        """
        INSERT INTO message_recipients (message_id, user_id, encrypted_aes_key)
        VALUES (?, ?, ?)
        """,
        [
            (message_id, member_lookup[item["username"]]["id"], item["encrypted_aes_key"])
            for item in recipients
        ],
    )
    db.execute(
        "UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (conversation_id,),
    )
    db.commit()
    emit_conversation_refresh(conversation_id, "new_message")
    for member in members:
        emit_user_refresh(member["id"], "conversation_updated")
    return jsonify({"message": "Encrypted message stored securely.", "message_id": message_id}), 201


@app.route("/api/messenger/messages/<int:message_id>", methods=["DELETE"])
@login_required
def api_delete_message(message_id):
    db = get_db()
    message = db.execute("SELECT sender_id, conversation_id FROM secure_messages WHERE id = ?", (message_id,)).fetchone()
    if not message:
        return jsonify({"error": "Message not found."}), 404

    if message["sender_id"] != session["user_id"]:
        return jsonify({"error": "You can only delete your own messages."}), 403

    db.execute("DELETE FROM message_recipients WHERE message_id = ?", (message_id,))
    db.execute("DELETE FROM secure_messages WHERE id = ?", (message_id,))
    db.commit()

    emit_conversation_refresh(message["conversation_id"], "message_deleted")
    return jsonify({"message": "Message deleted."})


@app.route("/api/messenger/send", methods=["POST"])
@login_required
def api_messenger_send():
    data = request.get_json() or {}
    receiver_username = (data.get("receiver") or "").strip()
    encrypted_message = (data.get("encrypted_message") or "").strip()
    encrypted_aes_key = (data.get("encrypted_aes_key") or "").strip()
    nonce = (data.get("nonce") or "").strip()
    tag = (data.get("tag") or "").strip()
    signature = (data.get("signature") or "").strip()

    if not all([receiver_username, encrypted_message, encrypted_aes_key, nonce, tag, signature]):
        return jsonify({"error": "All encrypted payload fields are required."}), 400

    if receiver_username == session["username"]:
        return jsonify({"error": "Choose a different recipient."}), 400
    sender = current_user()
    if is_user_revoked(sender):
        return jsonify({"error": "Your certificate is revoked by CA. Sending is blocked."}), 403

    receiver = fetch_user_by_username(receiver_username)
    if not receiver:
        return jsonify({"error": "Receiver not found."}), 404
    if is_blocked_pair(session["user_id"], receiver["id"]):
        return jsonify({"error": "This account is unavailable."}), 403
    if not receiver["public_encryption_key"] or not receiver["public_signing_key"]:
        return jsonify({"error": "Receiver has not registered cryptographic keys yet."}), 400

    get_db().execute(
        """
        INSERT INTO messages (
            sender_id,
            receiver_id,
            encrypted_message,
            encrypted_aes_key,
            nonce,
            tag,
            signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            receiver["id"],
            encrypted_message,
            encrypted_aes_key,
            nonce,
            tag,
            signature,
        ),
    )
    get_db().commit()
    return jsonify({"message": "Encrypted message stored securely."}), 201


@app.route("/api/messenger/inbox/<username>")
@login_required
def api_messenger_inbox(username):
    partner = fetch_user_by_username(username)
    if not partner:
        return jsonify({"error": "User not found."}), 404

    rows = get_db().execute(
        """
        SELECT
            m.id,
            sender.username AS sender,
            receiver.username AS receiver,
            m.encrypted_message,
            m.encrypted_aes_key,
            m.nonce,
            m.tag,
            m.signature,
            m.algorithm,
            m.created_at,
            sender.id AS sender_id,
            sender.encryption_certificate AS sender_encryption_certificate,
            sender.signing_certificate AS sender_signing_certificate
        FROM messages m
        JOIN messenger_users sender ON sender.id = m.sender_id
        JOIN messenger_users receiver ON receiver.id = m.receiver_id
        WHERE
            (sender.username = ? AND receiver.username = ?)
            OR
            (sender.username = ? AND receiver.username = ?)
        ORDER BY m.created_at ASC, m.id ASC
        """,
        (session["username"], username, username, session["username"]),
    ).fetchall()

    messages = []
    blocked_by_ca_count = 0
    blocked_by_user_count = 0
    for row in rows:
        if is_certificate_revoked(row["sender_encryption_certificate"]) or is_certificate_revoked(row["sender_signing_certificate"]):
            blocked_by_ca_count += 1
            continue
        messages.append(
            {
                "id": row["id"],
                "sender": row["sender"],
                "receiver": row["receiver"],
                "encrypted_message": row["encrypted_message"],
                "encrypted_aes_key": row["encrypted_aes_key"],
                "nonce": row["nonce"],
                "tag": row["tag"],
                "signature": row["signature"],
                "algorithm": row["algorithm"],
                "created_at": row["created_at"],
            }
        )
    return jsonify(
        {
            "messages": messages,
            "blocked_by_ca_count": blocked_by_ca_count,
            "blocked_by_user_count": blocked_by_user_count,
        }
    )


@app.route("/api/messenger/profile")
@login_required
def api_messenger_profile():
    user = current_user()
    return jsonify(
        {
            "username": user["username"],
            "has_encryption_key": bool(user["public_encryption_key"]),
            "has_signing_key": bool(user["public_signing_key"]),
            "has_encryption_certificate": bool(user["encryption_certificate"]),
            "has_signing_certificate": bool(user["signing_certificate"]),
            "revoked_by_ca": is_user_revoked(user),
        }
    )


@app.route("/api/caesar", methods=["POST"])
def api_caesar():
    data = request.get_json() or {}
    text = data.get("text", "")
    try:
        shift = int(data.get("shift", 3))
    except (TypeError, ValueError):
        shift = 3
    mode = data.get("mode", "encrypt")
    if mode == "decrypt":
        shift = -shift

    alphabet_len = len(CAESAR_ALPHABET)
    result = []
    for ch in text:
        if ch in CAESAR_ALPHABET:
            idx = CAESAR_ALPHABET.index(ch)
            result.append(CAESAR_ALPHABET[(idx + shift) % alphabet_len])
        else:
            result.append(ch)
    return jsonify({"result": "".join(result)})


@app.route("/api/hash-password", methods=["POST"])
def api_hash_password():
    data = request.get_json() or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Password is required."}), 400

    hashed_password = generate_password_hash(password, method="scrypt")
    return jsonify({"algorithm": "scrypt", "hash": hashed_password})


@app.route("/api/verify-password", methods=["POST"])
def api_verify_password():
    data = request.get_json() or {}
    password = data.get("password", "")
    hashed_password = data.get("hash", "")
    if not password or not hashed_password:
        return jsonify({"error": "Password and hash are required."}), 400

    is_valid = check_password_hash(hashed_password, password)
    return jsonify({"valid": is_valid})


@app.route("/api/hash-text-file", methods=["POST"])
def api_hash_text_file():
    uploaded = request.files.get("file")
    method = (request.form.get("method") or "sha256").strip().lower()
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "TXT file is required."}), 400

    if not uploaded.filename.lower().endswith(".txt"):
        return jsonify({"error": "Only .txt files are allowed."}), 400

    file_bytes = uploaded.read()
    if method == "md5":
        file_hash = hashlib.md5(file_bytes).hexdigest()
    elif method == "sha256":
        file_hash = hashlib.sha256(file_bytes).hexdigest()
    elif method == "scrypt":
        try:
            file_text = file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return jsonify({"error": "TXT file must be UTF-8 for scrypt hashing."}), 400
        file_hash = generate_password_hash(file_text, method="scrypt")
    else:
        return jsonify({"error": "Unsupported method. Use md5, sha256, or scrypt."}), 400

    return jsonify(
        {
            "algorithm": method,
            "hash": file_hash,
            "bytes": len(file_bytes),
            "filename": uploaded.filename,
        }
    )


@app.route("/api/verify-text-file-hash", methods=["POST"])
def api_verify_text_file_hash():
    uploaded = request.files.get("file")
    expected_hash = (request.form.get("expected_hash") or "").strip()
    method = (request.form.get("method") or "sha256").strip().lower()

    if not uploaded or not uploaded.filename:
        return jsonify({"error": "TXT file is required."}), 400
    if not uploaded.filename.lower().endswith(".txt"):
        return jsonify({"error": "Only .txt files are allowed."}), 400
    if not expected_hash:
        return jsonify({"error": "Expected hash is required."}), 400

    file_bytes = uploaded.read()
    if method == "md5":
        computed_hash = hashlib.md5(file_bytes).hexdigest()
        is_valid = computed_hash == expected_hash.lower()
    elif method == "sha256":
        computed_hash = hashlib.sha256(file_bytes).hexdigest()
        is_valid = computed_hash == expected_hash.lower()
    elif method == "scrypt":
        try:
            file_text = file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return jsonify({"error": "TXT file must be UTF-8 for scrypt verification."}), 400
        computed_hash = None
        is_valid = check_password_hash(expected_hash, file_text)
    else:
        return jsonify({"error": "Unsupported method. Use md5, sha256, or scrypt."}), 400

    return jsonify(
        {
            "algorithm": method,
            "filename": uploaded.filename,
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "valid": is_valid,
        }
    )


@app.route("/api/vigenere", methods=["POST"])
def api_vigenere():
    data = request.get_json() or {}
    text = data.get("text", "")
    key = data.get("key", "").upper()
    mode = data.get("mode", "encrypt")
    count_spaces = bool(data.get("count_spaces", True))
    if not key:
        return jsonify({"result": text})

    result = []
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            k = (ord(key[key_idx % len(key)]) - ord("A")) + 1
            if mode == "decrypt":
                k = -k
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + k) % 26 + base))
            key_idx += 1
        elif ch == " ":
            result.append(ch)
            if count_spaces:
                key_idx += 1
        else:
            result.append(ch)
    return jsonify({"result": "".join(result)})


@app.route("/api/password-check", methods=["POST"])
def api_password_check():
    data = request.get_json() or {}
    pwd = data.get("password", "")
    return jsonify(evaluate_password_strength(pwd))


with app.app_context():
    init_db()
    get_ca_material()


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
