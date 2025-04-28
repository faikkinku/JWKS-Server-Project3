from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
import base64
import datetime
import sqlite3
import os
import json
import jwt
import uuid
import threading
import time

hostName = "localhost"
serverPort = 8080
db_file = "totally_not_my_privateKeys.db"
rate_limit = {}
rate_limit_lock = threading.Lock()

# AES encryption helpers
def get_aes_key():
    key = os.getenv("NOT_MY_KEY")
    if key is None:
        raise ValueError("Environment variable NOT_MY_KEY not set.")
    key = key.encode('utf-8')
    if len(key) != 32:
        raise ValueError("NOT_MY_KEY must be exactly 32 bytes long.")
    return key

def encrypt_AES(data: bytes) -> bytes:
    key = get_aes_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted

def decrypt_AES(encrypted_data: bytes) -> bytes:
    key = get_aes_key()
    iv = encrypted_data[:16]
    encrypted = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Database setup
def init_db():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    return conn

def generate_and_store_keys(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]
    if count >= 2:
        return

    for hours in [-24, 24]:  # expired and valid keys
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        encrypted_pem = encrypt_AES(pem)
        exp_time = int((datetime.datetime.utcnow() + datetime.timedelta(hours=hours)).timestamp())
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_pem, exp_time))

    conn.commit()

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')

def cleanup_rate_limit():
    while True:
        time.sleep(1)
        now = time.time()
        with rate_limit_lock:
            for ip in list(rate_limit.keys()):
                rate_limit[ip] = [t for t in rate_limit[ip] if now - t <= 1]

threading.Thread(target=cleanup_rate_limit, daemon=True).start()

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            client_ip = self.client_address[0]

            with rate_limit_lock:
                now = time.time()
                rate_limit.setdefault(client_ip, []).append(now)
                rate_limit[client_ip] = [t for t in rate_limit[client_ip] if now - t <= 1]
                if len(rate_limit[client_ip]) > 10:
                    self.send_response(429)
                    self.end_headers()
                    self.wfile.write(b"Too many requests")
                    return

            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            current_time = int(datetime.datetime.utcnow().timestamp())

            if 'expired' in params:
                cursor.execute("SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp ASC LIMIT 1", (current_time,))
            else:
                cursor.execute("SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1", (current_time,))
            row = cursor.fetchone()
            if row is None:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No appropriate key found")
                return
            kid, key_encrypted = row

            try:
                key_pem = decrypt_AES(key_encrypted)
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                headers = {"kid": str(kid)}
                token_payload = {
                    "user": "testuser",
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }
                encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)

                # ✅ Always insert IP + NULL user_id
                cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, NULL)", (client_ip,))
                conn.commit()

                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
            finally:
                conn.close()
            return

        elif parsed_path.path == "/register":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)

            username = data.get("username")
            email = data.get("email")

            if not username or not email:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing username or email")
                return

            password = str(uuid.uuid4())
            hasher = PasswordHasher()
            password_hash = hasher.hash(password)

            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                               (username, password_hash, email))
                conn.commit()

                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"password": password}).encode())
            except sqlite3.IntegrityError:
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b"Username or email already exists")
            finally:
                conn.close()
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
            rows = cursor.fetchall()
            conn.close()

            keys = {"keys": []}
            for kid, encrypted_key in rows:
                key_pem = decrypt_AES(encrypted_key)
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                public_numbers = private_key.public_key().public_numbers()

                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                })

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    conn = init_db()
    generate_and_store_keys(conn)
    conn.close()

    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server running at http://{hostName}:{serverPort}/")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
