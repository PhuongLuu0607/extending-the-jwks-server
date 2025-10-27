# main.py — JWKS + SQLite (Project 2, non-FastAPI)
from http.server import BaseHTTPRequestHandler, HTTPServer
import sqlite3
import time
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
import json
import jwt

# --- Server settings ---
hostName = "0.0.0.0"
serverPort = 8080

# --- SQLite settings ---
DB_FILE = "totally_not_my_privateKeys.db"
SCHEMA = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
"""

# --- Crypto helpers ---
def generate_rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

def private_key_to_pem_pkcs1(priv) -> bytes:
  
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

def pem_to_private_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def public_jwk_from_private(priv, kid: str) -> dict:
    pub = priv.public_key()
    numbers = pub.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": b64u(n), "e": b64u(e)}

# --- DB layer (parameterized queries) ---
class KeyDB:
    def __init__(self, path=DB_FILE):
        # ✅ AUTOCOMMIT 
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.executescript(SCHEMA)

    def now(self) -> int:
        return int(time.time())

    def insert_key(self, pem: bytes, exp: int) -> int:
        cur = self.conn.execute("INSERT INTO keys(key, exp) VALUES(?, ?)", (pem, exp))
        return cur.lastrowid  # autocommitted

    def fetch_one_valid(self):
        cur = self.conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
            (self.now(),),
        )
        return cur.fetchone()

    def fetch_one_expired(self):
        cur = self.conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (self.now(),),
        )
        return cur.fetchone()

    def fetch_all_valid(self):
        cur = self.conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC",
            (self.now(),),
        )
        return cur.fetchall()

# Seed DB
db = KeyDB()
if not db.fetch_one_valid() and not db.fetch_one_expired():
    now = db.now()
    expired = generate_rsa_private_key()
    db.insert_key(private_key_to_pem_pkcs1(expired), now - 10)  # expired
    valid = generate_rsa_private_key()
    db.insert_key(private_key_to_pem_pkcs1(valid), now + 3600)  # +1h
    print("[DB] Seeded 1 expired key + 1 valid key ✅")

# --- HTTP server ---
class MyServer(BaseHTTPRequestHandler):
    def _send_json(self, obj, status=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # GET /.well-known/jwks.json: return JWKs 
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/.well-known/jwks.json":
            rows = db.fetch_all_valid()
            keys = []
            for kid, pem, _exp in rows:
                priv = pem_to_private_key(pem)
                keys.append(public_jwk_from_private(priv, kid=str(kid)))
            return self._send_json({"keys": keys})
        else:
            self.send_response(404)
            self.end_headers()

    def _json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # POST /auth[?expired=1] 
    def do_POST(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path != "/auth":
            self.send_response(404)
            self.end_headers()
            return

        use_expired = "expired" in qs
        row = db.fetch_one_expired() if use_expired else db.fetch_one_valid()
        if not row:
            return self._send_json({"error": "Requested key not available"}, status=404)
        kid, pem, _exp = row
        priv = pem_to_private_key(pem)

        #fallback JSON body {"username": ...}
        username = "userABC"
        auth = self.headers.get("Authorization")
        if auth and auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth.split()[1]).decode("utf-8")
                username = decoded.split(":", 1)[0] or username
            except Exception:
                pass
        else:
            body = self._json_body()
            username = body.get("username", username)

        now = int(time.time())
        payload = {
            "sub": username,
            "iss": "jwks-sqlite-demo",
            "aud": "example-aud",
            "iat": now,
            "exp": now + 900,  # 15 mins
        }
        headers = {"kid": str(kid), "alg": "RS256", "typ": "JWT"}

        token = jwt.encode(payload, priv, algorithm="RS256", headers=headers)
        return self._send_json({"token": token})

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Serving on http://{hostName}:{serverPort}  (DB: {DB_FILE})")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
