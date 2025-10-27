# app/auth.py
import time
import base64
import jwt
from app import db
from app.crypto import pem_to_private_key

def sign_jwt(username: str, use_expired: bool = False) -> str:
    import sqlite3
    row = db.fetch_one_expired() if use_expired else db.fetch_one_valid()
    if not row:
        raise ValueError("No suitable key found in database")

    kid, pem, _exp = row
    priv = pem_to_private_key(pem)
    now = int(time.time())

    payload = {
        "sub": username,
        "iss": "jwks-sqlite-demo",
        "aud": "example-aud",
        "iat": now,
        "exp": now + 900,
    }
    headers = {"kid": str(kid), "alg": "RS256", "typ": "JWT"}

    token = jwt.encode(payload, priv, algorithm="RS256", headers=headers)
    return token

def parse_basic_auth(header_value: str) -> str:
    default_user = "userABC"
    if not header_value or not header_value.startswith("Basic "):
        return default_user
    try:
        decoded = base64.b64decode(header_value.split()[1]).decode("utf-8")
        username = decoded.split(":", 1)[0]
        return username or default_user
    except Exception:
        return default_user
