"""Auth helper functions for JWT signing and validation."""

import jwt
import time
from app.crypto import pem_to_private_key
from app.db import KeyDB

def issue_token(username: str, use_expired: bool = False) -> str:
    """Create a signed JWT using current key (or expired key if requested)."""
    db = KeyDB()
    row = db.fetch_one_expired() if use_expired else db.fetch_one_valid()
    if not row:
        raise RuntimeError("No key available in DB")

    kid, pem, _ = row
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
    return jwt.encode(payload, priv, algorithm="RS256", headers=headers)
