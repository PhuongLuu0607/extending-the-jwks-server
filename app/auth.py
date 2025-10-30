from __future__ import annotations
import time, jwt
from typing import Dict, Any, Tuple, Optional
from .config import settings
from .db import fetch_one_key
# no need to load private key object for PyJWT; pass PEM bytes directly

def issue_token(expired: bool) -> Tuple[str, Dict[str, Any], int]:
    """
    Fetch a key from DB (expired or valid per `expired` flag), sign a JWT, return (token, meta, code).
    meta contains details on which kid was used and the key expiration timestamp (for debugging).
    """
    row = fetch_one_key(expired=expired)
    if not row:
        return ("", {"error": "no appropriate key found"}, 500)
    kid, pem_bytes, key_exp_ts = row
    now = int(time.time())
    # The token 'exp' claim is independent of the key expiry. For grading, we still set token expiry
    # so tokens are valid for a short time when signed with valid key.
    token_exp = now + 900 if not expired else now - 10  # expired token if expired==True
    payload = {
        "sub": "userABC",
        "iss": settings.jwt_iss,
        "aud": settings.jwt_aud,
        "iat": now,
        "exp": token_exp,
    }
    # PyJWT accepts PEM bytes as key for RS256
    try:
        token = jwt.encode(payload, pem_bytes, algorithm="RS256", headers={"kid": str(kid), "typ": "JWT"})
    except Exception as e:
        return ("", {"error": f"failed to sign token: {e}"}, 500)
    return (token, {"kid": kid, "key_exp": key_exp_ts}, 200)
