from __future__ import annotations
from typing import List, Tuple, Dict
from .crypto import pem_pkcs1_to_private_key, private_key_to_jwk

def build_jwks(rows: List[Tuple[int, bytes, int]]) -> Dict:
    """
    Build JWKS from DB rows (kid, pem_bytes, exp).
    Returns { "keys": [ ... ] } where each key is a JWK containing public n/e and kid.
    """
    keys = []
    for kid, pem, exp in rows:
        priv = pem_pkcs1_to_private_key(pem)
        jwk = private_key_to_jwk(priv, kid)
        keys.append(jwk)
    return {"keys": keys}
