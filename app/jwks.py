from app import db
from app.crypto import public_jwk_from_private
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_private_key_from_pem(pem_bytes):
    """Load PEM bytes into RSA private key object."""
    return serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())

def get_public_jwks():
    """Return JWKS JSON for all keys in database."""
    keys = []
    for kid, pem, exp in db.fetch_all_valid_keys():
        priv = load_private_key_from_pem(pem)
        keys.append(public_jwk_from_private(priv, kid=kid))
    return {"keys": keys}
