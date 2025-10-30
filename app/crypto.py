# crypto.py
# -----------------------------------------------------------
# This module handles all cryptographic functionality
# for the JWKS (JSON Web Key Set) SQLite server.
#
# It provides helper functions to:
#   - generate RSA private keys,
#   - serialize/deserialize them in PEM format,
#   - convert key components into base64url form, and
#   - construct JWK (JSON Web Key) representations.
#
# These functions are used by other modules (e.g., db.py, jwks.py)
# to securely create, store, and expose keys for JWT signing.
# -----------------------------------------------------------

from __future__ import annotations
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
import base64
from typing import Dict, Any

def generate_rsa_private_key() -> RSAPrivateKey:
    """
    Generate a new RSA private key (2048 bits).

    - public_exponent=65537: industry-standard value for RSA.
    - key_size=2048: sufficient for modern cryptographic security.
    - backend=default_backend(): uses system OpenSSL implementation.

    Returns:
        RSAPrivateKey: an RSA key object usable for signing JWTs.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

def private_key_to_pem_pkcs1(priv: RSAPrivateKey) -> bytes:
    """
    Serialize an RSA private key into PKCS#1 (PEM) format.

    - Encoding: PEM (Base64 with header/footer)
    - Format: TraditionalOpenSSL = PKCS#1 (older but widely supported)
    - Encryption: None (keys are stored unencrypted for simplicity)

    Returns:
        bytes: PEM-encoded key suitable for SQLite BLOB storage.
    """
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption(),
    )

def pem_pkcs1_to_private_key(pem: bytes) -> RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())

def int_to_base64url(n: int) -> str:
    """
    Convert an integer to a Base64URL-encoded string (no padding).

    This is required for constructing JWK fields 'n' (modulus)
    and 'e' (exponent), which must be base64url encoded per RFC 7517.

    Args:
        n (int): integer value to convert (RSA modulus/exponent).

    Returns:
        str: base64url string representation.
    """
    if n == 0:
        raw = b'\x00'
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def private_key_to_jwk(priv: RSAPrivateKey, kid: str) -> Dict[str, Any]:
    """Produce minimal RSA public JWK (n, e, kid)."""
    pub = priv.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": int_to_base64url(pub.n),
        "e": int_to_base64url(pub.e),
        "alg": "RS256",
        "use": "sig",
        "kid": str(kid),
    }
