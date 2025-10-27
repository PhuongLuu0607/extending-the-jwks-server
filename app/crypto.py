"""RSA key generation and JWK conversion helpers."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

def generate_rsa_private_key():
    """Generate a 2048-bit RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

def private_key_to_pem_pkcs1(priv) -> bytes:
    """Serialize RSA private key (PKCS#1) to PEM bytes."""
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

def pem_to_private_key(pem_bytes: bytes):
    """Load PEM back into private key object."""
    return serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())

def b64u(data: bytes) -> str:
    """Return base64url string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def public_jwk_from_private(priv, kid: str) -> dict:
    """Extract public JWK from private key."""
    pub = priv.public_key().public_numbers()
    n = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
    e = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": str(kid),
        "n": b64u(n),
        "e": b64u(e),
    }
