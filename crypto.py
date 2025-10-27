import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_rsa_private_key():
    """Tạo một RSA private key 2048-bit"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def private_key_to_pem_pkcs1(priv) -> bytes:
    """Chuyển RSA private key sang dạng PEM PKCS#1 để lưu trong SQLite"""
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def pem_to_private_key(pem: bytes):
    """Đọc private key từ PEM bytes"""
    return serialization.load_pem_private_key(
        pem,
        password=None,
        backend=default_backend()
    )


def b64u(data: bytes) -> str:
    """Base64 URL-safe encoding không có dấu '=' ở cuối"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def public_jwk_from_private(priv, kid: str) -> dict:
    """Tạo public JWK từ private key (cho endpoint /.well-known/jwks.json)"""
    pub = priv.public_key()
    numbers = pub.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": b64u(n),
        "e": b64u(e)
    }
