# tests/test_modules.py
# ------------------------------------------------------------
# Unit tests for the crypto and database modules.
# These tests verify that key generation, serialization,
# JWK conversion, and database interactions all work as expected.
# ------------------------------------------------------------
import time
from app.crypto import (
    generate_rsa_private_key,
    private_key_to_jwk,
    private_key_to_pem_pkcs1,
    pem_pkcs1_to_private_key,
)
from app.db import insert_key, fetch_one_key, fetch_all_valid_keys


def test_crypto_key_generation_and_jwk():
    """
    Test the cryptography module's key lifecycle and JWK conversion.

    Steps:
    1. Generate a new RSA private key.
    2. Serialize the private key to PEM (PKCS#1) format.
    3. Deserialize it back into a private key object.
    4. Convert the key into a JWK dictionary.

    Expected outcome:
    - The JWK contains valid fields: 'kty', 'kid', 'n', and 'e'.
    - 'kty' should be 'RSA'.
    - The 'kid' should match the assigned identifier.
    """
    priv = generate_rsa_private_key()
    pem = private_key_to_pem_pkcs1(priv)
    priv2 = pem_pkcs1_to_private_key(pem)

    jwk = private_key_to_jwk(priv2, kid="123")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == "123"
    assert "n" in jwk and "e" in jwk


def test_db_insert_and_fetch():
    """
    Test the database module's insert and fetch operations.

    Steps:
    1. Insert a valid (non-expired) private key into the database.
    2. Retrieve one valid key using fetch_one_key(expired=False).
    3. Retrieve all valid keys using fetch_all_valid_keys().
    4. Verify that the newly inserted key is present in the results.

    Expected outcome:
    - insert_key() returns a valid integer key ID.
    - fetch_one_key() returns a tuple (kid, key_bytes, exp).
    - fetch_all_valid_keys() returns a list containing the inserted key.
    """
    now = int(time.time())

    # Insert a valid key that expires in ~1000 seconds
    kid = insert_key(
        private_key_to_pem_pkcs1(generate_rsa_private_key()),
        now + 1000,
    )
    assert isinstance(kid, int)

    # Retrieve one valid key from the database
    row_valid = fetch_one_key(expired=False)
    assert row_valid is not None and len(row_valid) == 3  # (kid, key_bytes, exp)

    # Retrieve all valid keys and confirm our inserted one is included
    all_valid = fetch_all_valid_keys()
    assert isinstance(all_valid, list)
    assert any(k[0] == kid for k in all_valid)
