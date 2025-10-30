# tests/test_jwks.py
# ------------------------------------------------------------
# Unit test for the JWKS (JSON Web Key Set) module.
# This test ensures that valid, non-expired keys stored in the
# SQLite database are properly returned as a JWKS structure.
# ------------------------------------------------------------
from app.jwks import build_jwks
from app.db import insert_key, fetch_all_valid_keys
from app.crypto import generate_rsa_private_key, private_key_to_pem_pkcs1
import time

def test_jwks_has_valid_key():
    """
    Test that the JWKS endpoint correctly returns at least one valid key.

    Steps:
    1. Insert a valid RSA private key into the database with a future expiration timestamp.
    2. Fetch all valid (non-expired) keys from the database.
    3. Convert those keys into JWKS format using build_jwks().
    4. Verify that the returned JWKS contains a "keys" field
       and includes at least one key entry.

    Expected outcome:
    - jwks["keys"] exists and contains one or more key objects.
    """
    now = int(time.time())
    insert_key(private_key_to_pem_pkcs1(generate_rsa_private_key()), now + 3600)
    keys = fetch_all_valid_keys()
    jwks = build_jwks(keys)
    assert "keys" in jwks and len(jwks["keys"]) >= 1
