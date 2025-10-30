# tests/test_auth.py
# -------------------------------------------------------
# Unit tests for the authentication module (app/auth.py)
# These tests verify that JWT tokens are properly issued
# using either valid (unexpired) or expired private keys.
# -------------------------------------------------------
import jwt, time
from app.auth import issue_token
from app.db import insert_key
from app.crypto import generate_rsa_private_key, private_key_to_pem_pkcs1
from app.config import settings

def setup_module():
    """
    Prepare the testing environment before any test runs.
    Inserts two private keys into the SQLite database:
    - One expired key (exp <= now)
    - One valid key (exp >= now + 3600 seconds)
    This ensures both authentication paths can be tested.
    """
    now = int(time.time())
    insert_key(private_key_to_pem_pkcs1(generate_rsa_private_key()), now - 10)
    insert_key(private_key_to_pem_pkcs1(generate_rsa_private_key()), now + 3600)

def test_auth_valid_token():
    """
    Test issuing a valid (non-expired) JWT.
    - Calls issue_token(expired=False)
    - Ensures HTTP-like status code = 200
    - Verifies returned token is a valid JWT string
    - Confirms token header includes a 'kid' (key ID)
    """
    token, meta, code = issue_token(expired=False)
    assert code == 200
    assert token and isinstance(token, str)
    header = jwt.get_unverified_header(token)
    assert "kid" in header

def test_auth_expired_token():
    """
    Test issuing a JWT signed with an expired key.
    - Calls issue_token(expired=True)
    - Ensures status code = 200
    - Verifies token header includes 'kid'
    This ensures the /auth?expired=1 route is functioning correctly.
    """
    token, meta, code = issue_token(expired=True)
    assert code == 200
    header = jwt.get_unverified_header(token)
    assert "kid" in header
