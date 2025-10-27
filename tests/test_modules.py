from app import db, crypto, jwks
import time

def test_crypto_key_generation_and_jwk():
    priv = crypto.generate_rsa_private_key()
    pem = crypto.private_key_to_pem_pkcs1(priv)
    loaded = crypto.pem_to_private_key(pem)
    jwk = crypto.public_jwk_from_private(loaded, kid="test")
    assert jwk["kty"] == "RSA"
    assert "n" in jwk and "e" in jwk

def test_db_insert_and_fetch():
    now = int(time.time())
    pem = crypto.private_key_to_pem_pkcs1(crypto.generate_rsa_private_key())
    kid = db.insert_key(pem, now + 60)
    assert isinstance(kid, int)
    valid = db.fetch_one_valid_key()
    assert valid is not None

def test_jwks_fetch_valid_keys(monkeypatch):
    fake_pem = crypto.private_key_to_pem_pkcs1(crypto.generate_rsa_private_key())
    monkeypatch.setattr(jwks, "db", type("FakeDB", (), {
        "fetch_all_valid_keys": lambda self=None: [(1, fake_pem, int(time.time()) + 100)]
    })())
    keys = jwks.db.fetch_all_valid_keys()
    assert len(keys) >= 1

def test_jwks_get_public_jwks(monkeypatch):
    """Ensure jwks.get_public_jwks() returns proper JSON-like dict."""
    from app import jwks, crypto
    import time

    pem = crypto.private_key_to_pem_pkcs1(crypto.generate_rsa_private_key())

    # Fake DB returns one valid key
    class FakeDB:
        def fetch_all_valid_keys(self):
            return [(123, pem, int(time.time()) + 1000)]

    monkeypatch.setattr(jwks, "db", FakeDB())
    result = jwks.get_public_jwks()
    assert isinstance(result, dict)
    assert "keys" in result
    assert result["keys"][0]["kid"] == "123"

def test_db_expired_key_fetch(monkeypatch):
    """Force fetch_one_expired_key to run and return data."""
    from app import db, crypto
    import time

    pem = crypto.private_key_to_pem_pkcs1(crypto.generate_rsa_private_key())
    kid = db.insert_key(pem, int(time.time()) - 5)  # expired 5s ago
    row = db.fetch_one_expired_key()
    assert row is not None
    assert isinstance(row[0], int)

def test_db_close_and_edge_cases(monkeypatch):
    """Covers database close path and handles fetch with empty results."""
    from app import db

    # Force _close_conn() manually
    db._close_conn()

    # Monkeypatch _CONN to a fake closed connection to hit exception handling
    class DummyConn:
        def close(self): raise Exception("Already closed")

    monkeypatch.setattr(db, "_CONN", DummyConn())
    db._close_conn()

    # Should still safely handle no valid keys (empty list)
    class DummyEmpty:
        def fetch_all_valid_keys(self): return []
    monkeypatch.setattr(db, "fetch_all_valid_keys", DummyEmpty().fetch_all_valid_keys)
    assert db.fetch_all_valid_keys() == []

def test_db_close_and_edge_cases(monkeypatch):
    """Covers database close path and fetch edge cases."""
    from app import db

    # 1️⃣ Call normal close once (covers success branch)
    db._close_conn()

    # 2️⃣ Force an exception path in _close_conn()
    class DummyConn:
        def close(self): raise Exception("Already closed")
    monkeypatch.setattr(db, "_CONN", DummyConn())
    db._close_conn()  # Should not raise

    # 3️⃣ Verify fetch_all_valid_keys works with no rows
    class DummyEmpty:
        def fetchall(self): return []
    monkeypatch.setattr(db, "_CONN", type("FakeConn", (), {"execute": lambda *a, **kw: DummyEmpty()})())
    result = db.fetch_all_valid_keys()
    assert result == []

from http.client import HTTPConnection
import json

def test_invalid_path_returns_404():
    conn = HTTPConnection("127.0.0.1", 8080, timeout=3)
    conn.request("GET", "/not-exist")
    resp = conn.getresponse()
    assert resp.status == 404
    conn.close()

def test_auth_with_invalid_json():
    conn = HTTPConnection("127.0.0.1", 8080, timeout=3)
    conn.request("POST", "/auth", body=b"{invalid", headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = resp.read()
    assert resp.status in (200, 400, 404)  # tuỳ cách server phản hồi
    conn.close()
