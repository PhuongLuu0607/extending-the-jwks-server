import requests

BASE = "http://127.0.0.1:8080"

def test_auth_valid_token():
    r = requests.post(f"{BASE}/auth")
    assert r.status_code == 200
    assert "token" in r.json()

def test_auth_expired_token():
    r = requests.post(f"{BASE}/auth?expired=1")
    assert r.status_code == 200
    assert "token" in r.json()
