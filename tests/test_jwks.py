import requests

BASE = "http://127.0.0.1:8080"

def test_jwks_has_valid_key():
    r = requests.get(f"{BASE}/.well-known/jwks.json")
    assert r.status_code == 200
    body = r.json()
    assert "keys" in body and isinstance(body["keys"], list)
    assert len(body["keys"]) >= 1
    k = body["keys"][0]
    for f in ["kty","alg","use","kid","n","e"]:
        assert f in k
