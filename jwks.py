from app import db, crypto


def get_public_jwks():
    """Return JWKS of all valid (non-expired) keys from database."""
    keys = []
    for kid, pem, _exp in db.fetch_all_valid_keys():
        priv = crypto.pem_to_private_key(pem)
        keys.append(crypto.public_jwk_from_private(priv, kid=str(kid)))
    return {"keys": keys}


# Provide a direct alias so tests expecting jwks.public_jwk_from_private() still work
public_jwk_from_private = crypto.public_jwk_from_private
