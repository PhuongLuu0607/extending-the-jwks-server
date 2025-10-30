# config.py
# ---------------------------------------------
# This module defines global configuration settings
# for the JWKS SQLite server. It uses Python's dataclass
# to store constants such as server host, port, database
# path, and JWT configuration parameters.
# ---------------------------------------------
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
     # Host address for the HTTP server (0.0.0.0 allows all network interfaces)
    host: str = "0.0.0.0"
    port: int = 8080 # Port number for the server to listen on
    db_path: str = "totally_not_my_privateKeys.db" # Path to the SQLite database file where private keys are stored
    jwt_iss: str = "jwks-sqlite-demo" # JWT "iss" (issuer) claim identifying the token issuer
    jwt_aud: str = "example-aud" # JWT "aud" (audience) claim identifying the intended recipient of the token

settings = Settings() # Create a single, global Settings instance that can be imported elsewhere
