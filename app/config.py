"""Application configuration module."""

import os

class Settings:
    """Global configuration for DB and server."""

    # Database file path
    db_path: str = os.path.join(os.getcwd(), "totally_not_my_privateKeys.db")

    # HTTP server config
    host: str = "0.0.0.0"
    port: int = 8080

settings = Settings()

