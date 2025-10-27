import os

class Settings:
    def __init__(self):
        # Đường dẫn tới database SQLite
        self.db_path = os.getenv("DB_PATH", "totally_not_my_privateKeys.db")

settings = Settings()
