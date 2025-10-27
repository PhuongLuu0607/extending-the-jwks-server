from __future__ import annotations
import sqlite3
import time
from typing import Optional, Tuple, List
from .config import settings
import atexit

# --- Table schema ---
SCHEMA = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
"""

# --- Database connection helper ---
def _connect():
    # isolation_level=None = autocommit mode (still safe for simple operations)
    conn = sqlite3.connect(settings.db_path, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

# --- Global shared connection ---
_CONN = _connect()
_CONN.execute(SCHEMA)

# --- CRUD functions ---
def insert_key(pem_bytes: bytes, exp_ts: int) -> int:
    """Insert a new private key (PEM) with expiration timestamp into the database."""
    cur = _CONN.execute("INSERT INTO keys(key, exp) VALUES(?, ?)", (pem_bytes, exp_ts))
    _CONN.commit()  # ✅ ensure data is written to disk
    return cur.lastrowid

def now_ts() -> int:
    """Return current timestamp (Unix seconds)."""
    return int(time.time())

def fetch_one_valid_key() -> Optional[Tuple[int, bytes, int]]:
    """Fetch the first valid (non-expired) key."""
    cur = _CONN.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
        (now_ts(),),
    )
    return cur.fetchone()

def fetch_one_expired_key() -> Optional[Tuple[int, bytes, int]]:
    """Fetch the most recently expired key."""
    cur = _CONN.execute(
        "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
        (now_ts(),),
    )
    return cur.fetchone()

def fetch_all_valid_keys() -> List[Tuple[int, bytes, int]]:
    """Fetch all valid (non-expired) keys for JWKS endpoint."""
    cur = _CONN.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC",
        (now_ts(),),
    )
    return cur.fetchall()

@atexit.register
def _close_conn():
    """Close the global SQLite connection cleanly at program exit."""
    try:
        _CONN.close()
        print("[DB] Connection closed cleanly ✅")
    except Exception:
        pass
