from __future__ import annotations
import sqlite3
import time
from typing import Optional, Tuple, List
from .config import settings
import os

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
"""

def _connect():
    # Ensure DB folder exists (if path includes dirs)
    db_dir = os.path.dirname(os.path.abspath(settings.db_path))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(settings.db_path, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

_CONN = _connect()
_CONN.execute(SCHEMA)

def insert_key(pem_bytes: bytes, exp_ts: int) -> int:
    """Insert a private key (PEM bytes) and expiration timestamp. Returns kid."""
    cur = _CONN.execute("INSERT INTO keys(key, exp) VALUES(?, ?)", (pem_bytes, exp_ts))
    return cur.lastrowid

def fetch_one_key(expired: bool) -> Optional[Tuple[int, bytes, int]]:
    """
    Fetch one key row.
    - If expired == True: return an expired key (exp <= now), latest expired (desc).
    - If expired == False: return a valid key (exp > now), earliest valid (asc).
    """
    now = int(time.time())
    if expired:
        q = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1"
        row = _CONN.execute(q, (now,)).fetchone()
    else:
        q = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1"
        row = _CONN.execute(q, (now,)).fetchone()
    return row

def fetch_all_valid_keys() -> List[Tuple[int, bytes, int]]:
    """Return all rows for keys with exp > now."""
    now = int(time.time())
    q = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid ASC"
    return list(_CONN.execute(q, (now,)).fetchall())
