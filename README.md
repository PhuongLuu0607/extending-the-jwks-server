# Extending the JWKS Server  
**Project 2 – Foundations of Cybersecurity (CSCE 3550)**  
**Student:** Phuong Luu (tl0489)

---

## 📘 Overview
This project extends the **basic JSON Web Key Set (JWKS) server** by integrating an **SQLite** database to securely store and manage RSA private keys.  
It demonstrates secure key persistence, JWT signing, and RESTful key retrieval — while protecting against SQL injection through parameterized queries.

---

## 🎯 Objectives
- Use **SQLite** (`totally_not_my_privateKeys.db`) to persist RSA private keys.  
- Ensure keys survive server restarts.  
- Implement **secure, parameterized SQL queries** using `?` placeholders.  
- Provide two key REST endpoints:
  - `POST /auth` → issues a JWT signed with a valid (unexpired) key.  
  - `POST /auth?expired=1` → issues a JWT signed with an expired key (for grading).  
  - `GET /.well-known/jwks.json` → returns a JWKS document containing all **non-expired** public keys.

---

## 🧩 Project Structure

project2/
└─ py3/
├─ main.py # Entry point – runs HTTP server
├─ README.md # Project documentation
├─ pyproject.toml # Pytest configuration
├─ requirements.txt # Dependencies list
├─ totally_not_my_privateKeys.db # SQLite database (auto-created)
├─ app/
│ ├─ init.py
│ ├─ auth.py # JWT issuing logic
│ ├─ config.py # Global configuration settings
│ ├─ crypto.py # RSA key generation & JWK conversion
│ ├─ db.py # SQLite connection & queries
│ └─ jwks.py # JWKS builder
└─ tests/
├─ test_auth.py # Tests /auth endpoints
├─ test_jwks.py # Tests JWKS generation
└─ test_modules.py # Tests crypto + database modules

## ⚙️ Installation & Setup

### Create and activate virtual environment
```bash
cd project2/py3
python3 -m venv .venv
source .venv/bin/activate
```
### Install dependencies
pip install -r requirements.txt

### Running the Server
python main.py
```
The server will start on http://0.0.0.0:8080
 and automatically create
totally_not_my_privateKeys.db with one expired and one valid key.
```
### Manual Testing (curl commands)
# Health check
curl -s http://127.0.0.1:8080/health | jq

# JWT signed with a valid key
curl -s -X POST "http://127.0.0.1:8080/auth" | jq

# JWT signed with an expired key
curl -s -X POST "http://127.0.0.1:8080/auth?expired=1" | jq

# JWKS – shows only non-expired public keys
curl -s "http://127.0.0.1:8080/.well-known/jwks.json" | jq

### Testing with Pytest
python -m pytest -q --cov=app --cov-report=term-missing

### Gradebot Testing
cd ~/Desktop/CSCE3550_Darwin_arm64
./gradebot project2 \
  --database-file ~/Desktop/CSCE3550/project2/py3/totally_not_my_privateKeys.db \
  --code-dir ~/Desktop/CSCE3550/project2/py3

