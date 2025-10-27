# extending-the-jwks-server
Project 2 Assignment_Phuong Luu_tl0489
# JWKS Server with SQLite — Project 2 (CSCE 3550)

This project extends the basic JSON Web Key Set (JWKS) server by adding **SQLite persistence** for RSA private keys.  
It demonstrates secure database usage, JWT signing, and RESTful key serving — while maintaining protection against SQL injection.

---

## 🎯 Objective

- Use **SQLite** (`totally_not_my_privateKeys.db`) to persist RSA private keys.
- Ensure keys remain available across server restarts.
- Implement secure, parameterized queries (no string concatenation).
- Expose two REST endpoints:
  - `POST /auth` — issues a valid JWT.
  - `POST /auth?expired` — issues a JWT signed with an expired key.
  - `GET /.well-known/jwks.json` — returns public JWKS of all valid keys.

---

## 🧩 Project Structure

