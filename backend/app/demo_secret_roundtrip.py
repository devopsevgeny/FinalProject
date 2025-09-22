# backend/app/demo_secret_roundtrip.py
import os
import json
import uuid
import secrets
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import psycopg
from psycopg.rows import dict_row

# --- 1) Load AES-256-GCM key from env ---
DATA_KEY_HEX = os.getenv("DATA_KEY_HEX")
if not DATA_KEY_HEX or len(DATA_KEY_HEX) != 64:
    raise RuntimeError("DATA_KEY_HEX must be 32 bytes in hex (64 hex chars)")
KEY = bytes.fromhex(DATA_KEY_HEX)
AE = AESGCM(KEY)

# --- 2) Connection parameters from env (same as backend service) ---
CONN_KW = dict(
    host=os.getenv("PGHOST", "postgres"),
    dbname=os.getenv("PGDATABASE", "postgres"),
    user=os.getenv("PGUSER", "confmgr_db"),
    sslmode=os.getenv("PGSSLMODE", "verify-full"),
    sslrootcert=os.getenv("PGSSLROOTCERT"),
    sslcert=os.getenv("PGSSLCERT"),
    sslkey=os.getenv("PGSSLKEY"),
    connect_timeout=5,
)

# --- 3) Example secret payload ---
PATH = "app/prod/jwt"
VALUE = {"jwt_secret": "super-strong", "ttl": 3600}
CREATED_BY = uuid.UUID("11111111-1111-1111-1111-111111111111")

def ensure_item_and_next_version(cur, path: str):
    """Ensure secret_items entry exists and return (item_id, next_version)."""
    cur.execute(
        "insert into core.secret_items(path, created_by) values (%s, %s) "
        "on conflict(path) do nothing",
        (path, CREATED_BY),
    )
    cur.execute("select id from core.secret_items where path=%s", (path,))
    item_id = cur.fetchone()["id"]

    cur.execute(
        "select coalesce(max(version),0)+1 as next_ver "
        "from core.secret_versions where item_id=%s",
        (item_id,),
    )
    next_ver = cur.fetchone()["next_ver"]
    return item_id, next_ver

def encrypt_secret(plaintext_json: dict, aad: bytes):
    """Encrypt JSON payload with AES-GCM and return (nonce, ciphertext)."""
    plaintext = json.dumps(plaintext_json, separators=(",", ":"), sort_keys=True).encode()
    nonce = secrets.token_bytes(12)              # 96-bit nonce for AES-GCM
    ciphertext = AE.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

def decrypt_secret(nonce: bytes, ciphertext: bytes, aad: bytes) -> dict:
    """Decrypt ciphertext with AES-GCM and return JSON payload."""
    pt = AE.decrypt(nonce, ciphertext, aad)
    return json.loads(pt.decode())

def main():
    with psycopg.connect(**CONN_KW, autocommit=True) as conn, conn.cursor(row_factory=dict_row) as cur:
        # Prepare item and compute next version
        item_id, version = ensure_item_and_next_version(cur, PATH)

        # Additional Authenticated Data (AAD) binds ciphertext to item+version
        aad = f"{PATH}|{version}".encode()

        # Encrypt payload
        nonce, ciphertext = encrypt_secret(VALUE, aad)

        # Insert new version into DB
        cur.execute(
            """
            insert into core.secret_versions(item_id, version, is_current, ciphertext, nonce, alg, created_by)
            values (%s, %s, true, %s, %s, 'AES256-GCM', %s)
            """,
            (item_id, version, ciphertext, nonce, CREATED_BY),
        )
        print(f"Inserted version {version} for {PATH}")

        # Read it back
        cur.execute(
            "select version, ciphertext, nonce from core.secret_versions "
            "where item_id=%s and version=%s",
            (item_id, version),
        )
        row = cur.fetchone()
        restored = decrypt_secret(row["nonce"], row["ciphertext"], aad)
        print("Decrypted payload:", restored)

if __name__ == "__main__":
    main()

