import os, base64, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 32 байта (256 бит) в hex. Пример: openssl rand -hex 32
MASTER_KEY_HEX = os.getenv("DATA_KEY_HEX")
if not MASTER_KEY_HEX:
    raise RuntimeError("DATA_KEY_HEX is not set (32-byte hex key required)")

_MASTER = AESGCM(bytes.fromhex(MASTER_KEY_HEX))

def seal(plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    ct = _MASTER.encrypt(nonce, plaintext, aad)
    return nonce, ct

def open_sealed(nonce: bytes, ct: bytes, aad: bytes | None = None) -> bytes:
    return _MASTER.decrypt(nonce, ct, aad)

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))
