# backend/app/crypto.py
"""Cryptographic utilities (AES-256-GCM) used for at-rest encryption of secrets.

Public API:
- seal(plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]
- open_sealed(nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes

Key material:
- Uses 256-bit data key from env var DATA_KEY_HEX (64 hex chars).
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_DATA_KEY_ENV = "DATA_KEY_HEX"
_NONCE_LEN = 12  # 96-bit nonce required by AES-GCM


def _parse_key_hex(key_hex: str | None) -> bytes:
    """Validate and decode DATA_KEY_HEX (must be 32 bytes => 64 hex chars)."""
    if not key_hex:
        raise RuntimeError(
            f"{_DATA_KEY_ENV} must be set to a 32-byte key in hex (64 hex characters)."
        )
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise RuntimeError(f"{_DATA_KEY_ENV} must be valid hex.") from exc
    if len(key) != 32:
        raise RuntimeError(f"{_DATA_KEY_ENV} must decode to exactly 32 bytes (got {len(key)}).")
    return key


@lru_cache(maxsize=8)
def _aesgcm_for_key(key_hex: str) -> AESGCM:
    """Return AESGCM instance for a given hex key (cached)."""
    key = _parse_key_hex(key_hex)
    return AESGCM(key)


def _get_aesgcm() -> AESGCM:
    """Resolve DATA_KEY_HEX and return cached AESGCM instance."""
    key_hex = os.getenv(_DATA_KEY_ENV)
    return _aesgcm_for_key(key_hex or "")


def random_bytes(n: int) -> bytes:
    """Return n cryptographically secure random bytes."""
    if n <= 0:
        raise ValueError("n must be positive")
    return secrets.token_bytes(n)


def seal(plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM and return (nonce, ciphertext)."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    nonce = secrets.token_bytes(_NONCE_LEN)
    aesgcm = _get_aesgcm()
    ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), aad)
    return nonce, ciphertext


def open_sealed(nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt AES-256-GCM ciphertext; raise ValueError on auth failure."""
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != _NONCE_LEN:
        raise ValueError("nonce must be 12 bytes")
    if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) == 0:
        raise ValueError("ciphertext must be non-empty bytes")
    aesgcm = _get_aesgcm()
    try:
        return aesgcm.decrypt(bytes(nonce), bytes(ciphertext), aad)
    except Exception as exc:  # cryptography raises InvalidTag on auth failure
        raise ValueError("decryption failed") from exc


__all__ = ["seal", "open_sealed", "random_bytes"]
