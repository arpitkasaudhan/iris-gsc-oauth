"""AES-256-GCM envelope for OAuth tokens at rest.

Ciphertext format: ``v1.<kid>.<base64url(nonce || ciphertext+tag)>``

* The key id travels with the ciphertext, so keys can be rotated without a
  big-bang migration: prepend a new key, old rows still decrypt, and a
  background job can re-encrypt at leisure.
* Every ciphertext is bound to its row via AAD (e.g. ``conn:<id>:refresh``).
  Copying an encrypted refresh token into another user's row makes decryption
  fail instead of silently handing that user someone else's Google access.
"""

import base64
import os
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings

_VERSION = "v1"


class DecryptionError(Exception):
    pass


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


class TokenCipher:
    def __init__(self, keyring: str):
        self._keys: dict[str, AESGCM] = {}
        self._primary: str | None = None
        for entry in filter(None, (e.strip() for e in keyring.split(","))):
            kid, _, raw = entry.partition(":")
            key = _b64d(raw)
            if len(key) != 32:
                raise ValueError(f"key {kid!r} must be 32 bytes for AES-256-GCM")
            self._keys[kid] = AESGCM(key)
            self._primary = self._primary or kid
        if not self._primary:
            raise ValueError("TOKEN_ENCRYPTION_KEYS is empty")

    def encrypt(self, plaintext: str, aad: str) -> str:
        nonce = os.urandom(12)
        ct = self._keys[self._primary].encrypt(nonce, plaintext.encode(), aad.encode())
        return f"{_VERSION}.{self._primary}.{_b64e(nonce + ct)}"

    def decrypt(self, token: str, aad: str) -> str:
        try:
            version, kid, payload = token.split(".", 2)
            if version != _VERSION:
                raise DecryptionError(f"unknown ciphertext version {version}")
            blob = _b64d(payload)
            return self._keys[kid].decrypt(blob[:12], blob[12:], aad.encode()).decode()
        except (ValueError, KeyError, InvalidTag) as exc:
            raise DecryptionError("token could not be decrypted") from exc

    def needs_rotation(self, token: str) -> bool:
        return token.split(".", 2)[1] != self._primary


@lru_cache
def get_cipher() -> TokenCipher:
    return TokenCipher(get_settings().token_encryption_keys)
