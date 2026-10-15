import base64
import os

import pytest

from app.crypto import DecryptionError, TokenCipher


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def test_roundtrip():
    c = TokenCipher(f"k1:{_key()}")
    assert c.decrypt(c.encrypt("1//refresh", "conn:a:refresh"), "conn:a:refresh") == "1//refresh"


def test_ciphertext_bound_to_its_row():
    c = TokenCipher(f"k1:{_key()}")
    blob = c.encrypt("1//refresh", "conn:a:refresh")
    with pytest.raises(DecryptionError):
        c.decrypt(blob, "conn:b:refresh")


def test_key_rotation_old_rows_still_decrypt():
    old_key, new_key = _key(), _key()
    old = TokenCipher(f"k1:{old_key}")
    blob = old.encrypt("secret", "aad")
    rotated = TokenCipher(f"k2:{new_key},k1:{old_key}")
    assert rotated.decrypt(blob, "aad") == "secret"
    assert rotated.needs_rotation(blob)
    assert rotated.encrypt("secret", "aad").startswith("v1.k2.")


def test_tampering_detected():
    c = TokenCipher(f"k1:{_key()}")
    blob = c.encrypt("secret", "aad")
    tampered = blob[:-2] + ("A" if blob[-2] != "A" else "B") + blob[-1]
    with pytest.raises(DecryptionError):
        c.decrypt(tampered, "aad")


def test_rejects_short_key():
    with pytest.raises(ValueError):
        TokenCipher("k1:" + base64.urlsafe_b64encode(os.urandom(16)).decode())
