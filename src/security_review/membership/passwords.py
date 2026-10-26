"""Versioned scrypt password verifiers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets

_N = 2**15
_R = 8
_P = 3
_KEY_BYTES = 32
_SALT_BYTES = 16
_MAXMEM = 128 * 1024 * 1024


def hash_password(password: str) -> str:
    """Return a salted scrypt verifier for a policy-compliant password."""

    if not isinstance(password, str):
        raise ValueError("password must be text")
    try:
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("password must be valid UTF-8 text") from exc
    if not 12 <= len(password_bytes) <= 1024:
        raise ValueError("password length is outside policy")
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(
        password_bytes,
        salt=salt,
        n=_N,
        r=_R,
        p=_P,
        dklen=_KEY_BYTES,
        maxmem=_MAXMEM,
    )
    return "scrypt$1$32768$8$3$" + _b64(salt) + "$" + _b64(derived)


def verify_password(password: str, encoded: str) -> bool:
    """Verify a version 1 verifier; malformed inputs fail closed."""

    try:
        if not isinstance(password, str) or not isinstance(encoded, str):
            return False
        parts = encoded.split("$")
        if len(parts) != 7 or parts[:5] != ["scrypt", "1", "32768", "8", "3"]:
            return False
        salt = _unb64(parts[5])
        expected = _unb64(parts[6])
        if len(salt) != _SALT_BYTES or len(expected) != _KEY_BYTES:
            return False
        if len(password) > 1024:
            return False
        password_bytes = password.encode("utf-8")
        if not 12 <= len(password_bytes) <= 1024:
            return False
        actual = hashlib.scrypt(
            password_bytes,
            salt=salt,
            n=_N,
            r=_R,
            p=_P,
            dklen=_KEY_BYTES,
            maxmem=_MAXMEM,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, UnicodeEncodeError, MemoryError, OSError, binascii.Error):
        return False


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)
