"""Encrypt settings values at rest with a key derived from the JWT secret.

The derived key is stable for a deployment. Changing NETRA_JWT_SECRET_KEY makes
stored values unreadable, so re-enter the integration keys after rotating it.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from netra.core.config import settings


def _fernet() -> Fernet:
    digest = hashlib.sha256(b"netra-settings:" + settings.jwt_secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_value(plain: str) -> str:
    return _fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_value(token: str) -> str | None:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        return None


def mask(value: str) -> str:
    """Show only the last four characters, so the operator can recognise the key."""
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]
