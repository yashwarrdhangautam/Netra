"""Evidence encryption helpers."""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet

from netra.core.config import settings

DEFAULT_JWT_SECRET = "CHANGE-ME-IN-PRODUCTION"


def _fernet_key() -> bytes:
    """Resolve the evidence encryption key. Fails closed rather than using a guessable key."""
    raw = os.getenv("NETRA_EVIDENCE_KEY")
    if raw:
        try:
            return raw.encode("ascii")
        except UnicodeEncodeError as exc:
            raise RuntimeError("NETRA_EVIDENCE_KEY must be an ASCII Fernet key") from exc
    if settings.jwt_secret_key == DEFAULT_JWT_SECRET:
        raise RuntimeError(
            "Set NETRA_EVIDENCE_KEY (or change jwt_secret_key) before storing evidence; "
            "refusing to derive the key from the default secret."
        )
    digest = hashlib.sha256(settings.jwt_secret_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt(data: bytes) -> bytes:
    """Encrypt redacted evidence bytes."""
    return Fernet(_fernet_key()).encrypt(data)


def decrypt(data: bytes) -> bytes:
    """Decrypt evidence bytes."""
    return Fernet(_fernet_key()).decrypt(data)
