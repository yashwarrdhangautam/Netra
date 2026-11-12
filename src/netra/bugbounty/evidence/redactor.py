"""Streaming-friendly evidence redaction helpers."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RedactionHit:
    """A redaction hit without the secret value."""

    rule_id: str
    replacement: str
    start_offset: int
    end_offset: int


_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)\baws(.{0,20})?(secret|access)[-_ ]?key['\"\s:=]+[A-Za-z0-9/+=]{32,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]


def redact_text(text: str) -> tuple[str, list[RedactionHit]]:
    """Redact sensitive strings, returning redacted text and audit hits."""
    hits: list[RedactionHit] = []
    redacted = text
    for rule_id, pattern in _RULES:
        counter = 0

        def repl(match: re.Match[str]) -> str:
            nonlocal counter
            replacement = f"[REDACTED:{rule_id}:{counter}]"
            hits.append(
                RedactionHit(
                    rule_id=rule_id,
                    replacement=replacement,
                    start_offset=match.start(),
                    end_offset=match.end(),
                )
            )
            counter += 1
            return replacement

        redacted = pattern.sub(repl, redacted)
    return redacted, hits


def redact_bytes(data: bytes) -> tuple[bytes, list[RedactionHit]]:
    """Redact bytes as UTF-8 text, preserving binary-ish inputs as replacement-safe text."""
    text = data.decode("utf-8", errors="replace")
    redacted, hits = redact_text(text)
    return redacted.encode("utf-8"), hits

