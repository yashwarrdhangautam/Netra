"""Static guardrail for generated PoCs."""
from __future__ import annotations


FORBIDDEN_KEYWORDS = ("DELETE ", "PATCH ", "PUT ", "\nDELETE ", "\nPATCH ", "\nPUT ")


def is_safe_poc(text: str, *, allow_post: bool = False) -> bool:
    upper = text.upper()
    if any(token in upper for token in FORBIDDEN_KEYWORDS):
        return False
    if not allow_post and ("POST " in upper or "\nPOST " in upper):
        return False
    return True
