"""Static side-effect classification for generated requests."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SideEffectClass(StrEnum):
    PASSIVE = "passive"
    ACTIVE_READONLY = "active_readonly"
    ACTIVE_INTRUSIVE = "active_intrusive"
    FORBIDDEN = "forbidden"


@dataclass(frozen=True)
class SideEffectVerdict:
    verdict: SideEffectClass
    reason: str


def check(http_request: str) -> SideEffectVerdict:
    upper = http_request.upper()
    first_line = upper.splitlines()[0] if upper.splitlines() else upper
    if any(token in upper for token in ("X-HTTP-METHOD-OVERRIDE", " DELETE ", "\nDELETE ", " PATCH ", "\nPATCH ")):
        return SideEffectVerdict(SideEffectClass.FORBIDDEN, "destructive override or verb")
    if first_line.startswith(("DELETE ", "PATCH ", "PUT ")):
        return SideEffectVerdict(SideEffectClass.FORBIDDEN, "destructive verb")
    if first_line.startswith("POST "):
        if "/ADMIN/" in upper or "CONTENT-TYPE: APPLICATION/X-WWW-FORM-URLENCODED" in upper:
            return SideEffectVerdict(SideEffectClass.FORBIDDEN, "state-mutating post")
        return SideEffectVerdict(SideEffectClass.ACTIVE_INTRUSIVE, "post request")
    if first_line.startswith(("GET ", "HEAD ", "OPTIONS ")):
        return SideEffectVerdict(SideEffectClass.PASSIVE, "read-only verb")
    return SideEffectVerdict(SideEffectClass.ACTIVE_READONLY, "unclassified request")
