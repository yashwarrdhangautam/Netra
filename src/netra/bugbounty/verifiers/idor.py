"""Non-destructive IDOR (broken object-level authorization) verifier.

Proves an IDOR by *reading* one principal's object with another principal's
credentials, never by writing. The check is read-only by construction: only
GET/HEAD are permitted and the URL is scope-gated before any request is made.
A positive result is a reproducible, submission-ready proof of cross-principal
data access.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

# transport(method, url, headers) -> (status_code, body_text)
Transport = Callable[[str, str, dict[str, str]], Awaitable[tuple[int, str]]]
# scope_check(url) -> True when the URL is in scope / allowed to touch
ScopeCheck = Callable[[str], bool]

_READ_ONLY_METHODS = {"GET", "HEAD"}


class IdorVerificationError(RuntimeError):
    """Raised when a verification request would be unsafe or is out of scope."""


@dataclass
class IdorResult:
    confirmed: bool
    status_code: int | None
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed": self.confirmed,
            "status_code": self.status_code,
            "rationale": self.rationale,
            "evidence": self.evidence,
        }


async def verify_idor(
    *,
    method: str,
    url: str,
    attacker_headers: dict[str, str],
    owner_marker: str,
    transport: Transport,
    scope_check: ScopeCheck,
    success_statuses: tuple[int, ...] = (200,),
) -> IdorResult:
    """Attempt to read a victim's object with the attacker's credentials.

    IDOR is confirmed only when the attacker's read succeeds AND the response
    body carries ``owner_marker`` -- an identifier belonging to the victim, not
    the attacker -- i.e. genuine cross-principal data exposure. The method is
    restricted to GET/HEAD so the verification cannot modify state.
    """
    normalized = (method or "").upper()
    if normalized not in _READ_ONLY_METHODS:
        raise IdorVerificationError(
            f"Refusing {normalized or 'empty'} request: IDOR verification is read-only (GET/HEAD)"
        )
    if not owner_marker:
        raise IdorVerificationError("owner_marker is required to prove cross-principal access")
    if not scope_check(url):
        raise IdorVerificationError(f"Target is out of scope: {url}")

    status, body = await transport(normalized, url, dict(attacker_headers or {}))
    accessible = status in success_statuses
    leaked = accessible and owner_marker in (body or "")
    if leaked:
        rationale = (
            f"Attacker credentials read status {status} and the response contained the victim "
            f"identifier ({owner_marker!r}): cross-principal object access confirmed."
        )
    elif accessible:
        rationale = (
            f"Attacker read status {status} but the victim identifier was absent; "
            "no cross-principal exposure proven."
        )
    else:
        rationale = f"Attacker read was denied (status {status}); access control held."
    return IdorResult(
        confirmed=leaked,
        status_code=status,
        rationale=rationale,
        evidence={
            "method": normalized,
            "url": url,
            "status": status,
            "owner_marker_present": leaked,
        },
    )
