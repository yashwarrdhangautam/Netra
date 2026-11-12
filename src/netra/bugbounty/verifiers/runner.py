"""Read-only verifier/replay runner."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from netra.bugbounty.evidence.pipeline import read_evidence_blob
from netra.bugbounty.scope import ScopeValidator
from netra.bugbounty.verifiers.loader import VerifierSpec, find_verifier
from netra.db.models.bb_evidence import BBEvidence


def parse_captured_request(evidence: BBEvidence) -> dict[str, Any]:
    """Extract a captured request from redacted evidence."""
    blob = read_evidence_blob(evidence)
    text = blob.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict):
        # Non-object JSON (scalars, arrays) and non-JSON text are both treated as raw text.
        data = evidence.metadata_ or {}
        data.setdefault("raw", text)
    request = data.get("request") if isinstance(data.get("request"), dict) else data
    return {
        "method": str(request.get("method", "GET")).upper(),
        "url": request.get("url") or request.get("target"),
        "headers": request.get("headers") if isinstance(request.get("headers"), dict) else {},
        "original_status": request.get("status_code") or data.get("status_code"),
        "original_body": request.get("body") or data.get("body") or "",
    }


async def run_replay(
    evidence: BBEvidence,
    spec: VerifierSpec,
    validator: ScopeValidator,
    *,
    vuln_class: str | None,
) -> dict[str, Any]:
    """Replay an allowlisted read-only request after a scope check.

    The spec must be the one the allowlist holds for this finding's vuln_class.
    Caller-supplied specs that are not on the allowlist are refused here, not only in routes.
    """
    if not vuln_class or find_verifier(spec.id, vuln_class) is None:
        return {"status": "blocked", "error": f"Verifier {spec.id} is not allowlisted for this finding"}
    request = parse_captured_request(evidence)
    method = request["method"]
    url = request["url"]
    if not url:
        return {"status": "failed", "error": "Evidence does not contain a replayable URL"}
    if method not in spec.methods or method not in {"GET", "HEAD"}:
        return {"status": "blocked", "error": f"Verifier {spec.id} does not allow {method}"}

    decision = validator.require(str(url))
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
            response = await client.request(method, str(url), headers=request["headers"])
    except Exception as exc:
        return {"status": "failed", "error": str(exc), "scope": decision.reason}

    latency_ms = int((time.perf_counter() - start) * 1000)
    original_status = request.get("original_status")
    original_body = str(request.get("original_body") or "")
    body = response.text if method == "GET" else ""
    return {
        "status": "completed",
        "status_code": response.status_code,
        "latency_ms": latency_ms,
        "scope": decision.reason,
        "diff": {
            "status_changed": bool(
                original_status and int(original_status) != response.status_code
            ),
            "original_status": original_status,
            "current_status": response.status_code,
            "body_length_delta": len(body) - len(original_body),
            "headers": dict(response.headers),
        },
    }
