"""Deduplication — fingerprint a finding and check it against past submissions.

The signature is sha256 of (vuln_class | normalised_path | param_name). It's
deterministic — the same finding shape always produces the same signature.

When Graphify is wired in (graph_indexer.py), the deduper will additionally query
the graph for 'similar' (not just identical) prior findings on the same asset.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.bb_dedup_signature import BBDedupSignature

logger = structlog.get_logger()


@dataclass(frozen=True)
class DedupFingerprint:
    """The fingerprint a finding gets reduced to, before hashing."""

    vuln_class: str
    normalised_path: str
    param_name: str

    def hash(self) -> str:
        joined = f"{self.vuln_class}|{self.normalised_path}|{self.param_name}".lower()
        return hashlib.sha256(joined.encode()).hexdigest()


_NUMERIC_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


def normalise_path(path: str) -> str:
    """Collapse numeric IDs and UUIDs in path segments.

    Examples:
        /users/12345/orders     → /users/{id}/orders
        /a/3fa85f64-...-2c963f66afa6 → /a/{uuid}
    """
    if not path:
        return "/"
    p = path.strip().lower()
    p = _UUID_RE.sub("{uuid}", p)
    p = _NUMERIC_SEGMENT_RE.sub("/{id}", p)
    return p


def fingerprint(vuln_class: str, path: str, param_name: str = "") -> DedupFingerprint:
    """Build a fingerprint from raw inputs."""
    return DedupFingerprint(
        vuln_class=vuln_class.strip().lower(),
        normalised_path=normalise_path(path),
        param_name=(param_name or "").strip().lower(),
    )


async def is_duplicate(
    session: AsyncSession,
    program_id,
    fp: DedupFingerprint,
) -> BBDedupSignature | None:
    """Return the prior signature row if this fingerprint has been seen on this program."""
    h = fp.hash()
    stmt = select(BBDedupSignature).where(
        BBDedupSignature.program_id == program_id,
        BBDedupSignature.signature_hash == h,
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


def find_graph_similar(
    program_id,
    asset_path: str,
    vuln_class: str,
    export_path: Path = Path("data/graphify/submissions.json"),
) -> list[dict]:
    """Return softer graph/export similarity hints when Graphify data exists."""
    if not export_path.exists():
        return []
    try:
        records = json.loads(export_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    hints: list[dict] = []
    norm_asset = normalise_path(asset_path)
    for record in records if isinstance(records, list) else []:
        attrs = record.get("attrs", {})
        if str(attrs.get("program_id")) != str(program_id):
            continue
        if str(attrs.get("vuln_class", "")).lower() != vuln_class.lower():
            continue
        candidate_path = normalise_path(str(attrs.get("asset_path") or ""))
        if candidate_path == norm_asset or candidate_path.rsplit("/", 1)[0] == norm_asset.rsplit("/", 1)[0]:
            hints.append({
                "id": record.get("id"),
                "title": attrs.get("title"),
                "reason": "same vuln class on same or neighbouring asset path",
            })
    return hints[:5]


async def record_signature(
    session: AsyncSession,
    finding_id,
    program_id,
    fp: DedupFingerprint,
    asset_path: str,
    signal_type: str,
) -> BBDedupSignature:
    """Persist a fingerprint so the next equivalent finding is detected as dup."""
    sig = BBDedupSignature(
        finding_id=finding_id,
        program_id=program_id,
        signature_hash=fp.hash(),
        asset_path=asset_path[:1024],
        signal_type=signal_type[:40],
        vuln_class=fp.vuln_class[:80],
    )
    session.add(sig)
    await session.flush()
    logger.info(
        "bb.dedup.recorded",
        program_id=str(program_id),
        signature=fp.hash()[:16],
        vuln_class=fp.vuln_class,
    )
    return sig
