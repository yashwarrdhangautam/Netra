"""Evidence ingest pipeline: sniff, redact, encrypt, store."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.evidence.encryptor import decrypt, encrypt
from netra.bugbounty.evidence.redactor import RedactionHit, redact_bytes
from netra.core.config import settings
from netra.db.models.bb_evidence import BBEvidence, BBEvidenceRedaction


@dataclass(frozen=True)
class StoredEvidence:
    """Evidence row and redaction hits."""

    evidence: BBEvidence
    hits: list[RedactionHit]


def _evidence_root() -> Path:
    return Path(settings.evidence_dir)


def _redact_text(value: str) -> str:
    """Run caller-supplied text through the same redactor as the file bytes."""
    redacted, _ = redact_bytes(value.encode("utf-8"))
    return redacted.decode("utf-8", errors="replace")


def _redact_metadata(metadata: dict | None) -> dict:
    """Redact caller metadata before it is persisted to the database."""
    if not metadata:
        return {}
    redacted_text = _redact_text(json.dumps(metadata, default=str))
    try:
        cleaned = json.loads(redacted_text)
    except ValueError:
        return {"redacted_metadata": redacted_text}
    return cleaned if isinstance(cleaned, dict) else {"redacted_metadata": redacted_text}


def sniff_mime(filename: str, content_type: str | None) -> str:
    """Return a conservative MIME type."""
    guessed = mimetypes.guess_type(filename)[0]
    return content_type or guessed or "application/octet-stream"


async def store_evidence(
    session: AsyncSession,
    *,
    finding_id,
    program_id,
    filename: str,
    content: bytes,
    content_type: str | None = None,
    metadata: dict | None = None,
) -> StoredEvidence:
    """Run the redaction/encryption pipeline and persist DB metadata."""
    safe_filename = Path(_redact_text(filename or "evidence.txt")).name or "evidence.txt"
    safe_metadata = _redact_metadata(metadata)
    redacted, hits = redact_bytes(content)
    digest = hashlib.sha256(redacted).hexdigest()
    evidence_id = uuid.uuid4()
    storage_dir = _evidence_root() / str(program_id) / str(finding_id)
    storage_dir.mkdir(parents=True, exist_ok=True)
    storage_path = storage_dir / f"{evidence_id}.enc"
    storage_path.write_bytes(encrypt(redacted))

    evidence = BBEvidence(
        id=evidence_id,
        finding_id=finding_id,
        program_id=program_id,
        filename=safe_filename,
        mime_type=sniff_mime(safe_filename, content_type),
        storage_path=str(storage_path),
        sha256=digest,
        size_bytes=len(redacted),
        redaction_count=len(hits),
        encrypted=True,
        metadata_=safe_metadata,
    )
    session.add(evidence)
    await session.flush()
    for hit in hits:
        session.add(
            BBEvidenceRedaction(
                evidence_id=evidence.id,
                rule_id=hit.rule_id,
                replacement=hit.replacement,
                start_offset=hit.start_offset,
                end_offset=hit.end_offset,
            )
        )
    await session.flush()
    return StoredEvidence(evidence=evidence, hits=hits)


def read_evidence_blob(evidence: BBEvidence) -> bytes:
    """Read and decrypt an evidence blob from disk."""
    blob = Path(evidence.storage_path).read_bytes()
    return decrypt(blob) if evidence.encrypted else blob

