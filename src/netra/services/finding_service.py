"""Finding service for business logic."""
import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.finding import Finding, FindingStatus, Severity

logger = structlog.get_logger()

# SLA hours by severity
SLA_HOURS: dict[Severity, int] = {
    Severity.CRITICAL: 24,
    Severity.HIGH: 168,  # 7 days
    Severity.MEDIUM: 720,  # 30 days
    Severity.LOW: 2160,  # 90 days
    Severity.INFO: 0,  # No SLA
}


class FindingService:
    """Service for finding-related business logic."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create_finding_from_tool(
        self,
        scan_id: Any,  # uuid.UUID
        tool_name: str,
        finding_data: dict[str, Any],
    ) -> Finding | None:
        """Create a finding from tool output, with dedup check.

        Args:
            scan_id: Scan UUID
            tool_name: Name of the tool that found the finding
            finding_data: Finding data from tool wrapper

        Returns:
            Created Finding or None if duplicate
        """
        dedup_hash = self._compute_dedup_hash(finding_data)

        # Check for existing finding with same hash in this scan
        existing = await self.db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .where(Finding.dedup_hash == dedup_hash)
        )
        if existing.scalar_one_or_none():
            logger.debug("finding_deduplicated", hash=dedup_hash[:12])
            return None

        finding = Finding(
            scan_id=scan_id,
            title=finding_data.get("title", "Unknown Finding"),
            description=finding_data.get("description", "")[:10000],
            severity=self._normalize_severity(finding_data.get("severity", "info")),
            url=finding_data.get("url"),
            parameter=finding_data.get("parameter"),
            cwe_id=finding_data.get("cwe_id"),
            cve_ids=finding_data.get("cve_ids", []) or [],
            evidence=finding_data.get("evidence", {}) or {},
            tool_source=tool_name,
            confidence=finding_data.get("confidence", 50),
            tags=finding_data.get("tags", []) or [],
            dedup_hash=dedup_hash,
        )

        self.db.add(finding)
        await self.db.commit()
        logger.info(
            "finding_created",
            title=finding.title,
            severity=finding.severity,
            tool=tool_name,
        )
        return finding

    async def update_status(
        self,
        finding_id: Any,  # uuid.UUID
        new_status: FindingStatus,
        notes: str | None = None,
    ) -> Finding | None:
        """Update finding lifecycle status.

        Args:
            finding_id: Finding UUID
            new_status: New status to set
            notes: Optional notes to append

        Returns:
            Updated Finding or None if not found
        """
        result = await self.db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            return None

        # Validate transition
        valid_transitions: dict[FindingStatus, list[FindingStatus]] = {
            FindingStatus.NEW: [FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE],
            FindingStatus.CONFIRMED: [
                FindingStatus.IN_PROGRESS,
                FindingStatus.FALSE_POSITIVE,
                FindingStatus.ACCEPTED_RISK,
            ],
            FindingStatus.IN_PROGRESS: [
                FindingStatus.RESOLVED,
                FindingStatus.CONFIRMED,
            ],
            FindingStatus.RESOLVED: [FindingStatus.VERIFIED, FindingStatus.IN_PROGRESS],
            FindingStatus.VERIFIED: [],  # Terminal state
            FindingStatus.FALSE_POSITIVE: [FindingStatus.NEW],  # Can reopen
            FindingStatus.ACCEPTED_RISK: [FindingStatus.CONFIRMED],
        }

        if new_status not in valid_transitions.get(finding.status, []):
            logger.warning(
                "invalid_status_transition",
                current=finding.status,
                requested=new_status,
            )
            return None

        finding.status = new_status
        if notes:
            finding.notes = (finding.notes or "") + f"\n[{datetime.now(UTC).isoformat()}] {notes}"

        await self.db.commit()
        return finding

    async def get_sla_breaches(self, scan_id: Any) -> list[Finding]:
        """Get findings that have breached their SLA.

        Args:
            scan_id: Scan UUID

        Returns:
            List of findings that have breached SLA
        """
        now = datetime.now(UTC)
        breached: list[Finding] = []

        result = await self.db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .where(Finding.status.in_([FindingStatus.NEW, FindingStatus.CONFIRMED]))
        )

        for finding in result.scalars():
            sla_hours = SLA_HOURS.get(Severity(finding.severity), 0)
            if sla_hours == 0:
                continue
            age_hours = (now - finding.created_at).total_seconds() / 3600
            if age_hours > sla_hours:
                breached.append(finding)

        return breached

    def _compute_dedup_hash(self, data: dict[str, Any]) -> str:
        """Compute dedup hash: SHA256(cwe_id + url + parameter + title).

        Args:
            data: Finding data dictionary

        Returns:
            SHA256 hash string
        """
        parts = [
            str(data.get("cwe_id", "")),
            str(data.get("url", "")),
            str(data.get("parameter", "")),
            str(data.get("title", "")),
        ]
        raw = "|".join(str(p) for p in parts)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _normalize_severity(self, severity: str | Severity) -> Severity:
        """Normalize severity to enum.

        Args:
            severity: Severity string or enum

        Returns:
            Severity enum value
        """
        if isinstance(severity, Severity):
            return severity

        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "informational": Severity.INFO,
            "warning": Severity.MEDIUM,
            "error": Severity.HIGH,
        }
        return mapping.get(severity.lower(), Severity.INFO)
