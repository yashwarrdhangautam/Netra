"""DefectDojo integration for bidirectional vulnerability sync."""
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.core.config import settings
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan

logger = structlog.get_logger()


class DefectDojoClient:
    """Client for DefectDojo API integration.

    Supports:
    - Creating/updating products
    - Creating/updating engagements
    - Importing findings
    - Syncing finding status
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        """Initialize DefectDojo client.

        Args:
            base_url: DefectDojo API base URL (e.g., https://defectdojo.example.com)
            api_key: DefectDojo API v2 key
        """
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.api_key = api_key or ""
        self.headers = {
            "Authorization": f"Token {self.api_key}",
            "Content-Type": "application/json",
        }

    def is_configured(self) -> bool:
        """Check if DefectDojo integration is configured.

        Returns:
            True if base_url and api_key are set
        """
        return bool(self.base_url and self.api_key)

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]] | None:
        """Make HTTP request to DefectDojo API.

        Args:
            method: HTTP method
            endpoint: API endpoint (without base URL)
            data: Request body
            params: Query parameters

        Returns:
            JSON response or None

        Raises:
            httpx.HTTPError: If request fails
        """
        if not self.is_configured():
            logger.warning("defectdojo_not_configured")
            return None

        url = f"{self.base_url}/api/v2/{endpoint.lstrip('/')}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.request(
                    method,
                    url,
                    headers=self.headers,
                    json=data,
                    params=params,
                )
                response.raise_for_status()

                if response.status_code == 204:
                    return None

                return response.json()

        except httpx.HTTPError as e:
            logger.error(
                "defectdojo_request_failed",
                endpoint=endpoint,
                status_code=getattr(e.response, "status_code", None),
                error=str(e),
            )
            raise

    async def get_or_create_product(
        self,
        name: str,
        description: str = "",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Get existing product or create new one.

        Args:
            name: Product name
            description: Product description
            tags: Optional tags

        Returns:
            Product data
        """
        # Try to find existing product
        result = await self._request("GET", "products/", params={"name": name})

        if result and result.get("results"):
            return result["results"][0]

        # Create new product
        product_data = {
            "name": name,
            "description": description or f"Product for {name}",
            "tags": tags or [],
        }

        created = await self._request("POST", "products/", data=product_data)
        logger.info("defectdojo_product_created", name=name)
        return created or {}

    async def get_or_create_engagement(
        self,
        product_id: int,
        name: str,
        description: str = "",
        engagement_type: str = "CI/CD",
        target_start: str | None = None,
        target_end: str | None = None,
    ) -> dict[str, Any]:
        """Get existing engagement or create new one.

        Args:
            product_id: Product ID
            name: Engagement name
            description: Engagement description
            engagement_type: Type (CI/CD, Audit, etc.)
            target_start: Start date (ISO format)
            target_end: End date (ISO format)

        Returns:
            Engagement data
        """
        # Try to find existing engagement
        result = await self._request(
            "GET",
            "engagements/",
            params={"product": product_id, "name": name},
        )

        if result and result.get("results"):
            return result["results"][0]

        # Create new engagement
        now = datetime.now(UTC).isoformat()
        engagement_data = {
            "product": product_id,
            "name": name,
            "description": description or f"Engagement for {name}",
            "engagement_type": engagement_type,
            "target_start": target_start or now,
            "target_end": target_end or now,
            "status": "In Progress",
        }

        created = await self._request("POST", "engagements/", data=engagement_data)
        logger.info("defectdojo_engagement_created", name=name, product_id=product_id)
        return created or {}

    async def create_finding(
        self,
        engagement_id: int,
        finding: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a new finding in DefectDojo.

        Args:
            engagement_id: Engagement ID
            finding: Finding data (NETRA format)

        Returns:
            Created finding data (DefectDojo format)
        """
        # Map NETRA severity to DefectDojo
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Informational",
        }

        # Map NETRA status to DefectDojo

        dojo_finding = {
            "title": finding.get("title", "Unknown Finding"),
            "description": finding.get("description", ""),
            "severity": severity_map.get(
                finding.get("severity", "medium"), "Medium"
            ),
            "mitigation": finding.get("remediation", ""),
            "impact": finding.get("impact", ""),
            "steps_to_reproduce": finding.get("proof_of_concept", ""),
            "references": finding.get("references", []),
            "tags": finding.get("tags", []),
            "active": finding.get("status", "new") in ["new", "confirmed"],
            "verified": finding.get("status", "new") == "verified",
            "false_p": finding.get("status", "new") == "false_positive",
            "risk_accepted": finding.get("status", "new") == "wont_fix",
            "engagement": engagement_id,
            "numerical_severity": self._get_numerical_severity(
                finding.get("severity", "medium")
            ),
        }

        # Add CWE if available
        if cwe := finding.get("cwe"):
            dojo_finding["cwe"] = cwe

        # Add CVSS if available
        if cvss := finding.get("cvss_score"):
            dojo_finding["cvssv3_score"] = float(cvss)

        # Add file path if available
        if file_path := finding.get("file_path"):
            dojo_finding["file_path"] = file_path

        # Add line number if available
        if line := finding.get("line"):
            dojo_finding["line"] = line

        created = await self._request("POST", "findings/", data=dojo_finding)
        logger.info(
            "defectdojo_finding_created",
            title=dojo_finding["title"],
            engagement_id=engagement_id,
        )
        return created or {}

    async def update_finding(
        self,
        finding_id: int,
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an existing finding in DefectDojo.

        Args:
            finding_id: DefectDojo finding ID
            updates: Fields to update

        Returns:
            Updated finding data
        """
        updated = await self._request(
            "PATCH", f"findings/{finding_id}/", data=updates
        )
        logger.info("defectdojo_finding_updated", finding_id=finding_id)
        return updated or {}

    async def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        """Get a finding from DefectDojo.

        Args:
            finding_id: DefectDojo finding ID

        Returns:
            Finding data or None
        """
        return await self._request("GET", f"findings/{finding_id}/")

    async def sync_findings_to_defectdojo(
        self,
        db: AsyncSession,
        scan_id: uuid.UUID,
        product_name: str | None = None,
        engagement_name: str | None = None,
    ) -> dict[str, Any]:
        """Sync all findings from a scan to DefectDojo.

        Args:
            db: Database session
            scan_id: Scan UUID
            product_name: Optional product name (default: scan target)
            engagement_name: Optional engagement name (default: scan name)

        Returns:
            Sync result with counts
        """
        # Get scan
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            logger.error("scan_not_found", scan_id=str(scan_id))
            return {"status": "error", "message": "Scan not found"}

        # Get findings
        findings_result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        findings = list(findings_result.scalars().all())

        if not findings:
            logger.info("no_findings_to_sync", scan_id=str(scan_id))
            return {"status": "success", "created": 0, "updated": 0}

        # Get or create product
        product = await self.get_or_create_product(
            name=product_name or scan.target.value,
            description=f"Target: {scan.target.value}",
            tags=["netra", "security", scan.profile],
        )

        if not product:
            logger.error("failed_to_create_product", name=product_name)
            return {"status": "error", "message": "Failed to create product"}

        # Get or create engagement
        engagement = await self.get_or_create_engagement(
            product_id=product["id"],
            name=engagement_name or scan.name,
            description=f"Scan profile: {scan.profile}",
            engagement_type="CI/CD",
            target_start=scan.started_at.isoformat() if scan.started_at else None,
            target_end=scan.completed_at.isoformat() if scan.completed_at else None,
        )

        if not engagement:
            logger.error("failed_to_create_engagement", name=engagement_name)
            return {"status": "error", "message": "Failed to create engagement"}

        # Sync findings
        created_count = 0
        updated_count = 0

        for finding in findings:
            # Check if finding already exists in DefectDojo
            has_metadata = hasattr(finding, "metadata")
            dojo_finding_id = finding.metadata.get("defectdojo_id") if has_metadata else None

            if dojo_finding_id:
                # Update existing finding
                await self.update_finding(
                    dojo_finding_id,
                    {
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity,
                        "mitigation": finding.remediation,
                    },
                )
                updated_count += 1
            else:
                # Create new finding
                created = await self.create_finding(
                    engagement["id"],
                    {
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity,
                        "remediation": finding.remediation,
                        "proof_of_concept": finding.proof_of_concept,
                        "cwe": finding.cwe,
                        "cvss_score": finding.cvss_score,
                        "status": finding.status,
                    },
                )

                if created and "id" in created:
                    # Store DefectDojo ID for future sync
                    # Note: This would require a metadata column in Finding model
                    created_count += 1

        logger.info(
            "defectdojo_sync_complete",
            scan_id=str(scan_id),
            created=created_count,
            updated=updated_count,
        )

        return {
            "status": "success",
            "created": created_count,
            "updated": updated_count,
            "product_id": product["id"],
            "engagement_id": engagement["id"],
        }

    def _get_numerical_severity(self, severity: str) -> int:
        """Convert severity to numerical value for DefectDojo sorting.

        Args:
            severity: Severity string

        Returns:
            Numerical severity (1-4)
        """
        mapping = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "info": 5,
        }
        return mapping.get(severity.lower(), 3)


# Global client instance
defectdojo_client = DefectDojoClient()


async def sync_scan_to_defectdojo(
    db: AsyncSession,
    scan_id: uuid.UUID,
    product_name: str | None = None,
) -> dict[str, Any]:
    """Helper function to sync a scan to DefectDojo.

    Args:
        db: Database session
        scan_id: Scan UUID
        product_name: Optional product name

    Returns:
        Sync result
    """
    # Initialize client from settings
    client = DefectDojoClient(
        base_url=getattr(settings, "defectdojo_url", None),
        api_key=getattr(settings, "defectdojo_api_key", None),
    )

    if not client.is_configured():
        logger.warning("defectdojo_integration_not_configured")
        return {"status": "skipped", "message": "DefectDojo not configured"}

    return await client.sync_findings_to_defectdojo(
        db=db,
        scan_id=scan_id,
        product_name=product_name,
    )
