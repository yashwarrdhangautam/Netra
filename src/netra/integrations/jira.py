"""Jira integration for creating tickets from security findings."""
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.core.config import settings

logger = structlog.get_logger()


class JiraClient:
    """Client for Jira Cloud/Server API integration.

    Supports:
    - Creating issues from findings
    - Updating issue status
    - Adding comments
    - Linking issues
    """

    def __init__(
        self,
        base_url: str | None = None,
        email: str | None = None,
        api_token: str | None = None,
        project_key: str | None = None,
    ) -> None:
        """Initialize Jira client.

        Args:
            base_url: Jira base URL (e.g., https://your-domain.atlassian.net)
            email: Jira user email (for Cloud) or username (for Server)
            api_token: Jira API token (Cloud) or password (Server)
            project_key: Default Jira project key (e.g., "SEC")
        """
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.email = email or ""
        self.api_token = api_token or ""
        self.project_key = project_key or "SEC"
        self.is_cloud = "atlassian.net" in self.base_url.lower() if self.base_url else False

    def is_configured(self) -> bool:
        """Check if Jira integration is configured.

        Returns:
            True if base_url, email, and api_token are set
        """
        return bool(self.base_url and self.email and self.api_token)

    def _get_auth(self) -> tuple[str, str] | httpx.BasicAuth:
        """Get authentication for requests.

        Returns:
            Authentication tuple or BasicAuth object
        """
        if self.is_cloud:
            return httpx.BasicAuth(self.email, self.api_token)
        else:
            return (self.email, self.api_token)

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]] | None:
        """Make HTTP request to Jira API.

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
            logger.warning("jira_not_configured")
            return None

        url = f"{self.base_url}/rest/api/3/{endpoint.lstrip('/')}"
        headers = {"Accept": "application/json"}

        if self.is_cloud:
            headers["Content-Type"] = "application/json"
            auth = self._get_auth()
        else:
            headers["Content-Type"] = "application/json"
            auth = self._get_auth()

        try:
            async with httpx.AsyncClient(timeout=30.0, auth=auth) as client:
                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    json=data,
                    params=params,
                )
                response.raise_for_status()

                if response.status_code == 204:
                    return None

                return response.json()

        except httpx.HTTPError as e:
            logger.error(
                "jira_request_failed",
                endpoint=endpoint,
                status_code=getattr(e.response, "status_code", None),
                error=str(e),
            )
            raise

    async def get_project(self, project_key: str) -> dict[str, Any] | None:
        """Get Jira project details.

        Args:
            project_key: Project key (e.g., "SEC")

        Returns:
            Project data or None
        """
        return await self._request("GET", f"project/{project_key}")

    async def get_issue_types(self, project_key: str) -> list[dict[str, Any]]:
        """Get available issue types for a project.

        Args:
            project_key: Project key

        Returns:
            List of issue types
        """
        result = await self._request("GET", f"project/{project_key}/statuses")
        if not result:
            return []

        # Extract unique issue types
        issue_types = []
        seen = set()
        for item in result:
            if "statuses" in item:
                for status_item in item["statuses"]:
                    if "id" in status_item and status_item["id"] not in seen:
                        issue_types.append(status_item)
                        seen.add(status_item["id"])

        return issue_types

    async def create_issue(
        self,
        summary: str,
        description: str,
        issue_type: str = "Task",
        priority: str = "Medium",
        assignee_email: str | None = None,
        labels: list[str] | None = None,
        components: list[str] | None = None,
        custom_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new Jira issue.

        Args:
            summary: Issue summary/title
            description: Issue description
            issue_type: Issue type (Task, Bug, Story, etc.)
            priority: Priority (Highest, High, Medium, Low, Lowest)
            assignee_email: Email of assignee
            labels: Issue labels
            components: Component names
            custom_fields: Custom fields (e.g., security fields)

        Returns:
            Created issue data
        """
        fields: dict[str, Any] = {
            "project": {"key": self.project_key},
            "summary": summary,
            "description": {"type": "doc", "version": 1, "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": description}]
                }
            ]},
            "issuetype": {"name": issue_type},
            "priority": {"name": priority},
        }

        if assignee_email:
            fields["assignee"] = {"emailAddress": assignee_email}

        if labels:
            fields["labels"] = labels

        if components:
            fields["components"] = [{"name": c} for c in components if c]

        if custom_fields:
            fields.update(custom_fields)

        created = await self._request("POST", "issue", data={"fields": fields})
        
        if created:
            logger.info(
                "jira_issue_created",
                key=created.get("key"),
                summary=summary,
            )

        return created or {}

    async def add_comment(self, issue_key: str, comment: str) -> dict[str, Any]:
        """Add a comment to a Jira issue.

        Args:
            issue_key: Issue key (e.g., "SEC-123")
            comment: Comment text

        Returns:
            Created comment data
        """
        comment_data = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": comment}]
                    }
                ]
            }
        }

        return await self._request("POST", f"issue/{issue_key}/comment", data=comment_data)

    async def transition_issue(
        self,
        issue_key: str,
        transition_id: str,
    ) -> dict[str, Any]:
        """Transition an issue to a new status.

        Args:
            issue_key: Issue key (e.g., "SEC-123")
            transition_id: Transition ID

        Returns:
            Transition result
        """
        return await self._request(
            "POST",
            f"issue/{issue_key}/transitions",
            data={"transition": {"id": transition_id}},
        )

    async def get_transitions(self, issue_key: str) -> list[dict[str, Any]]:
        """Get available transitions for an issue.

        Args:
            issue_key: Issue key

        Returns:
            List of available transitions
        """
        result = await self._request("GET", f"issue/{issue_key}/transitions")
        if not result:
            return []
        return result.get("transitions", [])

    async def link_issues(
        self,
        inward_issue_key: str,
        outward_issue_key: str,
        link_type: str = "Relates",
    ) -> dict[str, Any]:
        """Link two Jira issues.

        Args:
            inward_issue_key: Inward issue key
            outward_issue_key: Outward issue key
            link_type: Link type (Relates, Blocks, Clones, etc.)

        Returns:
            Link result
        """
        return await self._request(
            "POST",
            "issueLink",
            data={
                "type": {"name": link_type},
                "inwardIssue": {"key": inward_issue_key},
                "outwardIssue": {"key": outward_issue_key},
            },
        )

    async def create_finding_ticket(
        self,
        finding: dict[str, Any],
        scan: dict[str, Any],
        issue_type: str = "Bug",
        assignee_email: str | None = None,
    ) -> dict[str, Any]:
        """Create a Jira ticket from a security finding.

        Args:
            finding: Finding data
            scan: Scan data
            issue_type: Issue type (default "Bug")
            assignee_email: Email to assign ticket to

        Returns:
            Created issue data
        """
        # Map severity to priority
        priority_map = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }

        severity = finding.get("severity", "medium")
        priority = priority_map.get(severity, "Medium")

        # Build description
        description = self._build_description(finding, scan)

        # Build labels
        labels = [
            "security",
            "netra",
            f"severity-{severity}",
            scan.get("profile", "unknown"),
        ]

        if cwe := finding.get("cwe"):
            labels.append(f"cwe-{cwe}")

        # Create issue
        issue = await self.create_issue(
            summary=f"[{severity.upper()}] {finding.get('title', 'Security Finding')}",
            description=description,
            issue_type=issue_type,
            priority=priority,
            assignee_email=assignee_email,
            labels=labels,
        )

        # Add PoC as comment if available
        if issue and finding.get("proof_of_concept"):
            await self.add_comment(
                issue.get("key", ""),
                f"*Proof of Concept:*\n{finding['proof_of_concept']}",
            )

        return issue

    def _build_description(self, finding: dict[str, Any], scan: dict[str, Any]) -> str:
        """Build Jira issue description from finding.

        Args:
            finding: Finding data
            scan: Scan data

        Returns:
            Formatted description
        """
        lines = [
            f"h2. Finding Details",
            "",
            f"*Target:* {scan.get('target', 'Unknown')}",
            f"*Scan:* {scan.get('name', 'Unknown')}",
            f"*Tool:* {finding.get('tool_name', 'Unknown')}",
            "",
            f"h3. Description",
            "",
            finding.get("description", "No description provided."),
            "",
        ]

        if cvss := finding.get("cvss_score"):
            lines.extend([
                f"h3. CVSS Score",
                "",
                f"{cvss}",
                "",
            ])

        if cwe := finding.get("cwe"):
            lines.extend([
                f"h3. CWE",
                "",
                f"CWE-{cwe}",
                "",
            ])

        if remediation := finding.get("remediation"):
            lines.extend([
                f"h3. Remediation",
                "",
                remediation,
                "",
            ])

        if references := finding.get("references"):
            lines.extend([
                f"h3. References",
                "",
            ])
            for ref in references:
                lines.append(f"* {ref}")
            lines.append("")

        lines.extend([
            f"h3. Metadata",
            "",
            f"_Generated by NETRA Security Platform on {datetime.now(timezone.utc).isoformat()}_",
        ])

        return "\n".join(lines)


# Global client instance
jira_client = JiraClient()


async def create_finding_ticket(
    db: AsyncSession,
    finding_id: uuid.UUID,
    assignee_email: str | None = None,
) -> dict[str, Any]:
    """Helper function to create a Jira ticket from a finding.

    Args:
        db: Database session
        finding_id: Finding UUID
        assignee_email: Email to assign ticket to

    Returns:
        Created issue data
    """
    # Get finding
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()

    if not finding:
        logger.error("finding_not_found", finding_id=str(finding_id))
        return {"status": "error", "message": "Finding not found"}

    # Get scan
    scan_result = await db.execute(select(Scan).where(Scan.id == finding.scan_id))
    scan = scan_result.scalar_one_or_none()

    if not scan:
        logger.error("scan_not_found", scan_id=str(finding.scan_id))
        return {"status": "error", "message": "Scan not found"}

    # Initialize client from settings
    client = JiraClient(
        base_url=getattr(settings, "jira_url", None),
        email=getattr(settings, "jira_email", None),
        api_token=getattr(settings, "jira_api_token", None),
        project_key=getattr(settings, "jira_project_key", "SEC"),
    )

    if not client.is_configured():
        logger.warning("jira_integration_not_configured")
        return {"status": "skipped", "message": "Jira not configured"}

    # Create ticket
    issue = await client.create_finding_ticket(
        finding={
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "tool_name": finding.tool_name,
            "cvss_score": finding.cvss_score,
            "cwe": finding.cwe,
            "remediation": finding.remediation,
            "proof_of_concept": finding.proof_of_concept,
            "references": [],
        },
        scan={
            "name": scan.name,
            "target": scan.target.value,
            "profile": scan.profile,
        },
        assignee_email=assignee_email,
    )

    if issue and "key" in issue:
        # Store Jira issue key in finding metadata (if column exists)
        logger.info(
            "jira_ticket_created",
            finding_id=str(finding_id),
            issue_key=issue["key"],
        )
        return {
            "status": "success",
            "issue_key": issue["key"],
            "issue_url": f"{client.base_url}/browse/{issue['key']}",
        }

    return {"status": "error", "message": "Failed to create issue"}


async def sync_finding_status(
    db: AsyncSession,
    finding_id: uuid.UUID,
) -> dict[str, Any]:
    """Sync finding status to Jira ticket.

    Args:
        db: Database session
        finding_id: Finding UUID

    Returns:
        Sync result
    """
    # Get finding
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()

    if not finding:
        return {"status": "error", "message": "Finding not found"}

    # Get Jira issue key from metadata (would need a column in Finding model)
    # For now, this is a placeholder for future implementation
    logger.info(
        "jira_status_sync_requested",
        finding_id=str(finding_id),
        status=finding.status,
    )

    return {
        "status": "info",
        "message": "Status sync requires Jira issue key in finding metadata",
    }
