"""Notification manager for coordinating Slack and Email alerts."""
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.core.config import settings
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.notifications.email import EmailNotifier
from netra.notifications.slack import SlackNotifier

logger = structlog.get_logger()


class NotificationManager:
    """Centralized notification manager for scan events and alerts."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize notification manager.

        Args:
            db: Database session
        """
        self.db = db
        self.slack = SlackNotifier()
        self.email = EmailNotifier()

    async def notify_critical_finding(
        self,
        finding: Finding,
        scan: Scan,
    ) -> None:
        """Send immediate alerts for critical/high severity findings.

        Args:
            finding: The finding that triggered the alert
            scan: The parent scan
        """
        if finding.severity not in ["critical", "high"]:
            return

        finding_data = {
            "title": finding.title,
            "description": finding.description,
            "target": scan.target.value,
            "tool_name": finding.tool_name,
            "cvss_score": finding.cvss_score,
            "remediation": finding.remediation,
            "url": f"{settings.api_cors_origins[0]}/findings/{finding.id}",
        }

        # Send Slack alert
        try:
            await self.slack.send_finding_alert(
                finding=finding_data,
                severity=finding.severity,
                scan_name=scan.name,
            )
        except Exception as e:
            logger.error("slack_alert_failed", finding_id=str(finding.id), error=str(e))

        # Send email alert to configured recipients
        for email_to in settings.notification_email_to:
            try:
                self.email.send_finding_alert(
                    to=email_to,
                    finding=finding_data,
                    severity=finding.severity,
                    scan_name=scan.name,
                )
            except Exception as e:
                logger.error("email_alert_failed", finding_id=str(finding.id), error=str(e))

    async def notify_scan_complete(
        self,
        scan: Scan,
        findings_summary: dict[str, int],
        duration_minutes: float,
        report_url: str | None = None,
        report_path: Any | None = None,
    ) -> None:
        """Send scan completion notifications.

        Args:
            scan: The completed scan
            findings_summary: Dict of severity -> count
            duration_minutes: Scan duration
            report_url: URL to view report online
            report_path: Path to report file for email attachment
        """
        # Send Slack notification
        try:
            await self.slack.send_scan_complete(
                scan_name=scan.name,
                target=scan.target.value,
                findings_summary=findings_summary,
                duration_minutes=duration_minutes,
                report_url=report_url,
            )
        except Exception as e:
            logger.error("slack_complete_notification_failed", error=str(e))

        # Send email notification
        for email_to in settings.notification_email_to:
            try:
                self.email.send_scan_complete(
                    to=email_to,
                    scan_name=scan.name,
                    target=scan.target.value,
                    findings_summary=findings_summary,
                    duration_minutes=duration_minutes,
                    report_path=report_path,
                )
            except Exception as e:
                logger.error("email_complete_notification_failed", error=str(e))

    async def check_and_notify_sla_breaches(self) -> int:
        """Check for SLA breaches and send alerts.

        SLA Requirements:
        - Critical: 24 hours
        - High: 7 days (168 hours)
        - Medium: 30 days (720 hours)
        - Low: 90 days (2160 hours)

        Returns:
            Number of breaches notified
        """
        sla_hours = {
            "critical": 24,
            "high": 168,  # 7 days
            "medium": 720,  # 30 days
            "low": 2160,  # 90 days
        }

        now = datetime.now(UTC)
        breaches_notified = 0

        # Get all confirmed/unresolved findings
        result = await self.db.execute(
            select(Finding)
            .where(Finding.status.in_(["confirmed", "new"]))
            .where(Finding.first_seen is not None)
        )
        findings = result.scalars().all()

        for finding in findings:
            if finding.severity not in sla_hours:
                continue

            max_hours = sla_hours[finding.severity]
            breach_time = finding.first_seen + timedelta(hours=max_hours)

            if now > breach_time:
                overdue_hours = int((now - breach_time).total_seconds() / 3600)

                # Get scan for target info
                scan_result = await self.db.execute(
                    select(Scan).where(Scan.id == finding.scan_id)
                )
                scan_result.scalar_one_or_none()

                finding_data = {
                    "title": finding.title,
                    "severity": finding.severity,
                }

                # Send Slack alert
                try:
                    await self.slack.send_sla_breach_alert(
                        finding=finding_data,
                        sla_hours=max_hours,
                        overdue_hours=overdue_hours,
                    )
                except Exception as e:
                    logger.error(
                        "slack_sla_breach_failed",
                        finding_id=str(finding.id),
                        error=str(e),
                    )

                # Send email alert
                for email_to in settings.notification_email_to:
                    try:
                        self.email.send_sla_breach_alert(
                            to=email_to,
                            finding=finding_data,
                            sla_hours=max_hours,
                            overdue_hours=overdue_hours,
                        )
                    except Exception as e:
                        logger.error(
                            "email_sla_breach_failed",
                            finding_id=str(finding.id),
                            error=str(e),
                        )

                breaches_notified += 1

        return breaches_notified

    async def notify_scan_started(self, scan: Scan) -> None:
        """Send notification that a scan has started.

        Args:
            scan: The scan that started
        """
        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🔍 Scan Started: {scan.name}",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Target*\n{scan.target.value}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Profile*\n{scan.profile}",
                        },
                    ],
                },
            ]
        }

        try:
            await self.slack.send(message)
        except Exception as e:
            logger.error("slack_scan_started_failed", error=str(e))

    async def notify_scan_failed(self, scan: Scan, error: str) -> None:
        """Send notification that a scan has failed.

        Args:
            scan: The failed scan
            error: Error message
        """
        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "❌ Scan Failed",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Scan*\n{scan.name}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Target*\n{scan.target.value}",
                        },
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Error:*\n```\n{error[:500]}\n```",
                    },
                },
            ]
        }

        try:
            await self.slack.send(message)
        except Exception as e:
            logger.error("slack_scan_failed_failed", error=str(e))


async def send_finding_notification(db: AsyncSession, finding_id: Any) -> None:
    """Helper function to send notification for a finding.

    Args:
        db: Database session
        finding_id: Finding UUID
    """
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        return

    scan_result = await db.execute(
        select(Scan).where(Scan.id == finding.scan_id)
    )
    scan = scan_result.scalar_one_or_none()

    if not scan:
        return

    manager = NotificationManager(db)
    await manager.notify_critical_finding(finding, scan)


async def send_scan_complete_notification(
    db: AsyncSession,
    scan_id: Any,
    findings_summary: dict[str, int],
    duration_minutes: float,
) -> None:
    """Helper function to send scan completion notification.

    Args:
        db: Database session
        scan_id: Scan UUID
        findings_summary: Dict of severity -> count
        duration_minutes: Scan duration
    """
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        return

    manager = NotificationManager(db)
    report_url = f"{settings.api_cors_origins[0]}/scans/{scan_id}"

    await manager.notify_scan_complete(
        scan=scan,
        findings_summary=findings_summary,
        duration_minutes=duration_minutes,
        report_url=report_url,
    )
