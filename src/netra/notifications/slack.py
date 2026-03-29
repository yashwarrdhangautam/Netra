"""Slack notification sender."""
from typing import Any

from netra.core.logging import get_logger

logger = get_logger(__name__)


class SlackNotifier:
    """Slack webhook notification sender."""

    def __init__(self, webhook_url: str | None = None) -> None:
        """Initialize Slack notifier.

        Args:
            webhook_url: Slack webhook URL (optional)
        """
        self.webhook_url = webhook_url

    async def send(self, message: dict[str, Any]) -> bool:
        """Send notification to Slack.

        Args:
            message: Message payload

        Returns:
            True if sent successfully
        """
        # Phase 1: implement real Slack webhook
        if not self.webhook_url:
            logger.info("slack_notification_skipped", reason="no_webhook_url")
            return False

        logger.info("slack_notification_stub", message=message)
        return True

    async def send_finding_alert(
        self,
        finding: dict[str, Any],
        severity: str,
    ) -> bool:
        """Send finding alert to Slack.

        Args:
            finding: Finding data
            severity: Finding severity

        Returns:
            True if sent successfully
        """
        message = {
            "text": f"New {severity} finding: {finding.get('title', 'Unknown')}",
            "attachments": [
                {
                    "color": self._get_severity_color(severity),
                    "fields": [
                        {"title": "Severity", "value": severity, "short": True},
                        {
                            "title": "Target",
                            "value": finding.get("target", "Unknown"),
                            "short": True,
                        },
                    ],
                }
            ],
        }
        return await self.send(message)

    def _get_severity_color(self, severity: str) -> str:
        """Get Slack attachment color for severity.

        Args:
            severity: Finding severity

        Returns:
            Hex color code
        """
        colors = {
            "critical": "#ff0000",
            "high": "#ff6600",
            "medium": "#ffcc00",
            "low": "#00ff00",
            "info": "#0066ff",
        }
        return colors.get(severity.lower(), "#808080")
