"""Slack notification sender with real webhook implementation."""
import json
from typing import Any

import httpx
import structlog

from netra.core.config import settings

logger = structlog.get_logger()


class SlackNotifier:
    """Slack webhook notification sender with real HTTP POST implementation."""

    def __init__(self, webhook_url: str | None = None) -> None:
        """Initialize Slack notifier.

        Args:
            webhook_url: Slack webhook URL (optional, falls back to settings)
        """
        self.webhook_url = webhook_url or settings.slack_webhook_url or None

    def _get_severity_color(self, severity: str) -> str:
        """Return Slack attachment color for a finding severity."""
        return {
            "critical": "#ff0000",
            "high": "#ff6600",
            "medium": "#ffcc00",
            "low": "#00ff00",
            "info": "#0066ff",
        }.get(severity.lower(), "#808080")

    def _get_severity_emoji(self, severity: str) -> str:
        """Return compact visual marker for a finding severity."""
        return {
            "critical": "\U0001f534",
            "high": "\U0001f7e0",
            "medium": "\U0001f7e1",
            "low": "\U0001f7e2",
            "info": "\U0001f535",
        }.get(severity.lower(), "\u26aa")

    async def send(self, message: dict[str, Any]) -> bool:
        """Send notification to Slack via webhook.

        Args:
            message: Message payload (blocks or attachment format)

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.webhook_url:
            logger.info("slack_notification_skipped", reason="no_webhook_url")
            return False

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    self.webhook_url,
                    json=message,
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    logger.info("slack_notification_sent", message_type=message.get("text", "unknown")[:50])
                    return True
                else:
                    logger.error(
                        "slack_notification_failed",
                        status_code=response.status_code,
                        response=response.text[:200],
                    )
                    return False

        except httpx.HTTPError as e:
            logger.error("slack_notification_error", error=str(e))
            return False
        except Exception as e:
            logger.error("slack_notification_unexpected_error", error=str(e))
            return False

    async def send_finding_alert(
        self,
        finding: dict[str, Any],
        severity: str,
        scan_name: str | None = None,
    ) -> bool:
        """Send finding alert to Slack with rich formatting.

        Args:
            finding: Finding data (title, description, target, etc.)
            severity: Finding severity (critical, high, medium, low)
            scan_name: Optional scan name for context

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.webhook_url:
            logger.info("slack_notification_skipped", reason="no_webhook_url")
            return False

        try:
            color = self._get_severity_color(severity)
            emoji = self._get_severity_emoji(severity)

            # Build message payload
            message = {
                "text": f"{emoji} Finding Alert: {finding.get('title', 'Unknown')}",
                "attachments": [
                    {
                        "color": color,
                        "title": finding.get("title", "Unknown Finding"),
                        "text": finding.get("description", "No description"),
                        "fields": [
                            {
                                "title": "Severity",
                                "value": severity.upper(),
                                "short": True,
                            },
                            {
                                "title": "Target",
                                "value": finding.get("target", "Unknown"),
                                "short": True,
                            },
                            {
                                "title": "Scan",
                                "value": scan_name or "Unknown",
                                "short": True,
                            },
                            {
                                "title": "CWE",
                                "value": finding.get("cwe", "N/A"),
                                "short": True,
                            },
                        ],
                        "footer": "NETRA Security Platform",
                        "ts": int(__import__("time").time()),
                    }
                ],
            }

            return await self.send(message)

        except Exception as e:
            logger.error("finding_alert_error", error=str(e))
            return False
