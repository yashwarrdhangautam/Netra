"""Bug bounty-specific notifications."""
from __future__ import annotations

from typing import Any

from netra.notifications.slack import SlackNotifier


async def notify_scope_diff(program: Any, diff: Any) -> bool:
    """Notify when a platform scope sync changes active rules."""
    if not getattr(diff, "has_changes", False):
        return False
    payload = {
        "text": f"NETRA-BB scope changed for {program.handle}",
        "attachments": [
            {
                "color": "#ffcc00",
                "fields": [
                    {"title": "Program", "value": f"{program.platform}/{program.handle}", "short": True},
                    {"title": "Added", "value": str(len(diff.added)), "short": True},
                    {"title": "Removed", "value": str(len(diff.removed)), "short": True},
                ],
            }
        ],
    }
    return await SlackNotifier().send(payload)


async def notify_critical_finding(finding: Any, program: Any) -> bool:
    """Notify for critical bug bounty findings."""
    if str(finding.severity) != "critical":
        return False
    payload = {
        "title": finding.title,
        "description": finding.description,
        "target": finding.url or program.handle,
        "cwe": finding.cwe_id or "N/A",
    }
    return await SlackNotifier().send_finding_alert(payload, "critical", scan_name=f"BB {program.handle}")

