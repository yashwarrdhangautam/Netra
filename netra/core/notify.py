"""
netra/core/notify.py
Notifications: Slack webhook + Email (SMTP).
notify_finding()   — triggered per critical/high finding during scan
notify_complete()  — triggered when scan finishes, sends full summary
"""

import json
import smtplib
import urllib.request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from datetime import datetime


SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
}

SEV_COLOR = {
    "critical": "#FF4560",
    "high":     "#FF8C00",
    "medium":   "#FFD700",
    "low":      "#00E676",
    "info":     "#888888",
}


def notify_finding(finding: dict) -> None:
    """
    Send real-time alert for a critical/high finding via Slack and/or email.
    Call this whenever a finding is saved to the DB.

    Args:
        finding: Finding dict from FindingsDB.add_finding()
    """
    from netra.core.config import CONFIG, is_on

    sev = finding.get("severity", "").lower()
    notify_severities = [s.strip() for s in CONFIG.get("notify_on", "critical,high").split(",")]

    if sev not in notify_severities:
        return

    title   = finding.get("title", "Unknown Finding")
    host    = finding.get("host", "?")
    url     = finding.get("url", host)
    cvss    = finding.get("cvss_score", "?")
    cve     = finding.get("cve_id", "")
    impact  = finding.get("impact", "")
    scan_id = finding.get("scan_id", "?")
    emoji   = SEV_EMOJI.get(sev, "⚪")

    if CONFIG.get("slack_webhook"):
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {sev.upper()}: {title}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Host:*\n{host}"},
                    {"type": "mrkdwn", "text": f"*CVSS:*\n{cvss}"},
                    {"type": "mrkdwn", "text": f"*CVE:*\n{cve or 'N/A'}"},
                    {"type": "mrkdwn", "text": f"*Scan:*\n{scan_id}"},
                ]
            },
        ]
        if url and url != host:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*URL:* {url}"}
            })
        if impact:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Impact:* {impact[:200]}"}
            })
        _send_slack({"blocks": blocks}, CONFIG["slack_webhook"])


def notify_complete(scan_id: str, workdir: str, stats: dict,
                    risk_score: int, risk_grade: str,
                    attachment_path: str = None) -> None:
    """
    Send scan completion notification with full summary stats.

    Args:
        scan_id:         Unique scan identifier.
        workdir:         Path to scan workdir.
        stats:           Dict of severity → count.
        risk_score:      0-100 risk score.
        risk_grade:      Letter grade A/B/C/D.
        attachment_path: Optional path to attach to email.
    """
    from netra.core.config import CONFIG, is_on

    if not is_on("notify_complete"):
        return

    total    = sum(stats.values())
    critical = stats.get("critical", 0)
    high     = stats.get("high", 0)
    medium   = stats.get("medium", 0)
    low      = stats.get("low", 0)
    ts       = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    grade_emoji = {"A": "✅", "B": "🔵", "C": "⚠️", "D": "🚨"}.get(risk_grade, "❓")

    if CONFIG.get("slack_webhook"):
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"✅ NETRA Scan Complete — Risk Grade: {grade_emoji} {risk_grade}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Scan ID:* {scan_id}\n"
                        f"*Completed:* {ts}\n"
                        f"*Risk Score:* {risk_score}/100 ({risk_grade})"
                    )
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"🔴 *Critical:* {critical}"},
                    {"type": "mrkdwn", "text": f"🟠 *High:* {high}"},
                    {"type": "mrkdwn", "text": f"🟡 *Medium:* {medium}"},
                    {"type": "mrkdwn", "text": f"🟢 *Low:* {low}"},
                    {"type": "mrkdwn", "text": f"📊 *Total:* {total}"},
                    {"type": "mrkdwn", "text": f"📁 *Workdir:* {Path(workdir).name}"},
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Full reports available in: `{workdir}`"
                }
            }
        ]
        _send_slack({"blocks": blocks}, CONFIG["slack_webhook"])

    if CONFIG.get("email_to") and CONFIG.get("smtp_host"):
        subject = f"[NETRA] Scan Complete — Risk Grade {risk_grade} — {scan_id}"
        html_body = f"""
<html><body style="font-family:monospace;background:#0a0f17;color:#b8cdd8;padding:24px">
<h2 style="color:#00e5cc">✅ NETRA Scan Complete</h2>
<table style="border-collapse:collapse;width:100%">
<tr><td style="padding:8px;border:1px solid #1a2d3d"><b>Scan ID</b></td>
    <td style="padding:8px;border:1px solid #1a2d3d">{scan_id}</td></tr>
<tr><td style="padding:8px;border:1px solid #1a2d3d"><b>Completed</b></td>
    <td style="padding:8px;border:1px solid #1a2d3d">{ts}</td></tr>
<tr><td style="padding:8px;border:1px solid #1a2d3d"><b>Risk Grade</b></td>
    <td style="padding:8px;border:1px solid #1a2d3d;color:#00e5cc"><b>{risk_grade} ({risk_score}/100)</b></td></tr>
<tr><td style="padding:8px;border:1px solid #1a2d3d"><b>🔴 Critical</b></td>
    <td style="padding:8px;border:1px solid #1a2d3d;color:#FF4560">{critical}</td></tr>
<tr><td style="padding:8px;border:1px solid #1a2d3d"><b>🟠 High</b></td>
    <td style="padding:8px;border:1px solid #1a2d3d;color:#FF8C00">{high}</td></tr>
<tr><td style="padding:8px;border:1px solid #1a2d3d"><b>🟡 Medium</b></td>
    <td style="padding:8px;border:1px solid #1a2d3d;color:#FFD700">{medium}</td></tr>
<tr><td style="padding:8px;border:1px solid #1a2d3d"><b>🟢 Low</b></td>
    <td style="padding:8px;border:1px solid #1a2d3d;color:#00E676">{low}</td></tr>
</table>
<p style="color:#3d6070">Reports saved to: {workdir}</p>
<p style="color:#3d6070;font-size:11px">NETRA नेत्र — The Third Eye of Security</p>
</body></html>
"""
        _send_email(subject, html_body, attachment_path, CONFIG)


def _send_slack(payload: dict, webhook_url: str) -> bool:
    """Send a Slack webhook payload. Returns True on success."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"  [notify] Slack error: {e}")
        return False


def _send_email(subject: str, html_body: str, attachment_path: str = None,
                cfg: dict = None) -> bool:
    """Send an HTML email with optional attachment. Returns True on success."""
    if not cfg:
        from netra.core.config import CONFIG
        cfg = CONFIG

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = cfg.get("email_from", "")
        msg["To"]      = cfg.get("email_to", "")
        msg.attach(MIMEText(html_body, "html"))

        if attachment_path and Path(attachment_path).exists():
            with open(attachment_path, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
            encoders.encode_base64(part)
            fname = Path(attachment_path).name
            part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
            msg.attach(part)

        with smtplib.SMTP(cfg["smtp_host"], int(cfg.get("smtp_port", 587))) as s:
            s.starttls()
            if cfg.get("smtp_user") and cfg.get("smtp_pass"):
                s.login(cfg["smtp_user"], cfg["smtp_pass"])
            s.send_message(msg)

        return True

    except Exception as e:
        print(f"  [notify] Email error: {e}")
        return False
