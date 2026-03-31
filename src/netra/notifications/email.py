"""Email notification sender with real SMTP implementation."""
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import structlog

from netra.core.config import settings

logger = structlog.get_logger()


class EmailNotifier:
    """SMTP email notification sender with TLS support."""

    def __init__(
        self,
        smtp_host: str | None = None,
        smtp_port: int = 587,
        smtp_user: str | None = None,
        smtp_password: str | None = None,
        from_email: str | None = None,
        use_tls: bool = True,
    ) -> None:
        """Initialize email notifier.

        Args:
            smtp_host: SMTP server host
            smtp_port: SMTP server port (587 for TLS, 465 for SSL)
            smtp_user: SMTP username
            smtp_password: SMTP password
            from_email: Sender email address
            use_tls: Whether to use TLS (default True)
        """
        self.smtp_host = smtp_host or settings.smtp_host
        self.smtp_port = smtp_port or settings.smtp_port
        self.smtp_user = smtp_user or settings.smtp_user
        self.smtp_password = smtp_password or settings.smtp_password
        self.from_email = from_email or settings.notification_email_from
        self.use_tls = use_tls

    def send(
        self,
        to: str,
        subject: str,
        body: str,
        html: bool = False,
        attachments: list[Path] | None = None,
    ) -> bool:
        """Send email notification via SMTP.

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body
            html: Whether body is HTML (default False)
            attachments: Optional list of file paths to attach

        Returns:
            True if sent successfully, False otherwise
        """
        if not all([self.smtp_host, self.smtp_user, self.smtp_password, self.from_email]):
            logger.info("email_notification_skipped", reason="smtp_not_configured")
            return False

        try:
            # Create message
            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = to
            msg["Subject"] = subject

            # Add body
            content_type = "html" if html else "plain"
            msg.attach(MIMEText(body, content_type, "utf-8"))

            # Add attachments
            if attachments:
                for file_path in attachments:
                    if file_path.exists():
                        try:
                            with open(file_path, "rb") as attachment:
                                part = MIMEBase("application", "octet-stream")
                                part.set_payload(attachment.read())
                                encoders.encode_base64(part)
                                part.add_header(
                                    "Content-Disposition",
                                    f"attachment; filename= {file_path.name}",
                                )
                                msg.attach(part)
                        except Exception as e:
                            logger.warning(
                                "attachment_failed",
                                file_path=str(file_path),
                                error=str(e),
                            )

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            logger.info(
                "email_sent",
                to=to,
                subject=subject[:50],
            )
            return True

        except smtplib.SMTPException as e:
            logger.error(
                "email_send_error",
                to=to,
                error=str(e),
            )
            return False
        except Exception as e:
            logger.error(
                "email_unexpected_error",
                to=to,
                error=str(e),
            )
            return False

    def send_bulk(
        self,
        recipients: list[str],
        subject: str,
        body: str,
        html: bool = False,
    ) -> dict[str, bool]:
        """Send email to multiple recipients.

        Args:
            recipients: List of recipient email addresses
            subject: Email subject
            body: Email body
            html: Whether body is HTML

        Returns:
            Dictionary mapping recipient email to send status
        """
        results = {}
        for recipient in recipients:
            results[recipient] = self.send(
                to=recipient,
                subject=subject,
                body=body,
                html=html,
            )
        return results
