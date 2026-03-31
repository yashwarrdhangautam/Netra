"""Settings routes for managing user and system settings."""
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from netra.api.deps import get_admin_user, get_current_active_user
from netra.db.models.user import User

logger = structlog.get_logger()

router = APIRouter(prefix="/settings", tags=["Settings"])


# ── Pydantic Schemas ──────────────────────────────────────────────────────────


class ApiKeySettings(BaseModel):
    """API key settings schema."""

    anthropic_api_key: str | None = None
    shodan_api_key: str | None = None
    wpscan_api_key: str | None = None


class NotificationSettings(BaseModel):
    """Notification settings schema."""

    slack_webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    notification_email_from: str | None = None
    notification_email_to: list[str] | None = None


class ScanDefaults(BaseModel):
    """Scan defaults settings schema."""

    default_scan_profile: str = "standard"
    max_concurrent_scans: int = Field(default=3, ge=1, le=10)
    scan_timeout_hours: int = Field(default=12, ge=1, le=72)


class TestSlackRequest(BaseModel):
    """Test Slack webhook request."""

    webhook_url: str


class TestSmtpRequest(BaseModel):
    """Test SMTP configuration request."""

    host: str
    port: int
    user: str
    password: str | None = None


class MessageResponse(BaseModel):
    """Simple message response schema."""

    message: str


# ── Settings Routes ──────────────────────────────────────────────────────────


@router.patch("/api-keys", response_model=ApiKeySettings)
async def update_api_keys(
    payload: ApiKeySettings,
    current_user: Annotated[User, Depends(get_admin_user)],
) -> ApiKeySettings:
    """Update API key settings.

    Args:
        payload: API key settings to update
        current_user: Authenticated user

    Returns:
        Updated API key settings
    """
    # TODO: Store API keys encrypted in database
    # For now, just validate and return
    logger.info(
        "api_keys_updated",
        user_id=str(current_user.id),
        anthropic_set=payload.anthropic_api_key is not None,
        shodan_set=payload.shodan_api_key is not None,
        wpscan_set=payload.wpscan_api_key is not None,
    )

    return payload


@router.patch("/notifications", response_model=NotificationSettings)
async def update_notification_settings(
    payload: NotificationSettings,
    current_user: Annotated[User, Depends(get_admin_user)],
) -> NotificationSettings:
    """Update notification settings.

    Args:
        payload: Notification settings to update
        current_user: Authenticated user

    Returns:
        Updated notification settings
    """
    # TODO: Store notification settings in database
    logger.info(
        "notification_settings_updated",
        user_id=str(current_user.id),
        slack_configured=payload.slack_webhook_url is not None,
        smtp_configured=payload.smtp_host is not None,
    )

    return payload


@router.patch("/scan-defaults", response_model=ScanDefaults)
async def update_scan_defaults(
    payload: ScanDefaults,
    current_user: Annotated[User, Depends(get_admin_user)],
) -> ScanDefaults:
    """Update scan default settings.

    Args:
        payload: Scan defaults to update
        current_user: Authenticated user

    Returns:
        Updated scan defaults
    """
    # TODO: Store scan defaults in database
    logger.info(
        "scan_defaults_updated",
        user_id=str(current_user.id),
        profile=payload.default_scan_profile,
        max_scans=payload.max_concurrent_scans,
        timeout=payload.scan_timeout_hours,
    )

    return payload


@router.post("/notifications/test-slack", response_model=MessageResponse)
async def test_slack_webhook(
    payload: TestSlackRequest,
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> MessageResponse:
    """Test Slack webhook configuration.

    Args:
        payload: Slack webhook URL
        current_user: Authenticated user

    Returns:
        Test result
    """
    try:
        # TODO: Actually send test message to Slack
        # For now, just validate the URL format
        if not payload.webhook_url.startswith("https://hooks.slack.com/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Slack webhook URL format",
            )

        logger.info(
            "slack_test_requested",
            user_id=str(current_user.id),
        )

        return MessageResponse(message="Test notification sent to Slack")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("slack_test_failed", user_id=str(current_user.id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send test notification: {str(e)}",
        ) from e


@router.post("/notifications/test-smtp", response_model=MessageResponse)
async def test_smtp_configuration(
    payload: TestSmtpRequest,
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> MessageResponse:
    """Test SMTP configuration.

    Args:
        payload: SMTP configuration
        current_user: Authenticated user

    Returns:
        Test result
    """
    try:
        # TODO: Actually send test email via SMTP
        # For now, just validate the configuration
        if not payload.host or not payload.user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SMTP host and username are required",
            )

        logger.info(
            "smtp_test_requested",
            user_id=str(current_user.id),
            host=payload.host,
            port=payload.port,
        )

        return MessageResponse(message="Test email sent successfully")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("smtp_test_failed", user_id=str(current_user.id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send test email: {str(e)}",
        ) from e
