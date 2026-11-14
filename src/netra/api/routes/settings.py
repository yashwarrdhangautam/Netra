"""Settings the GUI manages: integration keys (encrypted) and notification tests."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.api.rbac import require_admin
from netra.api.routes.auth import get_current_active_user
from netra.core.config import settings as app_settings
from netra.core.secretbox import decrypt_value, encrypt_value, mask
from netra.db.models.app_setting import AppSetting
from netra.db.models.user import User
from netra.notifications.email import EmailNotifier
from netra.notifications.slack import SlackNotifier
from netra.services.audit import record_audit

router = APIRouter(prefix="/settings", tags=["Settings"])

# name -> (label, environment fallback attribute)
INTEGRATIONS: dict[str, tuple[str, str]] = {
    "shodan_api_key": ("Shodan API key", "shodan_api_key"),
    "wpscan_api_token": ("WPScan API token", "wpscan_api_token"),
    "slack_webhook_url": ("Slack webhook URL", "slack_webhook_url"),
}


class IntegrationOut(BaseModel):
    name: str
    label: str
    configured: bool
    masked: str | None
    source: str  # "gui", "environment" or "unset"


class IntegrationIn(BaseModel):
    value: str = Field(default="", max_length=2000)


class TestResult(BaseModel):
    sent: bool
    detail: str


async def get_integration_value(db: AsyncSession, name: str) -> str | None:
    """GUI-entered value first, then the environment fallback. None if neither is set."""
    row = (await db.execute(select(AppSetting).where(AppSetting.name == name))).scalar_one_or_none()
    if row is not None:
        value = decrypt_value(row.value_encrypted)
        if value:
            return value
    attr = INTEGRATIONS[name][1] if name in INTEGRATIONS else ""
    return getattr(app_settings, attr, "") or None


def _check_name(name: str) -> None:
    if name not in INTEGRATIONS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown setting")


@router.get("/integrations", response_model=list[IntegrationOut])
async def list_integrations(
    _user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> list[IntegrationOut]:
    """Which integrations are set. Values are masked, never returned in full."""
    out: list[IntegrationOut] = []
    for name, (label, attr) in INTEGRATIONS.items():
        row = (
            await db.execute(select(AppSetting).where(AppSetting.name == name))
        ).scalar_one_or_none()
        gui_value = decrypt_value(row.value_encrypted) if row else None
        env_value = getattr(app_settings, attr, "") or None
        value = gui_value or env_value
        out.append(
            IntegrationOut(
                name=name,
                label=label,
                configured=bool(value),
                masked=mask(value) if value else None,
                source="gui" if gui_value else ("environment" if env_value else "unset"),
            )
        )
    return out


@router.put("/integrations/{name}", response_model=IntegrationOut)
async def set_integration(
    name: str,
    body: IntegrationIn,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> IntegrationOut:
    """Save an integration key, or clear it with an empty value. Stored encrypted."""
    _check_name(name)
    value = body.value.strip()
    row = (await db.execute(select(AppSetting).where(AppSetting.name == name))).scalar_one_or_none()
    if not value:
        if row is not None:
            await db.delete(row)
    elif row is None:
        db.add(
            AppSetting(
                name=name,
                value_encrypted=encrypt_value(value),
                updated_by_email=admin.email,
            )
        )
    else:
        row.value_encrypted = encrypt_value(value)
        row.updated_by_email = admin.email
    await record_audit(
        db,
        actor=admin,
        action="settings.integration.set" if value else "settings.integration.clear",
        resource_type="setting",
        resource_id=name,
    )
    await db.commit()
    return IntegrationOut(
        name=name,
        label=INTEGRATIONS[name][0],
        configured=bool(value),
        masked=mask(value) if value else None,
        source="gui" if value else "unset",
    )


@router.post("/notifications/slack/test", response_model=TestResult)
async def test_slack(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> TestResult:
    webhook = await get_integration_value(db, "slack_webhook_url")
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No Slack webhook is set. Add one under Integrations first.",
        )
    sent = await SlackNotifier(webhook_url=webhook).send(
        {"text": f"NETRA test notification sent by {admin.email}."}
    )
    return TestResult(
        sent=bool(sent),
        detail="Delivered to Slack." if sent else "Slack rejected the message or was unreachable.",
    )


@router.post("/notifications/email/test", response_model=TestResult)
async def test_email(
    user: Annotated[User, Depends(get_current_active_user)],
) -> TestResult:
    """Send a test email to the signed-in user using the server's SMTP settings."""
    if not app_settings.smtp_host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SMTP is not configured on the server (NETRA_SMTP_HOST).",
        )
    sent = EmailNotifier().send(
        to=user.email,
        subject="NETRA test email",
        body="This is a test message from NETRA. Email notifications are working.",
    )
    return TestResult(
        sent=bool(sent),
        detail="Test email sent." if sent else "SMTP send failed. Check the server logs.",
    )
