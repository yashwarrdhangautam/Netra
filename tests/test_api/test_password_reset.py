"""Password reset by email: request, single-use confirm, and invalidation on password change."""

import importlib
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import HTTPException

auth = importlib.import_module("netra.api.routes.auth")
from netra.core.config import settings
from netra.core.security import (
    create_password_reset_token,
    get_password_hash,
    verify_password,
)
from netra.db.models.user import User, UserRole

OLD_PASSWORD = "old-password-123"  # noqa: S105 - test fixture
NEW_PASSWORD = "new-password-456"  # noqa: S105 - test fixture


@pytest.fixture
def sent(monkeypatch):
    """Capture reset emails instead of sending them."""
    messages: list[dict] = []

    def fake_send(self, to, subject, body, html=False, attachments=None):
        messages.append({"to": to, "subject": subject, "body": body})
        return True

    monkeypatch.setattr(auth.EmailNotifier, "send", fake_send)
    return messages


async def _user(db, email="reset@example.org") -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        hashed_password=get_password_hash(OLD_PASSWORD),
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
        failed_login_attempts=3,
        locked_until=datetime.now(UTC) + timedelta(minutes=15),
    )
    db.add(user)
    await db.commit()
    return user


def _token_from_email(messages: list[dict]) -> str:
    link = messages[-1]["body"].split("\n\n")[1]
    return link.split("token=", 1)[1]


def _request_fn():
    """The rate-limited route, unwrapped so tests can call it without an HTTP request."""
    fn = auth.request_password_reset
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    return fn


async def test_request_for_unknown_email_sends_nothing_and_answers_the_same(db_session, sent):
    answer = await _request_fn()(
        request=None, body=auth.PasswordResetRequest(email="nobody@example.org"), db=db_session
    )

    assert answer == {"detail": "If that account exists, a reset link has been sent."}
    assert sent == []


async def test_request_emails_a_link_that_resets_the_password_once(db_session, sent):
    user = await _user(db_session)

    await _request_fn()(
        request=None, body=auth.PasswordResetRequest(email=user.email), db=db_session
    )
    token = _token_from_email(sent)
    assert sent[0]["to"] == user.email
    assert f"{settings.public_app_url}/reset-password?token=" in sent[0]["body"]

    done = await auth.confirm_password_reset(
        auth.PasswordResetConfirmRequest(token=token, new_password=NEW_PASSWORD), db=db_session
    )
    assert done["detail"].startswith("Password updated")
    await db_session.refresh(user)
    assert verify_password(NEW_PASSWORD, user.hashed_password)
    assert user.failed_login_attempts == 0
    assert user.locked_until is None

    # The same link cannot be used twice: the password hash has changed.
    with pytest.raises(HTTPException) as again:
        await auth.confirm_password_reset(
            auth.PasswordResetConfirmRequest(token=token, new_password="third-password-789"),
            db=db_session,
        )
    assert again.value.status_code == 400


async def test_token_is_void_after_password_changed_another_way(db_session):
    user = await _user(db_session)
    token = create_password_reset_token(user.id, password_hash=user.hashed_password)
    user.hashed_password = get_password_hash("changed-elsewhere-000")
    await db_session.commit()

    with pytest.raises(HTTPException) as exc:
        await auth.confirm_password_reset(
            auth.PasswordResetConfirmRequest(token=token, new_password=NEW_PASSWORD),
            db=db_session,
        )
    assert exc.value.status_code == 400


async def test_expired_and_forged_tokens_are_refused(db_session):
    user = await _user(db_session)
    expired = jwt.encode(
        {
            "sub": str(user.id),
            "type": "password_reset",
            "pwh": "x",
            "exp": datetime.now(UTC) - timedelta(minutes=1),
        },
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    forged = jwt.encode(
        {
            "sub": str(user.id),
            "type": "password_reset",
            "exp": datetime.now(UTC) + timedelta(hours=1),
        },
        "not-the-server-secret-value-000000000000",
        algorithm=settings.jwt_algorithm,
    )
    for token in (expired, forged, "garbage"):
        with pytest.raises(HTTPException) as exc:
            await auth.confirm_password_reset(
                auth.PasswordResetConfirmRequest(token=token, new_password=NEW_PASSWORD),
                db=db_session,
            )
        assert exc.value.status_code == 400
