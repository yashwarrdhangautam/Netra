"""Security hardening: submission drafts need an analyst or admin, docs are off outside development,
and the app refuses to start outside development with the built-in JWT secret."""

import uuid
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from netra.api.app import DEFAULT_JWT_SECRET, create_app
from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.core.config import settings
from netra.db.models.user import UserRole


def _user(role: UserRole):
    return SimpleNamespace(id=uuid.uuid4(), email="x@example.com", role=role, is_active=True)


async def _no_db():
    yield None


def _client(user) -> AsyncClient:
    app = create_app()

    async def override_user():
        return user

    app.dependency_overrides[get_current_active_user] = override_user
    app.dependency_overrides[get_db_session] = _no_db
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_viewer_cannot_download_submission_artifact():
    async with _client(_user(UserRole.VIEWER)) as client:
        response = await client.get(
            f"/api/v1/bb/submissions/{uuid.uuid4()}/artifact", params={"format": "md"}
        )
    assert response.status_code == 403


async def test_client_cannot_download_submission_artifact():
    async with _client(_user(UserRole.CLIENT)) as client:
        response = await client.get(
            f"/api/v1/bb/submissions/{uuid.uuid4()}/artifact", params={"format": "md"}
        )
    assert response.status_code == 403


def test_docs_disabled_outside_development(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    app = create_app()
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None


def test_docs_enabled_in_development(monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    app = create_app()
    assert app.docs_url == "/docs"


def test_refuses_default_jwt_secret_outside_development(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret_key", DEFAULT_JWT_SECRET)
    with pytest.raises(RuntimeError, match="NETRA_JWT_SECRET_KEY"):
        create_app()


def test_default_jwt_secret_allowed_in_development(monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "jwt_secret_key", DEFAULT_JWT_SECRET)
    assert create_app() is not None
