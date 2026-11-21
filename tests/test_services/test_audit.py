"""Audit detail is sanitized and commits atomically with the caller's changes."""

import copy
import uuid

from sqlalchemy import func, select

from netra.db.models.audit_log import AuditLog
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole
from netra.services.audit import record_audit


async def test_recursive_secrets_and_url_material_are_not_saved(db_session):
    detail = {
        "token": "synthetic-token",
        "nested": [{"AUTHORIZATION": "Bearer synthetic", "safe": "kept", "old_password": "old"}],
        "url": "https://alice:synthetic-pass@example.org/api?q=synthetic-query#synthetic-fragment",
        "message": "request failed at https://example.org/path?key=synthetic-inline",
        "fields": ["status", "assignee"],
    }
    original = copy.deepcopy(detail)
    await record_audit(
        db_session, actor=None, action="finding.update", resource_type="finding", detail=detail
    )
    await db_session.commit()
    row = await db_session.scalar(select(AuditLog))
    assert row.detail["token"] == "[REDACTED]"
    assert row.detail["nested"][0]["AUTHORIZATION"] == "[REDACTED]"
    assert row.detail["nested"][0]["old_password"] == "[REDACTED]"
    assert row.detail["nested"][0]["safe"] == "kept"
    assert row.detail["url"] == "https://example.org/api"
    assert row.detail["message"] == "request failed at https://example.org/path"
    assert row.detail["fields"] == ["status", "assignee"]
    assert detail == original
    assert "synthetic-" not in str(row.detail)


async def test_caller_rollback_removes_mutation_and_audit(db_session):
    target = Target(id=uuid.uuid4(), name="before", target_type="domain", value="example.org")
    actor = User(
        id=uuid.uuid4(), email="audit@example.org", hashed_password="unused", role=UserRole.ADMIN
    )
    db_session.add_all([target, actor])
    await db_session.commit()
    target_id, actor_id = target.id, actor.id
    target.name = "after"
    await record_audit(
        db_session,
        actor=actor,
        action="target.update",
        resource_type="target",
        resource_id=str(target_id),
        detail={"fields": ["name"]},
    )
    await db_session.flush()
    await db_session.rollback()
    assert (await db_session.get(Target, target_id)).name == "before"
    assert await db_session.scalar(select(func.count()).select_from(AuditLog)) == 0
    actor = await db_session.get(User, actor_id)
    await record_audit(
        db_session,
        actor=actor,
        action="target.update",
        resource_type="target",
        resource_id=str(target_id),
        detail={"fields": ["name"]},
    )
    await db_session.commit()
    row = await db_session.scalar(select(AuditLog))
    assert row.actor_id == actor_id
    assert row.actor_email == "audit@example.org"
    assert row.resource_id == str(target_id)


async def test_embedded_sensitive_headers_and_malformed_urls_are_redacted(db_session):
    await record_audit(
        db_session,
        actor=None,
        action="scan.update",
        resource_type="scan",
        detail={
            "headers": {"X-Custom": "synthetic-header"},
            "client_secret": "synthetic-secret",
            "Cookie": "synthetic-cookie",
            "endpoint": "https://user:pass@[broken?q=secret",
        },
    )
    await db_session.commit()
    row = await db_session.scalar(select(AuditLog))
    assert row.detail["headers"] == "[REDACTED]"
    assert row.detail["client_secret"] == "[REDACTED]"
    assert row.detail["Cookie"] == "[REDACTED]"
    assert row.detail["endpoint"] == "[REDACTED_URL]"


async def test_authorization_identifier_is_preserved_as_safe_uuid(db_session):
    authorization_id = str(uuid.uuid4())
    await record_audit(
        db_session,
        actor=None,
        action="target.authorization.grant",
        resource_type="target",
        detail={"authorization_id": authorization_id},
    )
    await db_session.commit()
    row = await db_session.scalar(select(AuditLog))
    assert row.detail["authorization_id"] == authorization_id
