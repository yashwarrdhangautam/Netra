"""Current authorization, immutable scan snapshots, and per-action policy checks."""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netra.bugbounty.scope import AssetType, ScopeValidator, parse_target
from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole
from netra.scanner.scope_gate import canonical_rule, compile_rules, compiled_policy_rules
from netra.schemas.authorization import AuthorizationRecord, AuthorizationRequest
from netra.services.audit import record_audit


class AuthorizationDenied(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _now(now: datetime | None) -> datetime:
    value = now or datetime.now(UTC)
    if value.tzinfo is None:
        raise AuthorizationDenied("authorization_invalid")
    return value


def canonical_policy(target: Target, request: AuthorizationRequest) -> dict[str, Any]:
    rules = compiled_policy_rules(target)
    return {
        "target_type": str(target.target_type),
        "rules": sorted((r.rule_type.value, r.asset_type.value, r.pattern) for r in rules),
        "allowed_actions": sorted(request.allowed_actions),
        "http_methods": sorted(request.http_methods),
        "ports": sorted(request.ports),
        "max_requests_per_second": request.max_requests_per_second,
    }


def policy_digest(policy: dict[str, Any]) -> str:
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_current_record(target: Target, now: datetime | None = None) -> AuthorizationRecord:
    if target.metadata_ is not None and not isinstance(target.metadata_, dict):
        raise AuthorizationDenied("authorization_invalid")
    value = (target.metadata_ or {}).get("scan_authorization")
    if value is None:
        raise AuthorizationDenied("authorization_missing")
    try:
        record = AuthorizationRecord.model_validate(value)
        current = _now(now)
        if record.revoked_at is not None:
            raise AuthorizationDenied("authorization_revoked")
        if record.authorized_at > current:
            raise AuthorizationDenied("authorization_invalid")
        if record.expires_at <= current:
            raise AuthorizationDenied("authorization_expired")
        if policy_digest(canonical_policy(target, record)) != record.scope_digest:
            raise AuthorizationDenied("policy_changed")
        return record
    except (ValidationError, ValueError, TypeError, AttributeError) as exc:
        raise AuthorizationDenied("authorization_invalid") from exc


async def _load_target(db: AsyncSession, target_id: uuid.UUID, *, lock: bool = False) -> Target:
    try:
        query = (
            select(Target).where(Target.id == target_id).execution_options(populate_existing=True)
        )
        if lock:
            query = query.with_for_update()
        target = await db.scalar(query)
    except SQLAlchemyError as exc:
        raise AuthorizationDenied("policy_unavailable") from exc
    if target is None:
        raise AuthorizationDenied("target_missing")
    return target


async def grant_authorization(
    db: AsyncSession,
    target_id: uuid.UUID,
    request: AuthorizationRequest,
    actor: User,
    *,
    now: datetime | None = None,
) -> AuthorizationRecord:
    if actor.role != UserRole.ADMIN:
        raise AuthorizationDenied("action_denied")
    target = await _load_target(db, target_id, lock=True)
    current = _now(now)
    if request.expires_at <= current:
        raise AuthorizationDenied("authorization_expired")
    try:
        digest = policy_digest(canonical_policy(target, request))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AuthorizationDenied("authorization_invalid") from exc
    old = (target.metadata_ or {}).get("scan_authorization")
    previous_version = 0
    if old is not None:
        try:
            previous_version = AuthorizationRecord.model_validate(old).policy_version
        except ValidationError as exc:
            raise AuthorizationDenied("authorization_invalid") from exc
    record = AuthorizationRecord(
        **request.model_dump(),
        authorization_id=uuid.uuid4(),
        authorized_by=actor.id,
        authorized_at=current,
        policy_version=previous_version + 1,
        scope_digest=digest,
    )
    target.metadata_ = {
        **(target.metadata_ or {}),
        "scan_authorization": record.model_dump(mode="json"),
    }
    await record_audit(
        db,
        actor=actor,
        action="target.authorization.grant",
        resource_type="target",
        resource_id=str(target.id),
        detail={
            "authorization_id": str(record.authorization_id),
            "policy_version": record.policy_version,
            "scope_digest": digest,
        },
    )
    await db.flush()
    return record


async def revoke_authorization(
    db: AsyncSession, target_id: uuid.UUID, actor: User, *, now: datetime | None = None
) -> AuthorizationRecord | None:
    target = await _load_target(db, target_id, lock=True)
    old = (target.metadata_ or {}).get("scan_authorization")
    if old is None:
        return None
    try:
        record = AuthorizationRecord.model_validate(old)
    except ValidationError as exc:
        raise AuthorizationDenied("authorization_invalid") from exc
    if record.revoked_at is not None:
        return record
    record = record.model_copy(update={"revoked_at": _now(now)})
    target.metadata_ = {
        **(target.metadata_ or {}),
        "scan_authorization": record.model_dump(mode="json"),
    }
    await record_audit(
        db,
        actor=actor,
        action="target.authorization.revoke",
        resource_type="target",
        resource_id=str(target.id),
        detail={
            "authorization_id": str(record.authorization_id),
            "policy_version": record.policy_version,
        },
    )
    await db.flush()
    return record


async def prepare_scan_authorization(
    db: AsyncSession, target_id: uuid.UUID, *, now: datetime | None = None
) -> dict[str, Any]:
    target = await _load_target(db, target_id)
    record = validate_current_record(target, now)
    return {
        "target_id": str(target.id),
        "record": record.model_dump(mode="json"),
        "policy": canonical_policy(target, record),
    }


def _check_snapshot(snapshot: object, target: Target, record: AuthorizationRecord) -> None:
    if not isinstance(snapshot, dict) or snapshot.get("target_id") != str(target.id):
        raise AuthorizationDenied("authorization_missing")
    if (
        snapshot.get("record") != record.model_dump(mode="json")
        or policy_digest(snapshot.get("policy", {})) != record.scope_digest
    ):
        raise AuthorizationDenied("policy_changed")


async def require_scan_authorization(
    db: AsyncSession, scan_id: uuid.UUID, *, now: datetime | None = None
) -> tuple[Scan, Target, AuthorizationRecord, ScopeValidator]:
    try:
        # populate_existing resets the scan's relationships, so the target is loaded eagerly:
        # callers read scan.target and an async session cannot lazy-load it.
        scan = await db.scalar(
            select(Scan)
            .options(selectinload(Scan.target))
            .where(Scan.id == scan_id)
            .execution_options(populate_existing=True)
        )
    except SQLAlchemyError as exc:
        raise AuthorizationDenied("policy_unavailable") from exc
    if scan is None:
        raise AuthorizationDenied("target_missing")
    if not isinstance(scan.checkpoint_data, dict | type(None)):
        raise AuthorizationDenied("authorization_invalid")
    if (scan.checkpoint_data or {}).get("policy_denial"):
        raise AuthorizationDenied("authorization_revoked")
    if scan.status == ScanStatus.CANCELLED:
        raise AuthorizationDenied("authorization_revoked")
    target = await _load_target(db, scan.target_id)
    record = validate_current_record(target, now)
    _check_snapshot((scan.checkpoint_data or {}).get("authorization_snapshot"), target, record)
    return scan, target, record, compile_rules(target)


async def require_target_action(
    db: AsyncSession,
    target_id: uuid.UUID,
    candidate: str,
    action: str,
    *,
    method: str | None = None,
    port: int | None = None,
    snapshot: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> AuthorizationRecord:
    target = await _load_target(db, target_id)
    record = validate_current_record(target, now)
    if snapshot is not None:
        _check_snapshot(snapshot, target, record)
    try:
        kind, normalized = canonical_rule(candidate)
        validator = compile_rules(target)
    except (ValueError, TypeError, AttributeError) as exc:
        raise AuthorizationDenied("scope_denied") from exc
    if kind == AssetType.CIDR:
        # A CIDR tool argument can only match an explicitly authorized canonical range;
        # individual addresses inside it continue through the shared matcher.
        rules = compiled_policy_rules(target)
        if any(r.rule_type.value == "out" for r in rules):
            raise AuthorizationDenied("scope_denied")
        if not any(
            r.rule_type.value == "in" and r.asset_type == kind and r.pattern == normalized
            for r in rules
        ):
            raise AuthorizationDenied("scope_denied")
    elif not validator.check(normalized).allowed:
        raise AuthorizationDenied("scope_denied")
    if action not in record.allowed_actions or (
        method is not None and method not in record.http_methods
    ):
        raise AuthorizationDenied("action_denied")
    parsed = parse_target(normalized)
    destination_port = (
        port
        if port is not None
        else parsed.port or {"http": 80, "https": 443}.get(parsed.scheme or "")
    )
    if destination_port is not None and destination_port not in record.ports:
        raise AuthorizationDenied("action_denied")
    return record
