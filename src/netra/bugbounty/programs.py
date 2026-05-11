"""Program registry — CRUD over BBProgram + scope rule snapshotting.

This is the only place outside services/ that should write to bb_programs and
bb_scope_rules. The CLI and integrations call these helpers; nothing else.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.bb_program import BBPlatform, BBProgram
from netra.db.models.bb_scope_rule import BBScopeRule, ScopeAssetType, ScopeRuleType

logger = structlog.get_logger()


# ── DTOs ────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ScopeRuleInput:
    """A scope rule pulled from a platform API, before it's persisted.

    Mirrors BBScopeRule fields except for IDs and timestamps. Used as the boundary
    type between integrations (hackerone.py / bugcrowd.py / intigriti.py) and the
    program registry — keeps platform-specific scraping out of this module.
    """

    rule_type: ScopeRuleType
    asset_type: ScopeAssetType
    pattern: str
    severity_cap: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class ProgramInput:
    """A program registration request from the operator or an integration."""

    platform: BBPlatform
    handle: str
    name: str
    policy_url: str | None = None
    payout_min: int | None = None
    payout_max: int | None = None
    currency: str = "USD"


@dataclass
class ScopeDiff:
    """Changes between an existing program's scope rules and a fresh sync."""

    added: list[ScopeRuleInput]
    removed: list[BBScopeRule]
    unchanged_count: int

    @property
    def has_changes(self) -> bool:
        return bool(self.added) or bool(self.removed)


# ── CRUD helpers ────────────────────────────────────────────────────────────────
async def get_program(
    session: AsyncSession, platform: BBPlatform, handle: str
) -> BBProgram | None:
    """Fetch a program by (platform, handle), or None if absent."""
    stmt = select(BBProgram).where(
        BBProgram.platform == platform,
        BBProgram.handle == handle,
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def create_program(session: AsyncSession, data: ProgramInput) -> BBProgram:
    """Insert a new program. Caller is responsible for transaction commit."""
    program = BBProgram(
        platform=data.platform,
        handle=data.handle,
        name=data.name,
        policy_url=data.policy_url,
        payout_min=data.payout_min,
        payout_max=data.payout_max,
        currency=data.currency,
        active=True,
    )
    session.add(program)
    await session.flush()
    logger.info(
        "bb.program.created",
        platform=data.platform.value,
        handle=data.handle,
        program_id=str(program.id),
    )
    return program


async def list_active_programs(session: AsyncSession) -> list[BBProgram]:
    """Return all non-deleted, active programs."""
    stmt = (
        select(BBProgram)
        .where(BBProgram.active.is_(True), BBProgram.deleted_at.is_(None))
        .order_by(BBProgram.platform, BBProgram.handle)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_active_scope_rules(
    session: AsyncSession, program_id
) -> list[BBScopeRule]:
    """Return the active scope rules for a program."""
    stmt = (
        select(BBScopeRule)
        .where(
            BBScopeRule.program_id == program_id,
            BBScopeRule.active.is_(True),
        )
        .order_by(BBScopeRule.rule_type, BBScopeRule.asset_type, BBScopeRule.pattern)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


# ── Scope sync + diff ───────────────────────────────────────────────────────────
def _rule_signature(rule_type: str, asset_type: str, pattern: str) -> tuple[str, str, str]:
    """Stable signature used to compare DB rules against fresh platform-pulled rules."""
    return (rule_type, asset_type, pattern.strip().lower())


def diff_scope(
    existing: Iterable[BBScopeRule], fresh: Iterable[ScopeRuleInput]
) -> ScopeDiff:
    """Compute the diff between existing DB rules and a fresh platform pull.

    Pure function — no DB writes. Caller decides whether to apply the diff.
    """
    existing_list = list(existing)
    fresh_list = list(fresh)

    existing_sigs = {
        _rule_signature(r.rule_type, r.asset_type, r.pattern): r for r in existing_list
    }
    fresh_sigs = {
        _rule_signature(r.rule_type.value, r.asset_type.value, r.pattern): r
        for r in fresh_list
    }

    added = [fresh_sigs[s] for s in fresh_sigs.keys() - existing_sigs.keys()]
    removed = [existing_sigs[s] for s in existing_sigs.keys() - fresh_sigs.keys()]
    unchanged = len(existing_sigs.keys() & fresh_sigs.keys())

    return ScopeDiff(added=added, removed=removed, unchanged_count=unchanged)


async def apply_scope_diff(
    session: AsyncSession, program: BBProgram, diff: ScopeDiff
) -> None:
    """Apply a scope diff: deactivate removed rules, insert added ones.

    Removed rules are soft-deactivated (active=False) rather than physically removed.
    This preserves audit history — operators can see when a rule disappeared.
    """
    now = datetime.now(timezone.utc)

    for stale in diff.removed:
        stale.active = False
        logger.info(
            "bb.scope.rule_deactivated",
            program_id=str(program.id),
            pattern=stale.pattern,
        )

    for new_rule in diff.added:
        rule = BBScopeRule(
            program_id=program.id,
            rule_type=new_rule.rule_type,
            asset_type=new_rule.asset_type,
            pattern=new_rule.pattern,
            severity_cap=new_rule.severity_cap,
            notes=new_rule.notes,
            active=True,
            synced_from_platform=True,
        )
        session.add(rule)
        logger.info(
            "bb.scope.rule_added",
            program_id=str(program.id),
            pattern=new_rule.pattern,
            rule_type=new_rule.rule_type.value,
        )

    program.scope_synced_at = now
    await session.flush()


async def replace_scope_rules(
    session: AsyncSession,
    program: BBProgram,
    fresh_rules: Iterable[ScopeRuleInput],
) -> ScopeDiff:
    """Sync flow: pull existing rules, compute diff, apply if non-empty.

    Returns the diff so the operator/CLI can show it.
    """
    existing = await get_active_scope_rules(session, program.id)
    diff = diff_scope(existing, fresh_rules)
    if diff.has_changes:
        await apply_scope_diff(session, program, diff)
    else:
        program.scope_synced_at = datetime.now(timezone.utc)
        await session.flush()
    return diff
