"""Manual scope-rule authorization (netra-bb scope --add)."""

import pytest

from netra.bugbounty.programs import add_scope_rule, get_active_scope_rules
from netra.bugbounty.scope import ScopeValidator
from netra.db.models.bb_program import BBPlatform, BBProgram


@pytest.mark.asyncio
async def test_manual_scope_rule_authorizes_target(db_session):
    program = BBProgram(
        platform=BBPlatform.PRIVATE,
        handle="demo",
        name="Demo",
        currency="USD",
        active_classes_approved=[],
    )
    db_session.add(program)
    await db_session.commit()
    await db_session.refresh(program)

    rules = await get_active_scope_rules(db_session, program.id)
    assert (
        ScopeValidator.from_db_rules(rules).check("https://app.example.com").allowed is False
    )  # deny by default

    await add_scope_rule(
        db_session, program, pattern="app.example.com", asset_type="domain", rule_type="in"
    )
    await db_session.commit()

    rules = await get_active_scope_rules(db_session, program.id)
    assert ScopeValidator.from_db_rules(rules).check("https://app.example.com").allowed is True
    assert ScopeValidator.from_db_rules(rules).check("https://evil.example.net").allowed is False
    assert rules[0].synced_from_platform is False
