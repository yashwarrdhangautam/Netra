"""Tests for PoC inclusion in BB submission drafts."""

from __future__ import annotations

from pathlib import Path

import pytest

from netra.db.models.bb_program import BBPlatform, BBProgram
from netra.db.models.finding import Finding, Severity
from netra.db.models.scan import Scan, ScanProfile
from netra.db.models.target import Target, TargetType
from netra.services.bb_submission_service import BBSubmissionService, DraftLeakRiskError


class StubPocBuilder:
    async def build(self, finding, evidence, vuln_class):  # noqa: ANN001
        return "```http\nGET /orders?token=AKIAIOSFODNN7EXAMPLE HTTP/1.1\nHost: api.shopify.com\n\n```"


@pytest.mark.asyncio
async def test_create_draft_includes_and_redacts_poc(monkeypatch, db_session, tmp_path: Path) -> None:
    async def fake_build_corpus_context(*args, **kwargs):  # noqa: ANN002, ANN003
        return [
            "[reports] Shopify reflected XSS :: Similar public report (https://example.com/report)"
        ]

    monkeypatch.setattr(
        "netra.services.bb_submission_service.PocBuilder",
        lambda: StubPocBuilder(),
    )
    monkeypatch.setattr(
        "netra.services.bb_submission_service.build_corpus_context",
        fake_build_corpus_context,
    )

    program = BBProgram(
        platform=BBPlatform.HACKERONE,
        handle="shopify",
        name="Shopify",
        currency="USD",
    )
    db_session.add(program)
    await db_session.flush()

    target = Target(name="bb:shopify", target_type=TargetType.DOMAIN, value="shopify")
    db_session.add(target)
    await db_session.flush()

    scan = Scan(
        name="Bug bounty passive hunt: shopify",
        profile=ScanProfile.BUGBOUNTY_PASSIVE,
        target_id=target.id,
        config={"program_id": str(program.id), "program_handle": "shopify", "platform": "hackerone"},
    )
    db_session.add(scan)
    await db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        title="Reflected XSS in api.shopify.com/orders",
        description="A reflected value is returned unsafely.",
        severity=Severity.HIGH,
        url="https://api.shopify.com/orders?x=1",
        tool_source="nuclei",
        evidence={"steps_to_reproduce": ["Open the endpoint with a reflected marker."]},
        tags=["xss"],
    )
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(finding)

    submission, paths = await BBSubmissionService(db_session).create_draft(
        finding,
        tmp_path,
        formats=("md",),
        include_poc=True,
        force=True,
    )

    assert "## Proof of Concept" in submission.draft_md
    assert "## Comparable Public Reports" not in submission.draft_md
    assert "[REDACTED:aws_access_key:0]" in submission.draft_md
    assert "AKIAIOSFODNN7EXAMPLE" not in submission.draft_md
    assert submission.metadata_["comparable_reports"]
    assert paths["md"].exists()


@pytest.mark.asyncio
async def test_create_draft_blocks_verbatim_public_prior_art(monkeypatch, db_session, tmp_path: Path) -> None:
    repeated = "The order endpoint reflects attacker supplied input without output encoding. " * 10

    async def fake_build_corpus_context(*args, **kwargs):  # noqa: ANN002, ANN003
        return [repeated]

    monkeypatch.setattr(
        "netra.services.bb_submission_service.build_corpus_context",
        fake_build_corpus_context,
    )

    program = BBProgram(
        platform=BBPlatform.HACKERONE,
        handle="shopify",
        name="Shopify",
        currency="USD",
    )
    db_session.add(program)
    await db_session.flush()

    target = Target(name="bb:shopify", target_type=TargetType.DOMAIN, value="shopify")
    db_session.add(target)
    await db_session.flush()

    scan = Scan(
        name="Bug bounty passive hunt: shopify",
        profile=ScanProfile.BUGBOUNTY_PASSIVE,
        target_id=target.id,
        config={"program_id": str(program.id), "program_handle": "shopify", "platform": "hackerone"},
    )
    db_session.add(scan)
    await db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        title="Reflected XSS in api.shopify.com/orders",
        description=repeated,
        severity=Severity.HIGH,
        url="https://api.shopify.com/orders?x=1",
        tool_source="nuclei",
        evidence={"steps_to_reproduce": ["Open the endpoint with a reflected marker."]},
        tags=["xss"],
    )
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(finding)

    with pytest.raises(DraftLeakRiskError):
        await BBSubmissionService(db_session).create_draft(
            finding,
            tmp_path,
            formats=("md",),
            include_poc=False,
            force=True,
        )
