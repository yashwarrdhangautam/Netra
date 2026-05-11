"""Bug bounty submission business logic."""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.agentic.poc_builder import PocBuilder
from netra.bugbounty.evidence.redactor import RedactionHit, redact_text
from netra.bugbounty.learning.search import build_corpus_context
from netra.bugbounty.submission.draft import (
    DraftSections,
    detect_verbatim_overlap,
    render_markdown,
)
from netra.bugbounty.submission.payout import estimate_payout
from netra.bugbounty.triage.deduper import fingerprint, is_duplicate, record_signature
from netra.db.models.bb_program import BBProgram
from netra.db.models.bb_submission import BBSubmission
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.services.templates.h1_submission import build_h1_docx


class DuplicateFindingError(RuntimeError):
    """Raised when drafting a duplicate without --force."""


class DraftLeakRiskError(RuntimeError):
    """Raised when a generated draft overlaps too heavily with public prior art."""


class BBSubmissionService:
    """Create and update bug bounty submissions."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def program_for_finding(self, finding: Finding) -> BBProgram | None:
        scan = await self.db.get(Scan, finding.scan_id)
        if not scan or not (scan.config or {}).get("program_id"):
            return None
        program_id = (scan.config or {})["program_id"]
        if isinstance(program_id, str):
            program_id = uuid.UUID(program_id)
        return await self.db.get(BBProgram, program_id)

    async def create_draft(
        self,
        finding: Finding,
        output_dir: Path,
        formats: tuple[str, ...] = ("md", "docx"),
        *,
        force: bool = False,
        include_poc: bool = False,
    ) -> tuple[BBSubmission, dict[str, Path]]:
        """Create a submission row and requested artifacts."""
        program = await self.program_for_finding(finding)
        if program is None:
            raise RuntimeError("Finding is not attached to a bug bounty program scan")

        vuln_class = self._vuln_class(finding)
        asset = finding.url or "affected asset"
        fp = fingerprint(vuln_class, urlparse(asset).path or asset, finding.parameter or "")
        dup = await is_duplicate(self.db, program.id, fp)
        if dup and not force:
            raise DuplicateFindingError(f"Duplicate of finding {dup.finding_id}; pass --force to draft anyway")

        title = self._title(finding, vuln_class, asset)
        poc = None
        if include_poc:
            poc = await PocBuilder().build(
                {
                    "title": finding.title,
                    "description": finding.description,
                    "severity": str(finding.severity),
                    "url": finding.url,
                },
                finding.evidence or {},
                vuln_class,
            )
        style_examples = await self._style_examples(program, finding, vuln_class)
        sections = self._sections(
            finding,
            title,
            proof_of_concept=poc,
            comparable_reports=style_examples,
        )
        rendered = render_markdown(sections)
        overlap = self._detect_public_report_overlap(rendered, style_examples)
        if overlap:
            raise DraftLeakRiskError(
                "Draft overlaps too closely with retrieved public prior art. "
                "Review the finding manually before drafting."
            )
        # Defence in depth: redact secrets from anything that ended up in the rendered
        # markdown before persisting or writing artifacts. The pipeline.store_evidence
        # path covers raw uploaded bytes; this covers strings that flowed through the
        # finding model into AI summaries or reproduction steps.
        markdown, redaction_hits = self._redact_draft(rendered)
        payout = estimate_payout(str(finding.severity), program.payout_min, program.payout_max, program.currency)

        submission = BBSubmission(
            finding_id=finding.id,
            program_id=program.id,
            title=title,
            draft_md=markdown,
            severity=str(finding.severity),
            cvss_vector=finding.cvss_vector,
            payout_expected=payout.estimate if payout else None,
            currency=program.currency,
            metadata_={
                "dedup_hash": fp.hash(),
                "duplicate_of": str(dup.finding_id) if dup else None,
                "redaction_count": len(redaction_hits),
                "redaction_rules": sorted({h.rule_id for h in redaction_hits}),
                "has_poc": bool(poc),
                "comparable_reports": style_examples,
            },
        )
        self.db.add(submission)
        await self.db.flush()
        if not dup:
            await record_signature(self.db, finding.id, program.id, fp, asset, vuln_class)

        output_dir.mkdir(parents=True, exist_ok=True)
        stem = f"{program.handle}-{str(finding.id)[:8]}"
        paths: dict[str, Path] = {}
        if "md" in formats:
            md_path = output_dir / f"{stem}.md"
            md_path.write_text(markdown, encoding="utf-8")
            paths["md"] = md_path
        if "docx" in formats:
            paths["docx"] = build_h1_docx(finding, submission, output_dir / f"{stem}.docx")
        if "pdf" in formats:
            pdf_path = output_dir / f"{stem}.pdf"
            pdf_path.write_text(markdown, encoding="utf-8")
            paths["pdf"] = pdf_path

        await self.db.commit()
        return submission, paths

    async def list_submissions(self, status: str | None = None) -> list[BBSubmission]:
        stmt = select(BBSubmission).order_by(BBSubmission.created_at.desc())
        if status:
            stmt = stmt.where(BBSubmission.status == status)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    def _sections(
        self,
        finding: Finding,
        title: str,
        proof_of_concept: str | None = None,
        comparable_reports: list[str] | None = None,
    ) -> DraftSections:
        evidence = finding.evidence or {}
        ai = finding.ai_analysis or {}
        defender = ai.get("defender", {})
        attacker = ai.get("attacker", {})
        bounty = ai.get("bounty_hunter", {})
        steps = evidence.get("steps_to_reproduce") if isinstance(evidence, dict) else None
        if not steps:
            steps = [
                f"Open {finding.url or 'the affected asset'}.",
                "Use the attached evidence to reproduce the issue.",
                "Confirm the observed behavior matches the impact statement.",
            ]
        refs = evidence.get("references", []) if isinstance(evidence, dict) else []
        return DraftSections(
            title=title,
            summary=finding.description or title,
            steps_to_reproduce=[str(s) for s in steps],
            impact=bounty.get("rationale") or attacker.get("business_impact") or "Impact requires operator validation.",
            suggested_fix=defender.get("immediate_fix") or finding.remediation,
            references=[str(r) for r in refs],
            proof_of_concept=proof_of_concept,
            comparable_reports=comparable_reports,
        )

    async def _style_examples(
        self,
        program: BBProgram,
        finding: Finding,
        vuln_class: str,
    ) -> list[str]:
        """Fetch compact public prior-art examples to include as drafting context."""
        query = " ".join(
            filter(
                None,
                [
                    program.handle,
                    str(program.platform),
                    finding.title,
                    vuln_class,
                    finding.url or "",
                ],
            )
        )
        examples = await build_corpus_context(
            self.db,
            query,
            top_k=3,
            filters={"program_handle": program.handle, "vuln_class": vuln_class},
        )
        if examples:
            return examples
        return await build_corpus_context(
            self.db,
            query,
            top_k=3,
            filters={"vuln_class": vuln_class},
        )

    @staticmethod
    def _redact_draft(markdown: str) -> tuple[str, list[RedactionHit]]:
        """Strip secrets from a rendered draft before it's persisted or written to disk.

        Pure function so it's unit-testable without a DB session. Uses the same rule set
        as the evidence pipeline so that redaction is consistent across surfaces.
        """
        return redact_text(markdown)

    @staticmethod
    def _detect_public_report_overlap(markdown: str, style_examples: list[str]) -> str | None:
        """Block drafts that quote retrieved examples too closely."""
        return detect_verbatim_overlap(markdown, style_examples)

    def _vuln_class(self, finding: Finding) -> str:
        tags = finding.tags or []
        if tags:
            return str(tags[0])
        if finding.cwe_id:
            return str(finding.cwe_id)
        return finding.title.split()[0].lower() if finding.title else "finding"

    def _title(self, finding: Finding, vuln_class: str, asset: str) -> str:
        if finding.title and finding.title != "Unknown Finding":
            return finding.title
        from netra.bugbounty.submission.draft import title_from_class

        return title_from_class(vuln_class, asset)
