"""Scan orchestrator for managing scan pipelines."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netra.db.models.bb_asset import BBAsset
from netra.db.models.bb_program import BBProgram
from netra.db.models.bb_scope_rule import BBScopeRule, ScopeRuleType
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.scan_phase import PhaseStatus, PhaseType, ScanPhase
from netra.scanner.tools.base import ToolResult

# Phase 2 tools

logger = structlog.get_logger()


class ScanOrchestrator:
    """Orchestrates the full scan pipeline."""

    def __init__(self, db: AsyncSession, scan_id: uuid.UUID) -> None:
        self.db = db
        self.scan_id = scan_id

    async def execute(self) -> None:
        """Run the full scan pipeline."""
        scan = await self._get_scan()
        if not scan:
            logger.error("scan_not_found", scan_id=str(self.scan_id))
            return

        if str(scan.profile) in {"bugbounty_passive", "bugbounty_active"}:
            await self._execute_bugbounty_scan(scan)
            return

        # The legacy standard path is not a second authorization implementation.
        # Standard execution must use the guarded Celery pipeline.
        scan.status = ScanStatus.FAILED
        scan.error_message = "standard_orchestrator_unavailable"
        scan.completed_at = datetime.now(UTC)
        await self.db.commit()
        return

    async def _run_ai_analysis(self, scan: Scan) -> None:
        """Phase: AI Brain analysis and enrichment."""
        phase = await self._create_phase(scan, PhaseType.AI_ANALYSIS)

        try:
            from netra.ai.brain import AIBrain

            brain = AIBrain()
            findings = await self._get_scan_findings(scan)
            program = None
            if str(scan.profile) in {"bugbounty_passive", "bugbounty_active"}:
                program_id = (scan.config or {}).get("program_id")
                if program_id:
                    if isinstance(program_id, str):
                        program_id = uuid.UUID(program_id)
                    program = await self.db.get(BBProgram, program_id)

            enriched_count = 0
            for finding in findings:
                similar_reports = await self._finding_corpus_hits(finding, program)
                enriched = await brain.analyze_finding(
                    finding,
                    program=program,
                    similar_reports=similar_reports,
                )
                if enriched:
                    finding.ai_analysis = enriched
                    finding.confidence = enriched.get("confidence", finding.confidence)
                    enriched_count += 1

            # Attack chain discovery
            chains = await brain.discover_attack_chains(findings)
            scan.checkpoint_data = {
                **(scan.checkpoint_data or {}),
                "attack_chains": chains,
            }

            await self._complete_phase(phase, findings_count=enriched_count)
            await self.db.commit()

        except Exception as e:
            logger.error("ai_analysis_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _execute_bugbounty_scan(self, scan: Scan) -> None:
        """Run NETRA-BB passive/active profiles with a hard scope gate."""
        from netra.bugbounty.agentic.budget import HuntBudget
        from netra.bugbounty.agentic.executor import AgenticExecutor
        from netra.bugbounty.agentic.planner import Planner
        from netra.bugbounty.graph_indexer import index_recon_output
        from netra.bugbounty.recon.active import run_active_recon
        from netra.bugbounty.recon.passive import run_passive_recon
        from netra.bugbounty.scope import ScopeValidator

        program_id = (scan.config or {}).get("program_id")
        if not program_id:
            scan.status = ScanStatus.FAILED
            scan.error_message = "bug bounty scan missing config.program_id"
            await self.db.commit()
            return
        if isinstance(program_id, str):
            program_id = uuid.UUID(program_id)

        program = await self.db.get(BBProgram, program_id)
        if not program:
            scan.status = ScanStatus.FAILED
            scan.error_message = f"bug bounty program not found: {program_id}"
            await self.db.commit()
            return

        rules_result = await self.db.execute(
            select(BBScopeRule).where(
                BBScopeRule.program_id == program.id,
                BBScopeRule.active.is_(True),
            )
        )
        rules = list(rules_result.scalars().all())
        validator = ScopeValidator.from_db_rules(rules)

        if scan.status == ScanStatus.CANCELLED:
            scan.completed_at = scan.completed_at or datetime.now(UTC)
            await self.db.commit()
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(UTC)
        await self.db.commit()

        try:
            allow_rules = [r.pattern for r in rules if r.rule_type == ScopeRuleType.IN]
            seed_domains = allow_rules or [scan.target.value]
            if bool((scan.config or {}).get("agentic")):
                phase = await self._create_phase(scan, PhaseType.RECON_OSINT)
                planner = Planner()
                asset_facts = await self._build_agentic_asset_facts(program, scan, seed_domains)
                corpus_hits = await self._build_agentic_corpus_hits(program, asset_facts)
                plan = await planner.make_plan(
                    asset_facts=asset_facts,
                    scope=seed_domains,
                    corpus_hits=corpus_hits,
                )
                phase.tool_outputs = {"agentic_plan": plan.to_dict()}
                await self._complete_phase(phase, findings_count=len(plan.steps))

                executor = AgenticExecutor(self.db)
                result = await executor.run_plan(
                    scan=scan,
                    program=program,
                    plan=plan,
                    validator=validator,
                    budget=HuntBudget(),
                    dry_run=bool((scan.config or {}).get("dry_run")),
                )
                scan.checkpoint_data = {
                    **(scan.checkpoint_data or {}),
                    "bb_program_handle": program.handle,
                    "agentic": True,
                    "agentic_plan": plan.to_dict(),
                    "agentic_coordination": plan.coordination,
                    "agentic_corpus_hits": corpus_hits,
                    "agentic_observations": result.get("observations", []),
                }
                if result.get("cancelled"):
                    scan.status = ScanStatus.CANCELLED
                    scan.completed_at = datetime.now(UTC)
                    await self.db.commit()
                    return
                await self._run_ai_analysis(scan)
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(UTC)
                await self.db.commit()
                return

            phase = await self._create_phase(scan, PhaseType.RECON_OSINT)
            passive = await run_passive_recon(seed_domains, validator, program.handle)

            for host in passive.in_scope_hosts:
                await self._upsert_bb_asset(program, host, {"source": "passive"})

            phase.tool_outputs = {
                "sources": passive.sources,
                "in_scope_hosts": passive.in_scope_hosts,
                "out_of_scope_hosts": passive.out_of_scope_hosts,
                "errors": passive.errors,
            }
            await self._complete_phase(phase, findings_count=len(passive.in_scope_hosts))

            if str(scan.profile) == "bugbounty_active":
                active_phase = await self._create_phase(scan, PhaseType.RECON_DISCOVERY)
                active = await run_active_recon(
                    passive.in_scope_hosts,
                    validator,
                    enable_alive=True,
                    enable_ffuf=bool((scan.config or {}).get("enable_ffuf")),
                    enable_nuclei=bool((scan.config or {}).get("enable_nuclei")),
                    rate_limit=(scan.config or {}).get("rate_limit"),
                )
                active_phase.tool_outputs = {
                    "alive_hosts": active.alive_hosts,
                    "discovered_paths": active.discovered_paths,
                    "nuclei_findings": active.nuclei_findings,
                    "blocked_targets": active.blocked_targets,
                    "errors": active.errors,
                }
                await self._complete_phase(
                    active_phase,
                    findings_count=len(active.nuclei_findings) + len(active.discovered_paths),
                )

            try:
                await index_recon_output(program.handle, Path("data/graphify/recon"))
            except Exception as exc:
                logger.warning(
                    "bb.graphify.recon_index_failed", program=program.handle, error=str(exc)
                )

            scan.checkpoint_data = {
                **(scan.checkpoint_data or {}),
                "bb_program_handle": program.handle,
                "bb_in_scope_hosts": passive.in_scope_hosts,
                "bb_out_of_scope_hosts": passive.out_of_scope_hosts,
            }
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(UTC)
        except Exception as exc:
            logger.error("bb.scan_failed", scan_id=str(scan.id), error=str(exc), exc_info=True)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
        await self.db.commit()

    async def _build_agentic_asset_facts(
        self,
        program: BBProgram,
        scan: Scan,
        seed_domains: list[str],
    ) -> dict[str, Any]:
        """Build a richer planner context from known assets and prior findings."""
        asset_rows = await self.db.execute(
            select(BBAsset)
            .where(BBAsset.program_id == program.id)
            .order_by(BBAsset.last_seen.desc())
        )
        assets = list(asset_rows.scalars().all())

        finding_rows = await self.db.execute(select(Finding).where(Finding.scan_id == scan.id))
        findings = list(finding_rows.scalars().all())

        tech = sorted(
            {
                str(item).strip()
                for asset in assets
                for item in (asset.tech or [])
                if str(item).strip()
            }
        )
        known_hosts = sorted({asset.host for asset in assets if asset.host})
        prior_vuln_classes = sorted(
            {
                str(tag).strip()
                for finding in findings
                for tag in (finding.tags or [])
                if str(tag).strip()
            }
        )
        return {
            "target": scan.target.value,
            "program_handle": program.handle,
            "program_name": program.name,
            "policy_url": program.policy_url,
            "payout_min": program.payout_min,
            "payout_max": program.payout_max,
            "seed_domains": seed_domains,
            "known_hosts": known_hosts[:20],
            "tech": tech[:20],
            "prior_vuln_classes": prior_vuln_classes[:20],
            "active_classes_approved": list(program.active_classes_approved or []),
        }

    async def _build_agentic_corpus_hits(
        self,
        program: BBProgram,
        asset_facts: dict[str, Any],
    ) -> list[str]:
        """Retrieve compact public-corpus context for planning and triage."""
        from netra.bugbounty.learning.search import build_corpus_context

        query_parts = [
            str(program.handle or ""),
            str(program.name or ""),
            *[str(item) for item in asset_facts.get("tech", [])[:5]],
            *[str(item) for item in asset_facts.get("prior_vuln_classes", [])[:5]],
            *[str(item) for item in asset_facts.get("known_hosts", [])[:3]],
        ]
        query = " ".join(part for part in query_parts if part).strip()
        filters = {"program_handle": program.handle}
        hits = await build_corpus_context(
            self.db,
            query or program.handle,
            top_k=5,
            filters=filters,
        )
        if hits:
            return hits
        fallback_filters = {"vuln_class": (asset_facts.get("prior_vuln_classes") or [None])[0]}
        return await build_corpus_context(
            self.db,
            query or program.handle,
            top_k=5,
            filters=fallback_filters,
        )

    async def _finding_corpus_hits(
        self,
        finding: Finding,
        program: BBProgram | None,
    ) -> list[str]:
        """Find compact similar-report context for BountyHunter scoring."""
        from netra.bugbounty.learning.search import build_corpus_context

        vuln_class = (
            str((finding.tags or [finding.cwe_id or "finding"])[0]).strip().lower()
            if (finding.tags or finding.cwe_id)
            else "finding"
        )
        query = " ".join(
            filter(
                None,
                [
                    program.handle if program else "",
                    finding.title,
                    finding.url or "",
                    vuln_class,
                ],
            )
        )
        filters: dict[str, Any] = {"vuln_class": vuln_class}
        if program is not None:
            filters["program_handle"] = program.handle
        hits = await build_corpus_context(self.db, query, top_k=5, filters=filters)
        if hits:
            return hits
        fallback = {"vuln_class": vuln_class}
        return await build_corpus_context(self.db, query, top_k=3, filters=fallback)

    async def _upsert_bb_asset(
        self, program: BBProgram, host: str, metadata: dict[str, Any]
    ) -> BBAsset:
        """Create or refresh a BB asset row."""
        result = await self.db.execute(
            select(BBAsset).where(BBAsset.program_id == program.id, BBAsset.host == host)
        )
        asset = result.scalar_one_or_none()
        if asset is None:
            asset = BBAsset(program_id=program.id, host=host, metadata_=metadata)
            self.db.add(asset)
        else:
            asset.last_seen = datetime.now(UTC)
            asset.metadata_ = {**(asset.metadata_ or {}), **metadata}
        await self.db.flush()
        return asset

    # ── Helper Methods ──

    async def _get_scan(self) -> Scan | None:
        """Get scan by ID."""
        result = await self.db.execute(
            select(Scan).options(selectinload(Scan.target)).where(Scan.id == self.scan_id)
        )
        return result.scalar_one_or_none()

    async def _create_phase(self, scan: Scan, phase_type: PhaseType) -> ScanPhase:
        """Create a new scan phase."""
        phase = ScanPhase(
            scan_id=scan.id,
            phase_type=phase_type,
            status=PhaseStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        self.db.add(phase)
        await self.db.commit()
        return phase

    async def _complete_phase(self, phase: ScanPhase, findings_count: int = 0) -> None:
        """Mark a phase as completed."""
        phase.status = PhaseStatus.COMPLETED
        phase.completed_at = datetime.now(UTC)
        phase.progress = 1.0
        phase.findings_count = findings_count
        await self.db.commit()

    async def _fail_phase(self, phase: ScanPhase, error: str) -> None:
        """Mark a phase as failed."""
        phase.status = PhaseStatus.FAILED
        phase.completed_at = datetime.now(UTC)
        phase.error_message = error
        await self.db.commit()

    async def _save_findings(self, scan: Scan, result: ToolResult) -> None:
        """Save tool results as Finding records with deduplication."""
        from netra.services.finding_service import FindingService

        service = FindingService(self.db)
        for f_data in result.findings:
            await service.create_finding_from_tool(
                scan_id=scan.id,
                tool_name=result.tool_name,
                finding_data=f_data,
            )

    def _phase_dir(self, phase: ScanPhase) -> Path:
        """Get working directory for a phase."""
        d = Path.home() / ".netra" / "scans" / str(phase.scan_id)[:8] / phase.phase_type
        d.mkdir(parents=True, exist_ok=True)
        return d

    async def _get_scan_findings(self, scan: Scan) -> list[Finding]:
        """Get all findings for a scan."""
        result = await self.db.execute(select(Finding).where(Finding.scan_id == scan.id))
        return list(result.scalars().all())
