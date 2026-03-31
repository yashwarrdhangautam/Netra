"""Scan orchestrator for managing scan pipelines."""
import asyncio
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.finding import Finding
from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.scan_phase import PhaseStatus, PhaseType, ScanPhase
from netra.scanner.profiles import get_profile_config
from netra.scanner.tools.amass import AmassTool
from netra.scanner.tools.base import BaseTool, ToolResult
from netra.scanner.tools.checkov import CheckovTool
from netra.scanner.tools.dalfox import DalfoxTool
from netra.scanner.tools.dependency_scan import PipAuditTool
from netra.scanner.tools.ffuf import FfufTool
from netra.scanner.tools.gitleaks import GitleaksTool
from netra.scanner.tools.httpx import HttpxTool
from netra.scanner.tools.llm_security import LLMSecurityTool
from netra.scanner.tools.nikto import NiktoTool
from netra.scanner.tools.nmap import NmapTool
from netra.scanner.tools.nuclei import NucleiTool
from netra.scanner.tools.prowler import ProwlerTool

# Phase 2 tools
from netra.scanner.tools.semgrep import SemgrepTool
from netra.scanner.tools.sqlmap import SqlmapTool
from netra.scanner.tools.subfinder import SubfinderTool
from netra.scanner.tools.trivy import TrivyTool

logger = structlog.get_logger()

T = TypeVar("T")


class ScanOrchestrator:
    """Orchestrates the full scan pipeline."""

    def __init__(self, db: AsyncSession, scan_id: uuid.UUID) -> None:
        self.db = db
        self.scan_id = scan_id

    async def _run_tool_with_retry(
        self,
        tool: BaseTool,
        target: str,
        max_retries: int = 3,
        base_delay: float = 2.0,
        max_delay: float = 30.0,
        **kwargs: Any,
    ) -> ToolResult:
        """Run a scanner tool with exponential backoff retry.

        Args:
            tool: Tool instance to run
            target: Target for the scan
            max_retries: Maximum number of retry attempts
            base_delay: Base delay between retries in seconds
            max_delay: Maximum delay between retries
            **kwargs: Arguments passed to tool.run()

        Returns:
            ToolResult from successful run or last failed attempt
        """
        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                result = await tool.run(target, **kwargs)
                if result.success:
                    return result

                # Tool ran but failed - may still be useful data
                logger.warning(
                    "tool_partial_failure",
                    tool=tool.name,
                    target=target,
                    attempt=attempt + 1,
                    error=result.error,
                )
                return result

            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    logger.warning(
                        "tool_retry",
                        tool=tool.name,
                        target=target,
                        attempt=attempt + 1,
                        max_retries=max_retries,
                        delay=delay,
                        error=str(e),
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        "tool_exhausted_retries",
                        tool=tool.name,
                        target=target,
                        error=str(e),
                    )

        # Return failed result if available, else raise
        if last_error:
            # Create a failed ToolResult for graceful degradation
            return ToolResult(
                tool_name=tool.name if hasattr(tool, "name") else "unknown",
                target=target,
                success=False,
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
                error=str(last_error),
            )
        raise last_error

    async def execute(self) -> None:
        """Run the full scan pipeline."""
        scan = await self._get_scan()
        if not scan:
            logger.error("scan_not_found", scan_id=str(self.scan_id))
            return

        profile = get_profile_config(scan.profile)

        # Update scan status
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(UTC)
        await self.db.commit()

        try:
            # Phase 1: Subdomain enumeration
            if self._should_run_phase(scan, PhaseType.RECON_SUBDOMAINS, profile):
                subdomains = await self._run_subdomain_enum(scan, profile)
            else:
                subdomains = await self._get_cached_subdomains(scan)

            # Phase 2: Live host discovery
            if self._should_run_phase(scan, PhaseType.RECON_DISCOVERY, profile):
                live_hosts = await self._run_discovery(scan, subdomains, profile)
            else:
                live_hosts = await self._get_cached_hosts(scan)

            # Phase 3: Port scanning
            if self._should_run_phase(scan, PhaseType.RECON_PORTS, profile):
                await self._run_port_scan(scan, live_hosts, profile)

            # Phase 4: Vulnerability scanning
            if self._should_run_phase(scan, PhaseType.VULN_SCAN, profile):
                await self._run_vuln_scan(scan, live_hosts, profile)

            # Phase 5: Active testing (SQLi, XSS, etc.)
            if self._should_run_phase(scan, PhaseType.PENTEST, profile):
                await self._run_pentest(scan, live_hosts, profile)

            # Phase 6: AI analysis
            if self._should_run_phase(scan, PhaseType.AI_ANALYSIS, profile):
                await self._run_ai_analysis(scan)

            # Phase 2: SAST (Static Application Security Testing)
            if self._should_run_phase(scan, PhaseType.SAST, profile):
                await self._run_sast(scan, profile)

            # Phase 2: Secrets detection
            if self._should_run_phase(scan, PhaseType.SECRETS, profile):
                await self._run_secrets(scan, profile)

            # Phase 2: Dependency scanning
            if self._should_run_phase(scan, PhaseType.DEPENDENCIES, profile):
                await self._run_dependencies(scan, profile)

            # Phase 2: CSPM (Cloud Security Posture Management)
            if self._should_run_phase(scan, PhaseType.CSPM, profile):
                await self._run_cspm(scan, profile)

            # Phase 2: Container scanning
            if self._should_run_phase(scan, PhaseType.CONTAINER, profile):
                await self._run_container(scan, profile)

            # Phase 2: IaC scanning
            if self._should_run_phase(scan, PhaseType.IAC, profile):
                await self._run_iac(scan, profile)

            # Phase 2: AI/LLM security testing
            if self._should_run_phase(scan, PhaseType.AI_LLM, profile):
                await self._run_llm_security(scan, profile)

            # Complete
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(UTC)

        except Exception as e:
            logger.error("scan_failed", scan_id=str(self.scan_id), error=str(e))
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)

        await self.db.commit()

    async def _run_subdomain_enum(
        self, scan: Scan, profile: dict[str, Any]
    ) -> list[str]:
        """Phase: Enumerate subdomains."""
        phase = await self._create_phase(scan, PhaseType.RECON_SUBDOMAINS)

        target = scan.target.value
        all_subdomains: set[str] = set()

        try:
            # Subfinder
            subfinder = SubfinderTool(work_dir=self._phase_dir(phase))
            result = await self._run_tool_with_retry(subfinder, target)
            await self._save_findings(scan, result)
            for f in result.findings:
                if hostname := f.get("hostname") or f.get("url", ""):
                    all_subdomains.add(hostname)

            # Amass (if deep profile)
            if profile.get("use_amass", False):
                amass = AmassTool(work_dir=self._phase_dir(phase))
                result = await self._run_tool_with_retry(amass, target)
                await self._save_findings(scan, result)
                for f in result.findings:
                    if hostname := f.get("hostname") or f.get("url", ""):
                        all_subdomains.add(hostname)

            # Always include the root target
            all_subdomains.add(target)

            await self._complete_phase(phase, findings_count=len(all_subdomains))

            # Save checkpoint
            scan.checkpoint_data = {
                **(scan.checkpoint_data or {}),
                "subdomains": list(all_subdomains),
            }
            await self.db.commit()

        except Exception as e:
            logger.error("subdomain_enum_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

        return list(all_subdomains)

    async def _run_discovery(
        self, scan: Scan, subdomains: list[str], profile: dict[str, Any]
    ) -> list[str]:
        """Phase: Probe for live HTTP services."""
        phase = await self._create_phase(scan, PhaseType.RECON_DISCOVERY)
        live_hosts: list[str] = []

        try:
            if not subdomains:
                await self._complete_phase(phase, findings_count=0)
                return []

            httpx_tool = HttpxTool(work_dir=self._phase_dir(phase))
            result = await self._run_tool_with_retry(
                httpx_tool,
                ",".join(subdomains[:profile.get("max_targets", 50)]),
                follow_redirects=True,
                tech_detect=True,
            )
            await self._save_findings(scan, result)

            live_hosts = [
                f.get("url", "")
                for f in result.findings
                if f.get("status_code", 0) in range(200, 500)
            ]

            await self._complete_phase(phase, findings_count=len(live_hosts))

            # Save checkpoint
            scan.checkpoint_data = {
                **(scan.checkpoint_data or {}),
                "live_hosts": live_hosts,
            }
            await self.db.commit()

        except Exception as e:
            logger.error("discovery_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

        return live_hosts

    async def _run_port_scan(
        self, scan: Scan, targets: list[str], profile: dict[str, Any]
    ) -> None:
        """Phase: Port scanning with Nmap."""
        phase = await self._create_phase(scan, PhaseType.RECON_PORTS)
        total_findings = 0

        try:
            nmap = NmapTool(work_dir=self._phase_dir(phase))
            for target in targets[:profile.get("max_targets", 50)]:
                result = await self._run_tool_with_retry(
                    nmap,
                    target=target,
                    ports=profile.get("port_range", "top-1000"),
                )
                await self._save_findings(scan, result)
                total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("port_scan_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _run_vuln_scan(
        self, scan: Scan, targets: list[str], profile: dict[str, Any]
    ) -> None:
        """Phase: Vulnerability scanning with Nuclei + Nikto."""
        phase = await self._create_phase(scan, PhaseType.VULN_SCAN)
        total_findings = 0

        try:
            # Nuclei
            nuclei = NucleiTool(work_dir=self._phase_dir(phase))
            for target in targets[:profile.get("max_targets", 50)]:
                result = await self._run_tool_with_retry(
                    nuclei,
                    target=target,
                    severity=profile.get("severity_filter", "critical,high,medium"),
                    rate_limit=profile.get("rate_limit", 150),
                )
                await self._save_findings(scan, result)
                total_findings += len(result.findings)

            # Nikto for web server misconfigs
            if profile.get("use_nikto", True):
                nikto = NiktoTool(work_dir=self._phase_dir(phase))
                for target in targets[:10]:  # Nikto is slow, limit targets
                    result = await self._run_tool_with_retry(nikto, target=target)
                    await self._save_findings(scan, result)
                    total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("vuln_scan_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _run_pentest(
        self, scan: Scan, targets: list[str], profile: dict[str, Any]
    ) -> None:
        """Phase: Active exploitation testing."""
        phase = await self._create_phase(scan, PhaseType.PENTEST)
        total_findings = 0

        try:
            # Get URLs with parameters from previous findings
            injectable_urls = await self._get_parameterized_urls(scan)

            # SQLi testing
            if profile.get("test_sqli", True):
                sqlmap = SqlmapTool(work_dir=self._phase_dir(phase))
                for url in injectable_urls[:profile.get("max_injection_tests", 20)]:
                    result = await sqlmap.run(
                        target=url,
                        safe_mode=True,
                        level=profile.get("sqlmap_level", 1),
                        risk=profile.get("sqlmap_risk", 1),
                    )
                    await self._save_findings(scan, result)
                    total_findings += len(result.findings)

            # XSS testing
            if profile.get("test_xss", True):
                dalfox = DalfoxTool(work_dir=self._phase_dir(phase))
                for url in injectable_urls[:profile.get("max_injection_tests", 20)]:
                    result = await dalfox.run(target=url)
                    await self._save_findings(scan, result)
                    total_findings += len(result.findings)

            # Directory fuzzing
            if profile.get("test_dirs", True):
                ffuf = FfufTool(work_dir=self._phase_dir(phase))
                for target in targets[:10]:
                    result = await ffuf.run(
                        target=f"{target}/FUZZ",
                        wordlist=profile.get("wordlist", "common.txt"),
                    )
                    await self._save_findings(scan, result)
                    total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("pentest_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _run_ai_analysis(self, scan: Scan) -> None:
        """Phase: AI Brain analysis and enrichment."""
        phase = await self._create_phase(scan, PhaseType.AI_ANALYSIS)

        try:
            from netra.ai.brain import AIBrain

            brain = AIBrain()
            findings = await self._get_scan_findings(scan)

            enriched_count = 0
            for finding in findings:
                enriched = await brain.analyze_finding(finding)
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

    # ── Phase 2 Methods ──

    async def _run_sast(self, scan: Scan, profile: dict[str, Any]) -> None:
        """Phase 2: SAST scanning with Semgrep."""
        phase = await self._create_phase(scan, PhaseType.SAST)
        total_findings = 0

        try:
            # Get source path from scan config
            source_path = scan.config.get("source_path", scan.target.value)

            semgrep = SemgrepTool(work_dir=self._phase_dir(phase))
            result = await semgrep.run(
                source_path,
                ruleset=profile.get("ruleset", "all"),
                max_findings=profile.get("max_findings", 500),
            )
            await self._save_findings(scan, result)
            total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("sast_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _run_secrets(self, scan: Scan, profile: dict[str, Any]) -> None:
        """Phase 2: Secrets detection with Gitleaks."""
        phase = await self._create_phase(scan, PhaseType.SECRETS)
        total_findings = 0

        try:
            source_path = scan.config.get("source_path", scan.target.value)

            gitleaks = GitleaksTool(work_dir=self._phase_dir(phase))
            result = await gitleaks.run(source_path, scan_history=True)
            await self._save_findings(scan, result)
            total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("secrets_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _run_dependencies(self, scan: Scan, profile: dict[str, Any]) -> None:
        """Phase 2: Dependency vulnerability scanning."""
        phase = await self._create_phase(scan, PhaseType.DEPENDENCIES)
        total_findings = 0

        try:
            source_path = scan.config.get("source_path", scan.target.value)

            pip_audit = PipAuditTool(work_dir=self._phase_dir(phase))
            result = await pip_audit.run(source_path)
            await self._save_findings(scan, result)
            total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("dependencies_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _run_cspm(self, scan: Scan, profile: dict[str, Any]) -> None:
        """Phase 2: Cloud Security Posture Management with Prowler."""
        phase = await self._create_phase(scan, PhaseType.CSPM)
        total_findings = 0

        try:
            provider = profile.get("provider", "aws")
            compliance = profile.get("compliance_framework", "")

            prowler = ProwlerTool(work_dir=self._phase_dir(phase))
            result = await prowler.run(
                provider,
                provider=provider,
                compliance=compliance,
            )
            await self._save_findings(scan, result)
            total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("cspm_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _run_container(self, scan: Scan, profile: dict[str, Any]) -> None:
        """Phase 2: Container image scanning with Trivy."""
        phase = await self._create_phase(scan, PhaseType.CONTAINER)
        total_findings = 0

        try:
            image_name = scan.target.value

            trivy = TrivyTool(work_dir=self._phase_dir(phase))
            result = await trivy.run(
                image_name,
                scan_type="image",
                severity=profile.get("severity_filter", "CRITICAL,HIGH"),
            )
            await self._save_findings(scan, result)
            total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("container_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _run_iac(self, scan: Scan, profile: dict[str, Any]) -> None:
        """Phase 2: IaC scanning with Checkov."""
        phase = await self._create_phase(scan, PhaseType.IAC)
        total_findings = 0

        try:
            iac_path = scan.config.get("source_path", scan.target.value)
            framework = profile.get("framework", "")

            checkov = CheckovTool(work_dir=self._phase_dir(phase))
            result = await checkov.run(iac_path, framework=framework)
            await self._save_findings(scan, result)
            total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("iac_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    async def _run_llm_security(self, scan: Scan, profile: dict[str, Any]) -> None:
        """Phase 2: AI/LLM security testing for OWASP LLM Top 10."""
        phase = await self._create_phase(scan, PhaseType.AI_LLM)
        total_findings = 0

        try:
            llm_endpoint = scan.target.value
            test_categories = profile.get(
                "test_categories",
                ["direct_injection", "jailbreak", "data_exfiltration", "excessive_agency"],
            )

            llm_scanner = LLMSecurityTool(work_dir=self._phase_dir(phase))
            result = await llm_scanner.run(
                llm_endpoint,
                test_categories=test_categories,
                max_payloads=profile.get("max_payloads", 10),
            )
            await self._save_findings(scan, result)
            total_findings += len(result.findings)

            await self._complete_phase(phase, findings_count=total_findings)

        except Exception as e:
            logger.error("llm_security_failed", phase=phase.id, error=str(e))
            await self._fail_phase(phase, str(e))

    # ── Helper Methods ──

    async def _get_scan(self) -> Scan | None:
        """Get scan by ID."""
        result = await self.db.execute(select(Scan).where(Scan.id == self.scan_id))
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
        logger.info("phase_started", scan_id=str(scan.id), phase=phase_type.value)
        return phase

    async def _complete_phase(
        self, phase: ScanPhase, findings_count: int = 0
    ) -> None:
        """Mark a scan phase as completed."""
        phase.status = PhaseStatus.COMPLETED
        phase.completed_at = datetime.now(UTC)
        phase.findings_count = findings_count
        await self.db.commit()
        logger.info(
            "phase_completed",
            phase=phase.phase_type.value,
            findings=findings_count,
        )

    async def _fail_phase(self, phase: ScanPhase, error: str) -> None:
        """Mark a scan phase as failed."""
        phase.status = PhaseStatus.FAILED
        phase.completed_at = datetime.now(UTC)
        phase.error_message = error
        await self.db.commit()
        logger.error("phase_failed", phase=phase.phase_type.value, error=error)

    async def _save_findings(self, scan: Scan, result: ToolResult) -> None:
        """Save tool results as findings in the database."""
        for finding_data in result.findings:
            finding = Finding(
                scan_id=scan.id,
                target_id=scan.target_id,
                title=finding_data.get("title", "Unknown"),
                description=finding_data.get("description", ""),
                severity=finding_data.get("severity", "info"),
                confidence=finding_data.get("confidence", 50),
                tool_source=result.tool_name,
                evidence=finding_data.get("evidence", {}),
                cwe_id=finding_data.get("cwe_id"),
                cvss_score=finding_data.get("cvss_score"),
            )
            self.db.add(finding)
        await self.db.commit()

    async def _get_scan_findings(self, scan: Scan) -> list[Finding]:
        """Get all findings for a scan."""
        result = await self.db.execute(
            select(Finding).where(Finding.scan_id == scan.id)
        )
        return list(result.scalars().all())

    async def _get_parameterized_urls(self, scan: Scan) -> list[str]:
        """Extract URLs with parameters from scan findings for injection testing."""
        findings = await self._get_scan_findings(scan)
        urls: list[str] = []
        for f in findings:
            if f.evidence and "url" in f.evidence:
                url = f.evidence["url"]
                if "?" in url or "=" in url:
                    urls.append(url)
        return urls

    async def _run_tool_with_retry(
        self, tool: Any, *args: Any, max_retries: int = 2, **kwargs: Any
    ) -> ToolResult:
        """Run a tool with retry logic."""
        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                return await tool.run(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < max_retries:
                    logger.warning(
                        "tool_retry",
                        tool=tool.__class__.__name__,
                        attempt=attempt + 1,
                        error=str(e),
                    )
        return ToolResult(
            tool_name=tool.__class__.__name__,
            success=False,
            findings=[],
            error=str(last_error),
        )

    def _phase_dir(self, phase: ScanPhase) -> Path:
        """Get working directory for a phase."""
        from netra.core.config import settings

        base = settings.evidence_dir / str(phase.scan_id) / phase.phase_type.value
        base.mkdir(parents=True, exist_ok=True)
        return base
