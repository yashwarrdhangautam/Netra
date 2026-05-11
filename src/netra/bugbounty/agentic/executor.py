"""Execute a bounded agentic hunt plan."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.agentic.budget import HuntBudget
from netra.bugbounty.agentic.observation import observation_from_tool_result
from netra.bugbounty.agentic.planner import PlannedStep, TestPlan
from netra.bugbounty.agentic.router import ToolRouter
from netra.bugbounty.agentic.tool_registry import SafetyClass, get_tool_spec
from netra.bugbounty.scope import ScopeValidator
from netra.db.models.bb_agentic_step import BBAgenticStep
from netra.db.models.bb_hunt_budget import BBHuntBudget
from netra.db.models.bb_hunt_plan import BBHuntPlan
from netra.db.models.bb_program import BBProgram
from netra.db.models.finding import Severity
from netra.db.models.scan import Scan, ScanStatus
from netra.scanner.tools.ffuf import FfufTool
from netra.scanner.tools.httpx import HttpxTool
from netra.scanner.tools.nuclei import NucleiTool
from netra.scanner.tools.subfinder import SubfinderTool


class AgenticExecutor:
    """Run a test plan through the safe tool router and existing wrappers."""

    def __init__(self, db: AsyncSession, router: ToolRouter | None = None) -> None:
        self.db = db
        self.router = router or ToolRouter()

    async def run_plan(
        self,
        *,
        scan,
        program: BBProgram,
        plan: TestPlan,
        validator: ScopeValidator,
        budget: HuntBudget,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        persisted_plan = await self._persist_plan(scan.id, plan, status="planned")
        await self._persist_budget(scan.id, budget)

        observations: list[dict[str, Any]] = []
        created_findings = 0

        for index, step in enumerate(plan.steps, start=1):
            if budget.exhausted():
                break
            if await self._is_cancelled(scan.id):
                persisted_plan.status = "cancelled"
                persisted_plan.completed_at = datetime.now(timezone.utc)
                await self.db.commit()
                return {
                    "plan_id": str(persisted_plan.id),
                    "observations": observations,
                    "created_findings": created_findings,
                    "cancelled": True,
                }
            choice = await self.router.next_tool(
                plan=plan.to_dict(),
                observations=observations,
                validator=validator,
                available_tools=[step.suggested_tool],
            )
            step_row = BBAgenticStep(
                scan_id=scan.id,
                plan_id=persisted_plan.id,
                step_n=index,
                status="planned" if dry_run else "running",
                tool_chosen=choice.tool,
                llm_prompt=f"step:{step.vuln_class}",
                llm_response=choice.raw_response,
                observations_in={"count": len(observations)},
                decision_rationale=choice.rationale or step.hypothesis,
                metadata_={"target": choice.target, "vuln_class": step.vuln_class},
            )
            self.db.add(step_row)
            await self.db.flush()

            if dry_run:
                step_row.status = "skipped"
                continue

            if not self._program_allows_step(program, step, choice.tool):
                step_row.status = "blocked"
                step_row.decision_rationale = (
                    f"Program has not approved active testing for vuln class {step.vuln_class}"
                )
                await self.db.commit()
                continue

            result = await self._execute_choice(choice)
            budget.record_tool()
            obs = observation_from_tool_result(result)
            observations.append(obs.to_dict())

            findings = result.findings or []
            created_findings += len(findings)
            from netra.services.finding_service import FindingService

            service = FindingService(self.db)
            for finding in findings:
                created = await service.create_finding_from_tool(scan.id, result.tool_name, finding)
                if created:
                    created.severity = service._normalize_severity(  # noqa: SLF001
                        finding.get("severity", Severity.INFO)
                    )
            step_row.status = "confirmed" if findings else "exhausted"
            step_row.observations_out = obs.to_dict()
            await self.db.commit()

        persisted_plan.status = "completed" if not dry_run else "dry_run"
        persisted_plan.completed_at = datetime.now(timezone.utc)
        await self.db.commit()
        return {"plan_id": str(persisted_plan.id), "observations": observations, "created_findings": created_findings}

    async def _persist_plan(self, scan_id, plan: TestPlan, status: str) -> BBHuntPlan:
        row = BBHuntPlan(
            scan_id=scan_id,
            status=status,
            json_plan=plan.to_dict(),
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(row)
        await self.db.flush()
        return row

    async def _persist_budget(self, scan_id, budget: HuntBudget) -> BBHuntBudget:
        row = BBHuntBudget(
            scan_id=scan_id,
            max_tools=budget.max_tools,
            wallclock_minutes=budget.wallclock_minutes,
            per_tool_concurrency=budget.per_tool_concurrency,
            tools_used=budget.tools_used,
            status="active",
        )
        self.db.add(row)
        await self.db.commit()
        return row

    async def _execute_choice(self, choice) -> Any:
        spec = get_tool_spec(choice.tool)
        kwargs = dict(choice.flags)
        if choice.tool == "subfinder":
            return await SubfinderTool().run(choice.target, passive_only=True, **kwargs)
        if choice.tool == "httpx":
            return await HttpxTool().run(choice.target, head=True, tech_detect=True, **kwargs)
        if choice.tool == "nuclei":
            return await NucleiTool().run(choice.target, tags="cve,exposure,misconfig", severity="critical,high,medium", **kwargs)
        if choice.tool == "ffuf":
            return await FfufTool().run(choice.target, **kwargs)
        raise ValueError(f"Unsupported tool choice for executor: {choice.tool} ({spec.name if spec else 'unknown'})")

    def _program_allows_step(self, program: BBProgram, step: PlannedStep, tool_name: str) -> bool:
        spec = get_tool_spec(tool_name)
        if spec is None:
            return False
        if spec.safety_class == SafetyClass.PASSIVE:
            return True
        approved = {
            str(item).strip().lower()
            for item in (program.active_classes_approved or [])
            if str(item).strip()
        }
        return step.vuln_class.strip().lower() in approved

    async def _is_cancelled(self, scan_id) -> bool:
        scan = await self.db.get(Scan, scan_id)
        if scan is None:
            return True
        return scan.status == ScanStatus.CANCELLED
