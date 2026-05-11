"""NETRA-BB CLI commands."""
from __future__ import annotations

import asyncio
import os
import shutil
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.table import Table
from sqlalchemy import text

from netra.core.config import settings

console = Console()


def _doctor_checks(include_local_tools: bool = True) -> list[tuple[str, bool, str]]:
    """Return non-invasive readiness checks for NETRA-BB live operation."""
    checks: list[tuple[str, bool, str]] = []
    local_tools_dir = Path(__file__).resolve().parents[3] / "tools" / "bin"

    def resolve_tool(binary: str) -> str | None:
        found = shutil.which(binary)
        if found:
            return found
        if include_local_tools:
            candidate = local_tools_dir / (f"{binary}.exe" if not binary.endswith(".exe") else binary)
            if candidate.exists():
                return str(candidate)
        return None

    for binary in ["subfinder", "amass", "httpx", "ffuf", "nuclei", "gitleaks"]:
        path = resolve_tool(binary)
        checks.append((f"tool:{binary}", bool(path), path or "not found on PATH"))

    graphify_path = shutil.which("graphify")
    checks.append(("tool:graphify", bool(graphify_path), graphify_path or "not found on PATH"))
    graphify_backend = os.getenv("GRAPHIFY_BACKEND", "ollama")
    graphify_key_env = {
        "ollama": "OLLAMA_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "claude": "ANTHROPIC_API_KEY",
        "kimi": "KIMI_API_KEY",
    }.get(graphify_backend)
    if graphify_key_env:
        key_ok = bool(os.getenv(graphify_key_env))
        checks.append((
            f"graphify:{graphify_backend}",
            key_ok,
            "configured" if key_ok else f"set {graphify_key_env} or choose another GRAPHIFY_BACKEND",
        ))

    checks.append((
        "hackerone:credentials",
        bool(os.getenv("H1_API_USERNAME") and os.getenv("H1_API_TOKEN")),
        "configured" if os.getenv("H1_API_USERNAME") and os.getenv("H1_API_TOKEN") else "set H1_API_USERNAME and H1_API_TOKEN",
    ))
    checks.append((
        "github:token",
        bool(os.getenv("GITHUB_TOKEN")),
        "configured" if os.getenv("GITHUB_TOKEN") else "optional: set GITHUB_TOKEN for GitHub dorks",
    ))
    checks.append((
        "mcp:federation",
        bool(os.getenv("NETRA_BB_MCP_COMMAND")),
        "configured" if os.getenv("NETRA_BB_MCP_COMMAND") else "optional: set NETRA_BB_MCP_COMMAND",
    ))
    broker_url = (
        os.getenv("CELERY_BROKER_URL")
        or os.getenv("NETRA_CELERY_BROKER_URL")
        or os.getenv("REDIS_URL")
        or "redis://localhost:6379/0"
    )
    broker_ok, broker_detail = _check_broker(broker_url)
    checks.append(("celery:broker", broker_ok, broker_detail))
    checks.append((
        "agentic:ollama_model_size_ok",
        _ollama_model_size_ok(),
        os.getenv("NETRA_OLLAMA_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1:8b")),
    ))
    priors_path = Path(__file__).resolve().parents[3] / "data" / "vuln_class_priors.yaml"
    checks.append((
        "agentic:vuln_class_priors_loaded",
        priors_path.exists(),
        str(priors_path) if priors_path.exists() else "missing data/vuln_class_priors.yaml",
    ))
    budget_ok, budget_detail = _check_agentic_budget_table()
    checks.append(("agentic:budget_table_present", budget_ok, budget_detail))
    for source_name, enabled, max_age_hours in [
        ("hackerone_hacktivity", settings.corpus_source_hackerone, 48),
        ("public_advisories", settings.corpus_source_advisories, 48),
        ("public_rss_writeups", settings.corpus_source_writeups, 24),
    ]:
        if enabled:
            ok, detail = _check_corpus_freshness(source_name, max_age_hours=max_age_hours)
            checks.append((f"corpus:{source_name}", ok, detail))

    return checks


def _check_broker(url: str) -> tuple[bool, str]:
    """Check whether the configured Redis broker is reachable."""
    parsed = urlparse(url)
    if parsed.scheme != "redis":
        return (bool(url), f"configured ({parsed.scheme or 'unknown'} broker)")
    host = parsed.hostname or "localhost"
    port = parsed.port or 6379
    try:
        with socket.create_connection((host, port), timeout=1.5) as sock:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            response = sock.recv(16)
        if response.startswith(b"+PONG"):
            return True, f"reachable at {host}:{port}"
        return False, f"unexpected Redis response at {host}:{port}"
    except OSError as exc:
        return False, f"Redis not reachable at {host}:{port}: {exc}"


def _ollama_model_size_ok() -> bool:
    model = (os.getenv("NETRA_OLLAMA_MODEL") or os.getenv("OLLAMA_MODEL") or "llama3.1:8b").lower()
    return any(marker in model for marker in ("7b", "8b", "13b", "14b", "32b"))


def _check_agentic_budget_table() -> tuple[bool, str]:
    try:
        from netra.db.engine import get_session

        async def run() -> tuple[bool, str]:
            async with get_session() as session:
                await session.execute(text("SELECT 1 FROM bb_hunt_budgets LIMIT 1"))
            return True, "reachable"

        return asyncio.run(run())
    except Exception as exc:
        return False, f"not ready: {exc}"


def _check_corpus_freshness(source_name: str, *, max_age_hours: int) -> tuple[bool, str]:
    try:
        from sqlalchemy import select

        from netra.db.engine import get_session
        from netra.db.models import CorpusIngestLog

        async def run() -> tuple[bool, str]:
            async with get_session() as session:
                result = await session.execute(
                    select(CorpusIngestLog)
                    .where(CorpusIngestLog.source_name == source_name)
                    .order_by(CorpusIngestLog.completed_at.desc())
                    .limit(1)
                )
                row = result.scalar_one_or_none()
            if row is None or row.completed_at is None:
                return False, "never ingested"
            age = datetime.now(timezone.utc) - row.completed_at
            return age <= timedelta(hours=max_age_hours), f"last ingest {row.completed_at.isoformat()}"

        return asyncio.run(run())
    except Exception as exc:
        return False, f"not ready: {exc}"


def _async(fn):
    """Decorator: turn an async click command into something click can call."""

    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))

    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


@click.group(help="NETRA-BB bug bounty hunting subcommands.")
def bb() -> None:
    pass


@bb.command("doctor", help="Check live NETRA-BB readiness without probing targets.")
@click.option("--strict", is_flag=True, help="Exit non-zero if live-hunt prerequisites are missing.")
def doctor_cmd(strict: bool) -> None:
    checks = _doctor_checks()

    table = Table(title="NETRA-BB Doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    for name, ok, detail in checks:
        table.add_row(name, "[green]ok[/green]" if ok else "[yellow]missing[/yellow]", detail)
    console.print(table)

    required = [name for name, ok, _ in checks if not ok and name.startswith(("tool:", "hackerone:", "celery:"))]
    if strict and required:
        console.print(f"[red]missing live prerequisites:[/red] {', '.join(required)}")
        sys.exit(1)


@bb.command("add-program", help="Register a bug bounty program and snapshot its scope.")
@click.option(
    "--platform",
    required=True,
    type=click.Choice(["hackerone", "bugcrowd", "intigriti", "yeswehack", "private"]),
)
@click.option("--handle", required=True, help="Platform handle, e.g. 'shopify'.")
@click.option("--name", help="Display name. Defaults to handle.")
@click.option("--policy-url", help="URL of the program policy / scope page.")
@click.option("--payout-min", type=int, help="Lowest paid bracket.")
@click.option("--payout-max", type=int, help="Highest paid bracket.")
@_async
async def add_program_cmd(
    platform: str,
    handle: str,
    name: str | None,
    policy_url: str | None,
    payout_min: int | None,
    payout_max: int | None,
) -> None:
    from netra.bugbounty.programs import ProgramInput, create_program, get_program, replace_scope_rules
    from netra.db.engine import get_session
    from netra.db.models.bb_program import BBPlatform

    plat = BBPlatform(platform)
    async with get_session() as session:
        existing = await get_program(session, plat, handle)
        if existing:
            console.print(f"[yellow]Program already registered:[/yellow] {plat.value}/{handle} (id={existing.id})")
            return

        scope_rules = []
        if plat == BBPlatform.HACKERONE:
            from netra.integrations.hackerone import HackerOneClient, to_program_input

            async with HackerOneClient() as h1:
                if h1.is_configured():
                    h1_program = await h1.get_program(handle)
                    scope_rules = await h1.get_structured_scopes(handle)
                    fetched = to_program_input(h1_program)
                    name = name or fetched.name
                    policy_url = policy_url or fetched.policy_url
                    payout_min = payout_min if payout_min is not None else fetched.payout_min
                    payout_max = payout_max if payout_max is not None else fetched.payout_max
                else:
                    console.print("[yellow]H1 credentials not configured; registering program without live scope.[/yellow]")

        program = await create_program(
            session,
            ProgramInput(
                platform=plat,
                handle=handle,
                name=name or handle,
                policy_url=policy_url,
                payout_min=payout_min,
                payout_max=payout_max,
            ),
        )
        if scope_rules:
            await replace_scope_rules(session, program, scope_rules)
        if plat == BBPlatform.HACKERONE:
            try:
                from netra.bugbounty.learning.sources.hackerone import bootstrap_program

                await bootstrap_program(session, handle=handle, since_days=90)
            except Exception as exc:
                console.print(f"[yellow]hacktivity bootstrap skipped:[/yellow] {exc}")
        await session.commit()
    console.print(f"[green]added program[/green] {plat.value}/{handle} (id={program.id}, scope_rules={len(scope_rules)})")


@bb.command("list-programs", help="List active bug bounty programs.")
@_async
async def list_programs_cmd() -> None:
    from netra.bugbounty.programs import list_active_programs
    from netra.db.engine import get_session

    async with get_session() as session:
        programs = await list_active_programs(session)

    table = Table(title="Bug Bounty Programs")
    table.add_column("Platform", style="cyan")
    table.add_column("Handle", style="bold")
    table.add_column("Payout", justify="right")
    table.add_column("Synced", style="dim")
    for p in programs:
        payout = f"${p.payout_min}-${p.payout_max}" if p.payout_min and p.payout_max else "-"
        synced = p.scope_synced_at.strftime("%Y-%m-%d") if p.scope_synced_at else "never"
        table.add_row(str(p.platform), p.handle, payout, synced)
    console.print(table)


@bb.group("corpus", help="Manage the local learning corpus.")
def corpus_group() -> None:
    pass


@corpus_group.command("forget", help="Hard-delete public corpus entries by author or source URL.")
@click.option("--author", help="Author/handle to forget.")
@click.option("--source-url", help="Source URL to forget.")
@click.option("--confirm", required=True, help="Type FORGET to proceed.")
@_async
async def corpus_forget_cmd(author: str | None, source_url: str | None, confirm: str) -> None:
    if confirm != "FORGET":
        console.print("[red]type --confirm FORGET to proceed[/red]")
        sys.exit(2)
    if not author and not source_url:
        console.print("[red]pass --author or --source-url[/red]")
        sys.exit(2)

    from netra.bugbounty.learning.ingest import forget_corpus_entries, log_ingest
    from netra.db.engine import get_session

    async with get_session() as session:
        deleted = await forget_corpus_entries(session, author=author, source_url=source_url)
        await log_ingest(
            session,
            source_name="corpus_forget",
            items_added=0,
            items_updated=0,
            notes=f"author={author or ''} source_url={source_url or ''} deleted={deleted}",
        )
        await session.commit()
    console.print(f"[yellow]forgot[/yellow] {deleted}")


@corpus_group.command("reembed", help="Refresh stored corpus embeddings after an embed-model change.")
@click.option("--confirm", required=True, help="Type REEMBED to proceed.")
@_async
async def corpus_reembed_cmd(confirm: str) -> None:
    if confirm != "REEMBED":
        console.print("[red]type --confirm REEMBED to proceed[/red]")
        sys.exit(2)

    from netra.bugbounty.learning.ingest import log_ingest, reembed_corpus
    from netra.db.engine import get_session

    async with get_session() as session:
        refreshed = await reembed_corpus(session)
        await log_ingest(
            session,
            source_name="corpus_reembed",
            items_added=0,
            items_updated=sum(refreshed.values()),
            notes=", ".join(f"{kind}={count}" for kind, count in refreshed.items()),
        )
        await session.commit()
    console.print(f"[cyan]re-embedded[/cyan] {refreshed}")



async def _sync_program_scope(platform_enum, handle: str):
    """Pull fresh scope rules from the platform and apply the diff. Returns ScopeDiff or None on failure."""
    from netra.bugbounty.programs import get_program, replace_scope_rules
    from netra.db.engine import get_session
    from netra.db.models.bb_program import BBPlatform

    if platform_enum == BBPlatform.HACKERONE:
        from netra.integrations.hackerone import HackerOneClient

        async with HackerOneClient() as client:
            if not client.is_configured():
                console.print("[red]H1 credentials not configured (set H1_API_USERNAME and H1_API_TOKEN).[/red]")
                return None
            fresh_rules = await client.get_structured_scopes(handle)
    else:
        console.print(f"[yellow]scope --sync not implemented for {platform_enum.value} yet.[/yellow]")
        return None

    async with get_session() as session:
        program = await get_program(session, platform_enum, handle)
        if program is None:
            console.print(f"[red]program not found:[/red] {platform_enum.value}/{handle}")
            return None
        diff = await replace_scope_rules(session, program, fresh_rules)
        await session.commit()
    return diff


def _render_scope_diff(diff, platform: str, program: str) -> None:
    """Render a ScopeDiff as a rich table. Pure presentation â testable in isolation."""
    if not diff.has_changes:
        console.print(
            f"[green]up to date[/green] {platform}/{program} â "
            f"{diff.unchanged_count} rules unchanged"
        )
        return

    table = Table(title=f"Scope diff: {platform}/{program}")
    table.add_column("change", justify="center")
    table.add_column("type")
    table.add_column("asset")
    table.add_column("pattern", overflow="fold")
    table.add_column("cap")

    for added in diff.added:
        table.add_row(
            "[green]+[/green]",
            getattr(added.rule_type, "value", str(added.rule_type)),
            getattr(added.asset_type, "value", str(added.asset_type)),
            added.pattern,
            added.severity_cap or "",
        )
    for removed in diff.removed:
        table.add_row(
            "[red]-[/red]",
            str(removed.rule_type),
            str(removed.asset_type),
            removed.pattern,
            removed.severity_cap or "",
        )
    console.print(table)
    console.print(
        f"[dim]+ {len(diff.added)} added, - {len(diff.removed)} deactivated, "
        f"{diff.unchanged_count} unchanged[/dim]"
    )


@bb.command("scope", help="Inspect or check scope for a program.")
@click.option("--program", required=True, help="Program handle.")
@click.option(
    "--platform",
    default="hackerone",
    type=click.Choice(["hackerone", "bugcrowd", "intigriti", "yeswehack", "private"]),
)
@click.option("--check", help="Target to test against the program scope.")
@click.option("--list", "list_rules", is_flag=True, help="List all active scope rules.")
@click.option("--sync", is_flag=True, help="Pull fresh scope from the platform and apply the diff.")
@_async
async def scope_cmd(
    program: str, platform: str, check: str | None, list_rules: bool, sync: bool
) -> None:
    from netra.bugbounty.programs import get_active_scope_rules, get_program
    from netra.bugbounty.scope import ScopeValidator
    from netra.db.engine import get_session
    from netra.db.models.bb_program import BBPlatform

    async with get_session() as session:
        prog = await get_program(session, BBPlatform(platform), program)
        if prog is None:
            console.print(f"[red]program not found[/red]: {platform}/{program}")
            sys.exit(1)
        rules = await get_active_scope_rules(session, prog.id)

    if sync:
        diff = await _sync_program_scope(BBPlatform(platform), program)
        if diff is None:
            return
        _render_scope_diff(diff, platform, program)
        return

    if list_rules:
        table = Table(title=f"Scope rules for {platform}/{program}")
        table.add_column("type")
        table.add_column("asset")
        table.add_column("pattern")
        table.add_column("cap")
        for r in rules:
            colour = "green" if r.rule_type == "in" else "red"
            table.add_row(f"[{colour}]{r.rule_type}[/{colour}]", r.asset_type, r.pattern, r.severity_cap or "")
        console.print(table)
        return

    if check:
        decision = ScopeValidator.from_db_rules(rules).check(check)
        colour = "green" if decision.allowed else "red"
        symbol = "in scope" if decision.allowed else "out of scope"
        console.print(f"[{colour}]{symbol}[/{colour}]: {decision.reason}")
        return

    console.print("[dim]Pass --check <target> or --list.[/dim]")


@bb.command("hunt", help="Run a bug bounty scan profile against a program.")
@click.option("--program", required=True, help="Program handle.")
@click.option(
    "--platform",
    default="hackerone",
    type=click.Choice(["hackerone", "bugcrowd", "intigriti", "yeswehack", "private"]),
)
@click.option("--profile", default="passive", type=click.Choice(["passive", "active"]))
@click.option("--enable-nuclei", is_flag=True, help="Active only: enable safe nuclei templates.")
@click.option("--enable-ffuf", is_flag=True, help="Active only: enable ffuf content discovery.")
@click.option("--agentic", is_flag=True, help="Use the agentic planner/router execution path.")
@click.option("--dry-run", is_flag=True, help="Agentic only: persist plan/telemetry without running tools.")
@click.option("--plan-only", is_flag=True, help="Generate and print an agentic plan, then exit.")
@_async
async def hunt_cmd(
    program: str,
    platform: str,
    profile: str,
    enable_nuclei: bool,
    enable_ffuf: bool,
    agentic: bool,
    dry_run: bool,
    plan_only: bool,
) -> None:
    if profile != "active" and (enable_nuclei or enable_ffuf):
        console.print("[red]--enable-nuclei and --enable-ffuf require --profile active[/red]")
        sys.exit(2)
    if (dry_run or plan_only) and not agentic:
        console.print("[red]--dry-run and --plan-only require --agentic[/red]")
        sys.exit(2)

    from netra.bugbounty.programs import get_program
    from netra.db.engine import get_session
    from netra.db.models.bb_program import BBPlatform
    from netra.services.scan_service import ScanService
    from netra.bugbounty.agentic.planner import Planner
    import json

    async with get_session() as session:
        prog = await get_program(session, BBPlatform(platform), program)
        if prog is None:
            console.print(f"[red]program not found:[/red] {platform}/{program}")
            sys.exit(1)
        if plan_only:
            from netra.bugbounty.programs import get_active_scope_rules

            rules = await get_active_scope_rules(session, prog.id)
            allow = [rule.pattern for rule in rules if str(rule.rule_type) == "in"]
            plan = await Planner().make_plan(
                asset_facts={"target": prog.handle, "tech": [], "program_handle": prog.handle},
                scope=allow or [prog.handle],
                corpus_hits=[],
            )
            console.print_json(json.dumps(plan.to_dict()))
            return
        scan = await ScanService(session).create_bugbounty_scan(
            program=prog,
            profile=profile,
            enable_nuclei=enable_nuclei,
            enable_ffuf=enable_ffuf,
            agentic=agentic,
            dry_run=dry_run,
            enqueue=True,
        )

    console.print(
        f"[green]queued[/green] scan {scan.id} for {platform}/{program} "
        f"profile=bugbounty_{profile} mode={'agentic' if agentic else 'fixed'}"
        f"{' dry-run' if dry_run else ''}"
    )


@bb.command("triage", help="Review findings ranked by BountyHunter score.")
@click.option("--program", required=True)
@click.option(
    "--platform",
    default="hackerone",
    type=click.Choice(["hackerone", "bugcrowd", "intigriti", "yeswehack", "private"]),
)
@click.option("--limit", type=int, default=20, help="Max findings to display.")
@click.option("--show-vetoed", is_flag=True, help="Include Skeptic-vetoed findings.")
@click.option("--graph-aware", is_flag=True, help="Show Graphify similarity mode in dedup column.")
@_async
async def triage_cmd(program: str, platform: str, limit: int, show_vetoed: bool, graph_aware: bool) -> None:
    from urllib.parse import urlparse

    from sqlalchemy import select

    from netra.bugbounty.programs import get_program
    from netra.bugbounty.triage.deduper import find_graph_similar, fingerprint, is_duplicate
    from netra.db.engine import get_session
    from netra.db.models.bb_program import BBPlatform
    from netra.db.models.finding import Finding, FindingStatus
    from netra.db.models.scan import Scan

    async with get_session() as session:
        prog = await get_program(session, BBPlatform(platform), program)
        if prog is None:
            console.print(f"[red]program not found:[/red] {platform}/{program}")
            sys.exit(1)
        result = await session.execute(
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.config["program_id"].as_string() == str(prog.id))
            .where(Finding.status.in_([FindingStatus.NEW, FindingStatus.CONFIRMED]))
        )
        findings = list(result.scalars().all())

        rows = []
        for finding in findings:
            ai = finding.ai_analysis or {}
            skeptic = ai.get("skeptic", {})
            if skeptic.get("verdict") == "false_positive" and not show_vetoed:
                continue
            bounty = ai.get("bounty_hunter", {})
            vuln_class = str((finding.tags or [finding.cwe_id or finding.title])[0])
            asset = finding.url or ""
            fp = fingerprint(vuln_class, urlparse(asset).path or asset, finding.parameter or "")
            dup = await is_duplicate(session, prog.id, fp)
            if dup:
                dedup_status = f"dup of {str(dup.finding_id)[:8]}"
            elif graph_aware and find_graph_similar(prog.id, urlparse(asset).path or asset, vuln_class):
                dedup_status = "similar"
            else:
                dedup_status = "new"
            rows.append((float(bounty.get("composite", 0) or 0), finding, bounty, dedup_status))
    rows.sort(key=lambda row: row[0], reverse=True)

    table = Table(title=f"Triage: {platform}/{program}")
    table.add_column("Tier")
    table.add_column("Score", justify="right")
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Asset")
    table.add_column("Dedup")
    for score, finding, bounty, dedup_status in rows[:limit]:
        table.add_row(
            str(bounty.get("tier", "unscored")),
            f"{score:.1f}",
            str(finding.severity),
            finding.title[:80],
            (finding.url or "")[:60],
            dedup_status,
        )
    console.print(table)


@bb.command("plan", help="Generate an agentic test plan without executing it.")
@click.option("--program", required=True, help="Program handle.")
@click.option(
    "--platform",
    default="hackerone",
    type=click.Choice(["hackerone", "bugcrowd", "intigriti", "yeswehack", "private"]),
)
@click.option("--asset", required=True, help="Asset or host to plan against.")
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON.")
@_async
async def plan_cmd(program: str, platform: str, asset: str, json_output: bool) -> None:
    import json

    from netra.bugbounty.agentic.planner import Planner
    from netra.bugbounty.programs import get_active_scope_rules, get_program
    from netra.db.engine import get_session
    from netra.db.models.bb_program import BBPlatform

    async with get_session() as session:
        prog = await get_program(session, BBPlatform(platform), program)
        if prog is None:
            console.print(f"[red]program not found:[/red] {platform}/{program}")
            sys.exit(1)
        rules = await get_active_scope_rules(session, prog.id)
        allow = [rule.pattern for rule in rules if str(rule.rule_type) == "in"]

    plan = await Planner().make_plan(
        asset_facts={"target": asset, "tech": [], "program_handle": program},
        scope=allow or [asset],
        corpus_hits=[],
    )
    if json_output:
        console.print_json(json.dumps(plan.to_dict()))
        return

    table = Table(title=f"Agentic plan: {platform}/{program}")
    table.add_column("#", justify="right")
    table.add_column("Class")
    table.add_column("Tool")
    table.add_column("Target")
    table.add_column("Hypothesis")
    for index, step in enumerate(plan.steps, start=1):
        table.add_row(
            str(index),
            step.vuln_class,
            step.suggested_tool,
            step.target,
            step.hypothesis[:100],
        )
    console.print(table)
    coordination = plan.coordination or {}
    if coordination:
        console.print(f"[bold]Coordination[/bold] {coordination.get('summary', '')}")
        focus = ", ".join(coordination.get("focus_areas", [])[:6])
        tools = ", ".join(coordination.get("recommended_tools", [])[:6])
        if focus:
            console.print(f"[cyan]Focus[/cyan] {focus}")
        if tools:
            console.print(f"[cyan]Suggested tools[/cyan] {tools}")
        retrieval_hits = coordination.get("retrieval_hits", [])[:5]
        if retrieval_hits:
            hits_table = Table(title="Graph / Knowledge Hits")
            hits_table.add_column("Title")
            hits_table.add_column("Source")
            hits_table.add_column("Snippet")
            for hit in retrieval_hits:
                hits_table.add_row(
                    str(hit.get("title", "")),
                    str(hit.get("source", ""))[:60],
                    str(hit.get("snippet", ""))[:100],
                )
            console.print(hits_table)
        attack_paths = coordination.get("attack_paths", [])[:5]
        if attack_paths:
            path_table = Table(title="Attack Paths")
            path_table.add_column("Name")
            path_table.add_column("Steps")
            path_table.add_column("Narrative")
            for path in attack_paths:
                steps = path.get("steps", [])
                path_table.add_row(
                    str(path.get("name", "")),
                    " -> ".join(str(step) for step in steps),
                    str(path.get("narrative", ""))[:100],
                )
            console.print(path_table)


@bb.command("trend", help="Summarize recent learning-corpus trends.")
@click.option("--days", default=7, type=int, help="Window to summarize.")
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON.")
@_async
async def trend_cmd(days: int, json_output: bool) -> None:
    import json

    from netra.bugbounty.learning.trends import summarize_trends
    from netra.db.engine import get_session

    async with get_session() as session:
        summary = await summarize_trends(session, days=days)

    if json_output:
        console.print_json(json.dumps(summary))
        return

    console.print(
        f"[bold]Learning Trends[/bold] {days}d | "
        f"reports={summary['total_reports']} writeups={summary['total_writeups']} advisories={summary['total_advisories']}"
    )

    def render_bucket_table(title: str, rows: list[dict[str, int | str]]) -> None:
        table = Table(title=title)
        table.add_column("Name")
        table.add_column("Count", justify="right")
        for row in rows:
            table.add_row(str(row["name"]), str(row["count"]))
        console.print(table)

    render_bucket_table("Top Vulnerability Classes", summary["top_vuln_classes"])
    render_bucket_table("Top Tech / Packages", summary["top_tech"])
    render_bucket_table("Top Programs", summary["top_programs"])


@bb.command("hunt-explain", help="Print the persisted step-by-step agentic trace for a scan.")
@click.argument("scan_id")
@_async
async def hunt_explain_cmd(scan_id: str) -> None:
    from sqlalchemy import select

    from netra.db.engine import get_session
    from netra.db.models.scan import Scan
    from netra.db.models.bb_agentic_step import BBAgenticStep

    async with get_session() as session:
        scan = await session.get(Scan, scan_id)
        result = await session.execute(
            select(BBAgenticStep)
            .where(BBAgenticStep.scan_id == scan_id)
            .order_by(BBAgenticStep.step_n.asc())
        )
        rows = list(result.scalars().all())

    coordination = ((scan.checkpoint_data or {}).get("agentic_coordination") if scan else None) or {}
    if coordination:
        console.print(f"[bold]Coordination[/bold] {coordination.get('summary', '')}")
        focus = ", ".join(coordination.get("focus_areas", [])[:6])
        tools = ", ".join(coordination.get("recommended_tools", [])[:6])
        if focus:
            console.print(f"[cyan]Focus[/cyan] {focus}")
        if tools:
            console.print(f"[cyan]Suggested tools[/cyan] {tools}")
        retrieval_hits = coordination.get("retrieval_hits", [])[:5]
        if retrieval_hits:
            hits_table = Table(title="Graph / Knowledge Hits")
            hits_table.add_column("Title")
            hits_table.add_column("Source")
            hits_table.add_column("Snippet")
            for hit in retrieval_hits:
                hits_table.add_row(
                    str(hit.get("title", "")),
                    str(hit.get("source", ""))[:60],
                    str(hit.get("snippet", ""))[:100],
                )
            console.print(hits_table)
        attack_paths = coordination.get("attack_paths", [])[:5]
        if attack_paths:
            path_table = Table(title="Attack Paths")
            path_table.add_column("Name")
            path_table.add_column("Steps")
            path_table.add_column("Narrative")
            for path in attack_paths:
                steps = path.get("steps", [])
                path_table.add_row(
                    str(path.get("name", "")),
                    " -> ".join(str(step) for step in steps),
                    str(path.get("narrative", ""))[:100],
                )
            console.print(path_table)

    table = Table(title=f"Agentic trace: {scan_id}")
    table.add_column("#", justify="right")
    table.add_column("Status")
    table.add_column("Tool")
    table.add_column("Rationale")
    table.add_column("Observed")
    for row in rows:
        observed = str((row.observations_out or {}).get("kind", ""))
        table.add_row(
            str(row.step_n),
            row.status,
            row.tool_chosen or "",
            (row.decision_rationale or "")[:90],
            observed,
        )
    console.print(table)


@bb.command("cancel-hunt", help="Cancel a queued or running bug bounty scan.")
@click.argument("scan_id")
@_async
async def cancel_hunt_cmd(scan_id: str) -> None:
    from netra.db.engine import get_session
    from netra.db.models.scan import Scan, ScanStatus
    from netra.scanner.tools.process_control import kill_registered_processes
    from netra.worker.celery_app import celery_app

    async with get_session() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            console.print(f"[red]scan not found:[/red] {scan_id}")
            sys.exit(1)
        task_id = str((scan.config or {}).get("celery_task_id") or "").strip()
        if task_id:
            celery_app.control.revoke(task_id, terminate=True, signal="SIGKILL")
            kill_registered_processes(task_id)
        scan.status = ScanStatus.CANCELLED
        await session.commit()

    console.print(f"[yellow]cancel requested[/yellow] for {scan_id}")


@bb.command("program-approve", help="Approve active vuln classes for a program.")
@click.option("--program", required=True, help="Program handle.")
@click.option(
    "--platform",
    default="hackerone",
    type=click.Choice(["hackerone", "bugcrowd", "intigriti", "yeswehack", "private"]),
)
@click.option("--vuln-classes", required=True, help="Comma-separated classes, e.g. xss,csrf,ssrf")
@_async
async def program_approve_cmd(program: str, platform: str, vuln_classes: str) -> None:
    from netra.bugbounty.programs import get_program
    from netra.db.engine import get_session
    from netra.db.models.bb_program import BBPlatform

    approved = [item.strip() for item in vuln_classes.split(",") if item.strip()]
    async with get_session() as session:
        prog = await get_program(session, BBPlatform(platform), program)
        if prog is None:
            console.print(f"[red]program not found:[/red] {platform}/{program}")
            sys.exit(1)
        prog.active_classes_approved = approved
        prog.metadata_ = {
            **(prog.metadata_ or {}),
            "active_approval_updated_at": datetime.utcnow().isoformat() + "Z",
        }
        await session.commit()
    console.print(f"[green]approved[/green] active classes for {platform}/{program}: {', '.join(approved)}")


@bb.command("verify", help="Generate a PoC preview and run the allowlisted replay verifier.")
@click.option("--finding-id", required=True, help="Finding UUID.")
@click.option("--evidence-id", help="Optional evidence UUID. Defaults to latest evidence for the finding.")
@click.option("--verifier-id", help="Optional verifier id. Defaults by vuln class.")
@click.option("--typed-confirm", help="Program handle confirmation for replay.")
@_async
async def verify_cmd(
    finding_id: str,
    evidence_id: str | None,
    verifier_id: str | None,
    typed_confirm: str | None,
) -> None:
    from sqlalchemy import select

    from netra.bugbounty.agentic.poc_builder import PocBuilder
    from netra.bugbounty.programs import get_active_scope_rules
    from netra.bugbounty.scope import ScopeValidator
    from netra.bugbounty.verifiers.loader import find_verifier
    from netra.bugbounty.verifiers.runner import run_replay
    from netra.db.engine import get_session
    from netra.db.models.bb_evidence import BBEvidence, BBEvidenceReplay
    from netra.db.models.bb_program import BBProgram
    from netra.db.models.finding import Finding

    async with get_session() as session:
        finding = await session.get(Finding, finding_id)
        if finding is None:
            console.print(f"[red]finding not found:[/red] {finding_id}")
            sys.exit(1)

        if evidence_id:
            evidence = await session.get(BBEvidence, evidence_id)
        else:
            result = await session.execute(
                select(BBEvidence)
                .where(BBEvidence.finding_id == finding.id)
                .order_by(BBEvidence.created_at.desc())
                .limit(1)
            )
            evidence = result.scalar_one_or_none()
        if evidence is None:
            console.print("[red]no evidence found for this finding[/red]")
            sys.exit(1)

        program = await session.get(BBProgram, evidence.program_id)
        if program is None:
            console.print("[red]program not found for this evidence[/red]")
            sys.exit(1)

        vuln_class = str((finding.tags or [finding.cwe_id or finding.title or "finding"])[0]).lower()
        chosen_verifier = verifier_id or (
            "xss_reflected_passive" if vuln_class == "xss" else "generic_read_only_replay"
        )
        spec = find_verifier(chosen_verifier, vuln_class)
        if spec is None:
            console.print(
                f"[red]verifier not allowlisted for vuln class {vuln_class}:[/red] {chosen_verifier}"
            )
            sys.exit(2)
        if typed_confirm and typed_confirm != program.handle:
            console.print("[red]typed confirmation does not match the program handle[/red]")
            sys.exit(2)

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
        console.print("[bold]PoC preview[/bold]")
        console.print(poc)

        rules = await get_active_scope_rules(session, program.id)
        validator = ScopeValidator.from_db_rules(rules)
        result = await run_replay(evidence, spec, validator)
        replay = BBEvidenceReplay(
            evidence_id=evidence.id,
            verifier_id=spec.id,
            status=str(result.get("status", "failed")),
            status_code=result.get("status_code"),
            latency_ms=result.get("latency_ms"),
            diff=result.get("diff") or {},
            error_message=result.get("error"),
        )
        session.add(replay)
        await session.commit()

    console.print(
        f"[green]{replay.status}[/green] verifier={replay.verifier_id} status_code={replay.status_code}"
    )
    if replay.error_message:
        console.print(f"[yellow]{replay.error_message}[/yellow]")


@bb.command("draft", help="Generate an H1-style submission draft for a finding.")
@click.option("--finding-id", required=True, help="Finding UUID.")
@click.option("--output", default="~/reports", type=click.Path(), help="Output directory.")
@click.option("--format", "formats", multiple=True, default=("md", "docx"), type=click.Choice(["md", "docx", "pdf"]))
@click.option("--force", is_flag=True, help="Draft even if dedupe marks the finding as duplicate.")
@click.option("--include-poc", is_flag=True, help="Generate and include a read-only PoC section.")
@_async
async def draft_cmd(
    finding_id: str,
    output: str,
    formats: tuple[str, ...],
    force: bool,
    include_poc: bool,
) -> None:
    from netra.db.engine import get_session
    from netra.db.models.finding import Finding
    from netra.services.bb_submission_service import BBSubmissionService, DuplicateFindingError

    out = Path(output).expanduser()
    async with get_session() as session:
        finding = await session.get(Finding, finding_id)
        if finding is None:
            console.print(f"[red]finding not found:[/red] {finding_id}")
            sys.exit(1)
        try:
            submission, paths = await BBSubmissionService(session).create_draft(
                finding,
                out,
                formats=formats,
                force=force,
                include_poc=include_poc,
            )
        except DuplicateFindingError as exc:
            console.print(f"[yellow]{exc}[/yellow]")
            sys.exit(2)

    console.print(f"[green]drafted[/green] submission {submission.id}")
    for kind, path in paths.items():
        console.print(f"  {kind}: {path}")


@bb.group("submission", help="Manage bug bounty submission state.")
def submission_group() -> None:
    pass


@submission_group.command("list", help="List bug bounty submissions.")
@click.option("--status", help="Filter by submission status.")
@_async
async def submission_list_cmd(status: str | None) -> None:
    from netra.db.engine import get_session
    from netra.services.bb_submission_service import BBSubmissionService

    async with get_session() as session:
        rows = await BBSubmissionService(session).list_submissions(status)

    table = Table(title="Bug Bounty Submissions")
    table.add_column("ID")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Expected")
    for row in rows:
        table.add_row(str(row.id), str(row.status), row.severity, row.title[:80], str(row.payout_expected or ""))
    console.print(table)


@submission_group.command("status", help="Transition a submission to a new status.")
@click.argument("submission_id")
@click.argument("new_status")
@click.option("--notes", help="Optional notes.")
@_async
async def submission_status_cmd(submission_id: str, new_status: str, notes: str | None) -> None:
    from netra.bugbounty.submission.tracker import InvalidTransition, transition
    from netra.db.engine import get_session
    from netra.db.models.bb_submission import BBSubmission, SubmissionStatus

    async with get_session() as session:
        submission = await session.get(BBSubmission, submission_id)
        if submission is None:
            console.print(f"[red]submission not found:[/red] {submission_id}")
            sys.exit(1)
        try:
            await transition(session, submission, SubmissionStatus(new_status), notes=notes)
            await session.commit()
        except InvalidTransition as exc:
            console.print(f"[red]{exc}[/red]")
            sys.exit(2)

    console.print(f"[green]updated[/green] {submission_id} -> {new_status}")


@submission_group.command("verdict", help="Record final platform verdict.")
@click.argument("submission_id")
@click.argument("verdict", type=click.Choice(["paid", "dup", "na", "info"]))
@click.option("--payout-actual", type=int)
@click.option("--notes", default="")
@_async
async def submission_verdict_cmd(submission_id: str, verdict: str, payout_actual: int | None, notes: str) -> None:
    from netra.bugbounty.graph_indexer import export_submissions_json
    from netra.bugbounty.submission.tracker import transition
    from netra.db.engine import get_session
    from netra.db.models.bb_submission import BBSubmission, SubmissionStatus

    status_map = {
        "paid": SubmissionStatus.RESOLVED_PAID,
        "dup": SubmissionStatus.RESOLVED_DUP,
        "na": SubmissionStatus.RESOLVED_NA,
        "info": SubmissionStatus.RESOLVED_INFORMATIVE,
    }
    async with get_session() as session:
        submission = await session.get(BBSubmission, submission_id)
        if submission is None:
            console.print(f"[red]submission not found:[/red] {submission_id}")
            sys.exit(1)
        submission.payout_actual = payout_actual
        await transition(session, submission, status_map[verdict], notes=notes)
        await session.commit()
        export_submissions_json([
            {
                "id": submission.id,
                "title": submission.title,
                "severity": submission.severity,
                "status": submission.status,
                "program_id": submission.program_id,
                "finding_id": submission.finding_id,
                "vuln_class": (submission.metadata_ or {}).get("vuln_class"),
            }
        ], Path("data/graphify/submissions.json"))

    console.print(f"[green]recorded[/green] verdict={verdict} for {submission_id}")


@bb.group("graphify", help="Graphify local-output indexing.")
def graphify_group() -> None:
    pass


@bb.group("audit", help="Review bug bounty safety audit logs.")
def audit_group() -> None:
    pass


@audit_group.command("out-of-scope", help="List blocked scope-gate events.")
@click.option("--since", default="7d", help="Time window, currently informational.")
@click.option("--limit", default=100, type=int)
@_async
async def audit_out_of_scope_cmd(since: str, limit: int) -> None:
    from sqlalchemy import select

    from netra.db.engine import get_session
    from netra.db.models.scan_phase import PhaseStatus, ScanPhase

    async with get_session() as session:
        result = await session.execute(
            select(ScanPhase)
            .where(ScanPhase.status == PhaseStatus.BLOCKED)
            .order_by(ScanPhase.created_at.desc())
            .limit(limit)
        )
        phases = list(result.scalars().all())

    table = Table(title=f"Out-of-scope audit ({since})")
    table.add_column("Time")
    table.add_column("Phase")
    table.add_column("Target")
    table.add_column("Reason")
    for phase in phases:
        outputs = phase.tool_outputs or {}
        table.add_row(
            str(phase.created_at),
            str(phase.phase_type),
            str(outputs.get("target", "")),
            str(outputs.get("reason", phase.error_message or ""))[:120],
        )
    console.print(table)


@graphify_group.command("index-codebase", help="Index NETRA's codebase into data/graphify/netra.")
@click.option("--src-root", default="src", type=click.Path(exists=True, file_okay=False))
@click.option("--output", default="data/graphify/netra", type=click.Path(file_okay=False))
@_async
async def graphify_index_codebase_cmd(src_root: str, output: str) -> None:
    from netra.bugbounty.graph_indexer import index_codebase

    result = await index_codebase(Path(src_root), Path(output))
    if result.success:
        console.print(f"[green]indexed[/green] {result.target} -> {result.output_dir}")
    else:
        console.print(f"[yellow]graphify failed/skipped:[/yellow] {result.error}")
        sys.exit(1)


def main() -> None:
    bb()


if __name__ == "__main__":
    main()
