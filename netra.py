#!/usr/bin/env python3
"""
netra.py
Main CLI entry point for NETRA नेत्र.
Orchestrates all 8 phases: input → recon → pentest → AI analysis → reports.

Usage:
    python3 netra.py                        # interactive mode
    python3 netra.py -f targets.txt         # file input
    python3 netra.py -x assets.xlsx         # Excel input
    python3 netra.py -t example.com         # single target
    python3 netra.py --resume               # resume last scan
    python3 netra.py --install-deps         # install all tools
    python3 netra.py --status               # show DB summary
    python3 netra.py mcp                    # start MCP server
"""

import os
import sys
import time
import argparse
from pathlib import Path
from datetime import datetime

# ── Ensure netra package is importable ───────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from netra.core.config     import CONFIG, load_config, save_config, apply_scan_profile, is_on, SCAN_PROFILES
from netra.core.checkpoint import Checkpoint, check_resume_prompt, PHASES
from netra.core.database   import FindingsDB
from netra.core.notify     import notify_complete
from netra.core.utils      import (
    banner, status, C, make_workdir, deduplicate,
    read_targets_file, write_targets_file, format_table, severity_sort_key,
)
from netra.core.deps       import check_deps, install_deps, quick_check


# ═══════════════════════════════════════════════════════════════════════
#  NETRA BANNER
# ═══════════════════════════════════════════════════════════════════════

BANNER = f"""
{C.TEAL}
  ███╗   ██╗███████╗████████╗██████╗  █████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ██████╔╝███████║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══██║
  ██║ ╚████║███████╗   ██║   ██║  ██║██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
{C.RESET}
{C.PURPLE}  नेत्र  —  The Third Eye of Security{C.RESET}
{C.DIM}  Operator: {os.getenv("USER", "operator")}  |  {datetime.now().strftime("%Y-%m-%d %H:%M")}{C.RESET}
{C.DIM}  Version: 1.0.0  |  AGPL-3.0  |  Author: Yash Wardhan Gautam{C.RESET}
"""


# ═══════════════════════════════════════════════════════════════════════
#  CLI ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    """Build the NETRA argument parser."""
    p = argparse.ArgumentParser(
        prog="netra",
        description="NETRA नेत्र — AI-Augmented Cybersecurity Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 netra.py -t example.com --profile balanced
  python3 netra.py -f targets.txt --client "Acme Corp" --engagement "Q1 Pentest"
  python3 netra.py -x assets.xlsx --profile healthcare
  python3 netra.py --resume
  python3 netra.py mcp                    # start MCP server for Claude Desktop
  python3 netra.py --status               # show database summary
"""
    )

    sub = p.add_subparsers(dest="command")

    # ── MCP subcommand ────────────────────────────────────────────────
    sub.add_parser("mcp", help="Start the NETRA MCP server for Claude Desktop integration")

    # ── Scan arguments (top-level) ────────────────────────────────────
    # Input sources
    p.add_argument("-t", "--target",  help="Single target (domain, IP, or URL)")
    p.add_argument("-f", "--file",    help="Text file of targets (one per line)")
    p.add_argument("-x", "--excel",   help="Excel file (.xlsx) with targets")
    p.add_argument("-p", "--product", help="Product name tag for targets", default="")

    # Scan config
    p.add_argument("--profile", choices=list(SCAN_PROFILES.keys()),
                   default="balanced", help="Scan profile (default: balanced)")
    p.add_argument("--client",     help="Client name for reports", default="")
    p.add_argument("--engagement", help="Engagement name", default="")

    # Resume / manage
    p.add_argument("--resume", action="store_true", help="Resume an incomplete scan")
    p.add_argument("--status", action="store_true", help="Show DB summary and exit")

    # Deps
    p.add_argument("--install-deps", action="store_true", help="Install all dependencies")
    p.add_argument("--check-deps",   action="store_true", help="Check dependencies only")

    # Phase control
    p.add_argument("--skip-recon",   action="store_true", help="Skip recon phases")
    p.add_argument("--skip-pentest", action="store_true", help="Skip pentest phase")
    p.add_argument("--only-recon",   action="store_true", help="Run recon only")
    p.add_argument("--only-pentest", action="store_true",
                   help="Run pentest only (requires prior recon data)")

    # CI/CD output
    p.add_argument("--output-sarif", help="Path to write SARIF output file")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                   help="Exit with code 1 if findings at this severity or above")

    # DB management
    p.add_argument("--mark-fp",  type=int, metavar="FINDING_ID",
                   help="Mark finding as false positive")
    p.add_argument("--fp-reason", default="", help="Reason for FP (use with --mark-fp)")
    p.add_argument("--add-note", type=int, metavar="FINDING_ID",
                   help="Add note to finding")
    p.add_argument("--note", default="", help="Note text (use with --add-note)")

    return p


# ═══════════════════════════════════════════════════════════════════════
#  DB MANAGEMENT HELPERS
# ═══════════════════════════════════════════════════════════════════════

def show_status(db: FindingsDB) -> None:
    """Print a summary of all scan runs and findings in the database."""
    banner("NETRA DATABASE STATUS")
    with db._conn() as conn:
        scans = conn.execute(
            "SELECT scan_id, started_at, completed_at, risk_grade, finding_count "
            "FROM scan_runs ORDER BY started_at DESC LIMIT 20"
        ).fetchall()

    if not scans:
        print("  No scans found in database.\n")
        return

    rows = []
    for s in scans:
        completed = "✓" if s["completed_at"] else "..."
        grade     = s["risk_grade"] or "-"
        count     = s["finding_count"] or 0
        started   = (s["started_at"] or "")[:16].replace("T", " ")
        rows.append([s["scan_id"], started, completed, grade, str(count)])

    print(format_table(
        rows,
        headers=["Scan ID", "Started", "Done", "Grade", "Findings"],
        col_widths=[22, 18, 6, 7, 10]
    ))
    print()


def handle_db_commands(args: argparse.Namespace, db: FindingsDB) -> bool:
    """
    Handle non-scan database management commands.

    Returns:
        True if a command was handled (caller should exit).
    """
    if args.mark_fp:
        reason = args.fp_reason or input("  FP reason: ").strip()
        db.mark_fp(args.mark_fp, reason, operator=CONFIG.get("operator", ""))
        status(f"Finding #{args.mark_fp} marked as false positive", "ok")
        return True

    if args.add_note:
        note = args.note or input("  Note: ").strip()
        db.add_note(args.add_note, note, operator=CONFIG.get("operator", ""))
        status(f"Note added to finding #{args.add_note}", "ok")
        return True

    return False


# ═══════════════════════════════════════════════════════════════════════
#  TARGET COLLECTION
# ═══════════════════════════════════════════════════════════════════════

def collect_targets(args: argparse.Namespace) -> list:
    """
    Collect and deduplicate targets from CLI args.

    Returns:
        List of target strings.
    """
    targets: list = []

    if args.target:
        targets.append(args.target.strip())

    if args.file:
        file_targets = read_targets_file(args.file)
        status(f"Loaded {len(file_targets)} targets from {args.file}", "ok")
        targets.extend(file_targets)

    if args.excel:
        try:
            import openpyxl
            wb = openpyxl.load_workbook(args.excel, read_only=True)
            for ws in wb.worksheets:
                for row in ws.iter_rows(min_row=2, values_only=True):
                    cell = str(row[0]).strip() if row[0] else ""
                    if cell and cell != "None":
                        targets.append(cell)
            status(f"Loaded targets from {args.excel}", "ok")
        except Exception as e:
            status(f"Failed to read Excel file: {e}", "error")

    targets = deduplicate(targets)

    if not targets:
        # Interactive input
        print(f"\n{C.TEAL}  Enter targets (one per line, blank line to finish):{C.RESET}")
        while True:
            t = input("  > ").strip()
            if not t:
                break
            targets.append(t)
        targets = deduplicate(targets)

    return targets


# ═══════════════════════════════════════════════════════════════════════
#  SCAN ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════

def run_scan(args: argparse.Namespace, targets: list,
             workdir: Path, resume_from: str = None) -> None:
    """
    Execute the full NETRA scan pipeline.

    Args:
        args:        Parsed CLI arguments.
        targets:     Deduplicated target list.
        workdir:     Path to scan working directory.
        resume_from: Phase to resume from, or None for fresh start.
    """
    db      = FindingsDB()
    cp      = Checkpoint(workdir)
    profile = apply_scan_profile(args.profile)

    if not resume_from:
        cp.init({
            "targets":    targets,
            "count":      len(targets),
            "product":    args.product,
            "profile":    args.profile,
            "client":     args.client,
            "engagement": args.engagement,
        })
        CONFIG["client_name"]     = args.client
        CONFIG["engagement_name"] = args.engagement
        save_config()

    scan_id  = cp.get_scan_id()
    operator = CONFIG.get("operator", "operator")

    db.create_scan_run(scan_id, str(workdir), operator=operator, profile=args.profile)

    status(f"Scan ID: {scan_id}", "info")
    status(f"Targets: {len(targets)}", "info")
    status(f"Profile: {args.profile} — {profile.get('description', '')}", "info")
    status(f"Workdir: {workdir}", "info")

    # Write targets file for tools
    targets_file = str(workdir / "recon" / "targets.txt")
    write_targets_file(targets_file, targets)

    skip_recon   = args.skip_recon or args.only_pentest
    skip_pentest = args.skip_pentest or args.only_recon

    # ── Phase 1: OSINT ────────────────────────────────────────────────
    if not skip_recon and cp.should_run("1_osint", resume_from):
        try:
            from netra.modules.vapt.osint import run_osint
            run_osint(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"OSINT phase error: {e}", "warn")
        cp.done("1_osint")

    # ── Phase 2: Subdomains ───────────────────────────────────────────
    if not skip_recon and cp.should_run("2_subdomains", resume_from):
        try:
            from netra.modules.vapt.subdomains import run_subdomains
            run_subdomains(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"Subdomains phase error: {e}", "warn")
        cp.done("2_subdomains")

    # ── Phase 3: Discovery ────────────────────────────────────────────
    if not skip_recon and cp.should_run("3_discovery", resume_from):
        try:
            from netra.modules.vapt.discovery import run_discovery
            run_discovery(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"Discovery phase error: {e}", "warn")
        cp.done("3_discovery")

    # ── Phase 4: Port Scan ────────────────────────────────────────────
    if not skip_recon and cp.should_run("4_ports", resume_from):
        try:
            from netra.modules.vapt.ports import run_ports
            run_ports(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"Ports phase error: {e}", "warn")
        cp.done("4_ports")

    # ── Phase 5: Vulnerability Scan ───────────────────────────────────
    if not skip_recon and cp.should_run("5_vulns", resume_from):
        try:
            from netra.modules.vapt.vulns import run_vulns
            run_vulns(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"Vulns phase error: {e}", "warn")
        cp.done("5_vulns")

    # ── Phase 6: Pentest ──────────────────────────────────────────────
    if not skip_pentest and cp.should_run("6_pentest", resume_from):
        try:
            from netra.modules.vapt.injection import run_injection
            run_injection(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"Pentest/injection phase error: {e}", "warn")
        try:
            from netra.modules.vapt.auth_testing import run_auth_testing
            run_auth_testing(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"Pentest/auth phase error: {e}", "warn")
        try:
            from netra.modules.vapt.api_testing import run_api_testing
            run_api_testing(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"Pentest/api phase error: {e}", "warn")
        cp.done("6_pentest")

    # ── Phase 7: Misconfiguration + WAF ──────────────────────────────
    if not skip_pentest and cp.should_run("7_auth_session", resume_from):
        try:
            from netra.modules.vapt.misconfig import run_misconfig
            run_misconfig(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"Misconfig phase error: {e}", "warn")
        cp.done("7_auth_session")

    # ── Phase 8: JS Analysis ──────────────────────────────────────────
    if is_on("js_analysis") and cp.should_run("8_ai_surface", resume_from):
        try:
            from netra.modules.vapt.js_analysis import run_js_analysis
            run_js_analysis(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"JS analysis phase error: {e}", "warn")
        cp.done("8_ai_surface")

    # ── Phase 9: Enrichment ───────────────────────────────────────────
    if cp.should_run("9_enrichment", resume_from):
        try:
            from netra.modules.vapt.extractor import run_extractor
            run_extractor(targets, workdir, scan_id, db)
        except Exception as e:
            status(f"Enrichment phase error: {e}", "warn")
        cp.done("9_enrichment")

    # ── Phase 10: AI Analysis ─────────────────────────────────────────
    if is_on("ai_analysis") and cp.should_run("10_ai_analysis", resume_from):
        try:
            from netra.ai_brain.consensus import run_consensus_analysis
            run_consensus_analysis(scan_id, db)
        except Exception as e:
            status(f"AI analysis phase error: {e}", "warn")
        cp.done("10_ai_analysis")

    # ── Phase 11: Reports ─────────────────────────────────────────────
    if cp.should_run("11_reports", resume_from):
        _generate_reports(scan_id, workdir, db)
        cp.done("11_reports")

    # ── Completion ────────────────────────────────────────────────────
    risk_score, risk_grade = db.compute_risk_score(scan_id)
    db.complete_scan_run(scan_id, risk_score, risk_grade,
                         cp.data.get("completed_phases", []))
    cp.done("complete")

    stats = db.get_stats(scan_id)
    _print_summary(scan_id, stats, risk_score, risk_grade, workdir)
    notify_complete(scan_id, str(workdir), stats, risk_score, risk_grade)

    # ── CI/CD: SARIF output ──────────────────────────────────────────
    if args.output_sarif:
        try:
            from netra.reports.sarif import generate_sarif
            findings = db.get_findings(scan_id)
            generate_sarif(findings, Path(args.output_sarif))
            status(f"SARIF output: {args.output_sarif}", "ok")
        except Exception as e:
            status(f"SARIF generation failed: {e}", "warn")

    # ── CI/CD: Exit code based on severity ───────────────────────────
    if args.fail_on:
        severity_order = ["critical", "high", "medium", "low", "info"]
        threshold_idx = severity_order.index(args.fail_on)
        findings = db.get_findings(scan_id)
        
        for f in findings:
            sev = f.get("severity", "info")
            if sev in severity_order:
                sev_idx = severity_order.index(sev)
                if sev_idx <= threshold_idx:
                    status(f"Failing due to {sev} severity finding", "warn")
                    sys.exit(1)
        
        status("No findings at or above threshold", "ok")
        sys.exit(0)


def _generate_reports(scan_id: str, workdir: Path, db: FindingsDB) -> None:
    """Generate all configured report types."""
    banner("REPORT GENERATION", "Building all report formats")

    reports_dir = workdir / "reports"
    reports_dir.mkdir(exist_ok=True)

    findings = db.get_findings(scan_id)
    assets   = db.get_assets(scan_id)
    chains   = db.get_attack_chains(scan_id)
    stats    = db.get_stats(scan_id)
    score, grade = db.compute_risk_score(scan_id)

    ctx = {
        "scan_id":    scan_id,
        "findings":   findings,
        "assets":     assets,
        "chains":     chains,
        "stats":      stats,
        "risk_score": score,
        "risk_grade": grade,
        "client":     CONFIG.get("client_name", ""),
        "engagement": CONFIG.get("engagement_name", ""),
        "date":       datetime.now().strftime("%Y-%m-%d"),
        "operator":   CONFIG.get("operator", "operator"),
    }

    if is_on("report_word"):
        try:
            from netra.reports.word_report import generate_word_report
            path = generate_word_report(ctx, reports_dir)
            db.save_report(scan_id, "word", str(path))
            status(f"Word report: {path.name}", "ok")
        except Exception as e:
            status(f"Word report failed: {e}", "warn")

    if is_on("report_pdf"):
        try:
            from netra.reports.pdf_report import generate_pdf_report
            path = generate_pdf_report(ctx, reports_dir)
            db.save_report(scan_id, "pdf", str(path))
            status(f"PDF report: {path.name}", "ok")
        except Exception as e:
            status(f"PDF report failed: {e}", "warn")

    if is_on("report_html"):
        try:
            from netra.reports.html_report import generate_html_report
            path = generate_html_report(ctx, reports_dir)
            db.save_report(scan_id, "html", str(path))
            status(f"HTML report: {path.name}", "ok")
        except Exception as e:
            status(f"HTML report failed: {e}", "warn")

    if is_on("report_excel"):
        try:
            from netra.reports.excel_report import generate_excel_report
            path = generate_excel_report(ctx, reports_dir)
            db.save_report(scan_id, "excel", str(path))
            status(f"Excel report: {path.name}", "ok")
        except Exception as e:
            status(f"Excel report failed: {e}", "warn")

    if is_on("report_compliance"):
        try:
            from netra.reports.compliance_report import generate_compliance_report
            path = generate_compliance_report(ctx, reports_dir)
            db.save_report(scan_id, "compliance", str(path))
            status(f"Compliance report: {path.name}", "ok")
        except Exception as e:
            status(f"Compliance report failed: {e}", "warn")

    # Evidence ZIP always generated if there are findings
    if findings:
        try:
            from netra.reports.evidence_zip import generate_evidence_zip
            path = generate_evidence_zip(ctx, workdir, reports_dir)
            db.save_report(scan_id, "evidence_zip", str(path))
            status(f"Evidence ZIP: {path.name}", "ok")
        except Exception as e:
            status(f"Evidence ZIP failed: {e}", "warn")


def _print_summary(scan_id: str, stats: dict, score: int,
                   grade: str, workdir: Path) -> None:
    """Print a coloured scan completion summary."""
    grade_color = {"A": C.GREEN, "B": C.TEAL, "C": C.YELLOW, "D": C.RED}.get(grade, C.WHITE)
    total = sum(stats.values())

    print(f"\n{C.TEAL}{'═' * 62}{C.RESET}")
    print(f"{C.TEAL}  NETRA SCAN COMPLETE{C.RESET}")
    print(f"{C.TEAL}{'─' * 62}{C.RESET}")
    print(f"  Scan ID:    {scan_id}")
    print(f"  Risk Score: {grade_color}{C.BOLD}{score}/100  Grade: {grade}{C.RESET}")
    print()
    print(f"  {C.RED}Critical: {stats.get('critical', 0):<4}{C.RESET}  "
          f"{C.ORANGE}High: {stats.get('high', 0):<4}{C.RESET}  "
          f"{C.YELLOW}Medium: {stats.get('medium', 0):<4}{C.RESET}  "
          f"{C.GREEN}Low: {stats.get('low', 0):<4}{C.RESET}  "
          f"Total: {total}")
    print()
    print(f"  Reports:    {workdir / 'reports'}")
    print(f"{C.TEAL}{'═' * 62}{C.RESET}\n")


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    """Entry point for NETRA CLI."""
    load_config()
    parser = build_parser()
    args   = parser.parse_args()

    print(BANNER)

    # ── MCP server ────────────────────────────────────────────────────
    if args.command == "mcp":
        from netra.mcp.server import run_mcp_server
        run_mcp_server()
        return

    # ── Install / check deps ──────────────────────────────────────────
    if args.install_deps:
        install_deps()
        return

    if args.check_deps:
        check_deps(verbose=True)
        return

    db = FindingsDB()

    # ── DB status ─────────────────────────────────────────────────────
    if args.status:
        show_status(db)
        return

    # ── DB management (FP / notes) ────────────────────────────────────
    if handle_db_commands(args, db):
        return

    # ── Resume ────────────────────────────────────────────────────────
    resume_from = None
    workdir     = None

    if args.resume:
        result = check_resume_prompt(CONFIG["output_dir"])
        if result:
            workdir, resume_from = result
            targets_file = str(workdir / "recon" / "targets.txt")
            targets = read_targets_file(targets_file)
            if not targets:
                status("No targets file found in workdir", "error")
                return
            status(f"Resuming {len(targets)} targets from {workdir.name}", "ok")
            run_scan(args, targets, workdir, resume_from)
            return

    # ── Fresh scan ────────────────────────────────────────────────────
    # Quick dep check (non-blocking)
    quick_check()

    targets = collect_targets(args)
    if not targets:
        status("No targets provided. Exiting.", "error")
        sys.exit(1)

    status(f"Collected {len(targets)} unique targets", "ok")

    label   = args.product or (targets[0] if targets else "scan")
    workdir = make_workdir(CONFIG["output_dir"], label)
    run_scan(args, targets, workdir)


if __name__ == "__main__":
    main()
