"""
netra/mcp/tools.py
All MCP tool definitions for the NETRA server.
Tools are registered onto a FastMCP instance in register_tools().

Each tool maps to a real NETRA capability backed by the SQLite DB,
checkpoint system, and report engine.
"""

import json
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Any

from netra.core.config   import CONFIG, load_config
from netra.core.database import FindingsDB


# ── Helpers ───────────────────────────────────────────────────────────

def _db() -> FindingsDB:
    """Return a fresh FindingsDB instance using current CONFIG."""
    return FindingsDB()


def _scan_workdir(scan_id: str) -> Optional[Path]:
    """
    Locate the workdir for a scan_id by checking the DB, then scanning
    the output directory for a matching checkpoint.

    Args:
        scan_id: The scan identifier to look up.

    Returns:
        Path to the workdir, or None if not found.
    """
    db  = _db()
    run = db.get_scan_run(scan_id)
    if run and run.get("workdir"):
        p = Path(run["workdir"])
        if p.exists():
            return p

    # Fallback: glob the output dir
    output_dir = Path(CONFIG.get("output_dir", Path.home() / "netra_output"))
    for cp in output_dir.rglob("checkpoint.json"):
        try:
            import json as _json
            data = _json.loads(cp.read_text())
            if data.get("scan_id") == scan_id:
                return cp.parent
        except Exception:
            continue
    return None


def _format_finding(f: dict, include_evidence: bool = False) -> dict:
    """
    Slim down a raw DB finding dict for MCP response size.

    Args:
        f:                Full finding dict from FindingsDB.
        include_evidence: If True, include raw evidence fields.

    Returns:
        Cleaned dict suitable for JSON serialisation.
    """
    out = {
        "id":            f.get("id"),
        "title":         f.get("title"),
        "severity":      f.get("severity"),
        "cvss_score":    f.get("cvss_score"),
        "host":          f.get("host"),
        "url":           f.get("url"),
        "cve_id":        f.get("cve_id"),
        "cwe_id":        f.get("cwe_id"),
        "category":      f.get("category"),
        "owasp_web":     f.get("owasp_web"),
        "mitre":         f.get("mitre_technique"),
        "status":        f.get("status"),
        "confidence":    f.get("confidence"),
        "description":   f.get("description", "")[:300],
        "remediation":   f.get("remediation", "")[:300],
        "ai_narrative":  f.get("ai_narrative", "")[:500],
    }
    if include_evidence:
        out["evidence"]    = f.get("evidence", "")[:1000]
        out["poc_command"] = f.get("poc_command", "")
        out["request"]     = f.get("request", "")[:500]
    return out


# ═══════════════════════════════════════════════════════════════════════
#  TOOL REGISTRATION
# ═══════════════════════════════════════════════════════════════════════

def register_tools(mcp: Any) -> None:
    """
    Register all NETRA tools onto a FastMCP server instance.

    Args:
        mcp: FastMCP server instance.
    """

    # ── Scan Management ───────────────────────────────────────────────

    @mcp.tool()
    def start_scan(
        targets: List[str],
        profile: str = "balanced",
        module: str = "vapt",
        client: str = "",
        engagement: str = "",
        product: str = "",
    ) -> dict:
        """
        Start a new NETRA security scan in a background process.

        Args:
            targets:    List of targets (domains, IPs, URLs).
            profile:    Scan profile: fast|balanced|deep|healthcare|legacy|mobile|saas.
            module:     Scan module (currently: vapt).
            client:     Optional client name for reports.
            engagement: Optional engagement name for reports.
            product:    Optional product tag.

        Returns:
            dict with scan_id, workdir, message, and config summary.
        """
        import subprocess
        import time

        if not targets:
            return {"error": "No targets provided"}

        valid_profiles = ["fast", "balanced", "deep", "healthcare", "legacy", "mobile", "saas"]
        if profile not in valid_profiles:
            return {"error": f"Invalid profile '{profile}'. Choose from: {valid_profiles}"}

        # Write a temp targets file
        output_dir = Path(CONFIG.get("output_dir", Path.home() / "netra_output"))
        output_dir.mkdir(parents=True, exist_ok=True)
        ts           = datetime.now().strftime("%Y%m%d_%H%M%S")
        targets_file = output_dir / f"mcp_targets_{ts}.txt"
        targets_file.write_text("\n".join(targets) + "\n")

        netra_root = Path(__file__).resolve().parents[2]
        netra_py   = netra_root / "netra.py"

        cmd = [
            "python3", str(netra_py),
            "-f", str(targets_file),
            "--profile", profile,
        ]
        if client:
            cmd += ["--client", client]
        if engagement:
            cmd += ["--engagement", engagement]
        if product:
            cmd += ["-p", product]

        try:
            proc = subprocess.Popen(
                cmd, cwd=str(netra_root),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            # Give it a moment to write the checkpoint
            time.sleep(1.5)

            # Try to find the scan_id from the newest checkpoint
            scan_id = "pending"
            for cp_file in sorted(output_dir.rglob("checkpoint.json"),
                                   key=lambda p: p.stat().st_mtime, reverse=True):
                try:
                    data = json.loads(cp_file.read_text())
                    if data.get("scan_id", "").startswith("scan_"):
                        scan_id = data["scan_id"]
                        workdir = str(cp_file.parent)
                        break
                except Exception:
                    continue
            else:
                workdir = str(output_dir)

            return {
                "scan_id":   scan_id,
                "workdir":   workdir,
                "pid":       proc.pid,
                "targets":   targets,
                "profile":   profile,
                "message":   f"Scan started. Use check_status('{scan_id}') to monitor progress.",
            }
        except Exception as e:
            return {"error": f"Failed to start scan: {e}"}

    @mcp.tool()
    def resume_scan(scan_id: str) -> dict:
        """
        Resume an incomplete NETRA scan from its last checkpoint.

        Args:
            scan_id: The scan ID to resume.

        Returns:
            dict with status and message.
        """
        import subprocess

        workdir = _scan_workdir(scan_id)
        if not workdir:
            return {"error": f"Scan '{scan_id}' not found"}

        netra_root = Path(__file__).resolve().parents[2]
        netra_py   = netra_root / "netra.py"

        try:
            proc = subprocess.Popen(
                ["python3", str(netra_py), "--resume"],
                cwd=str(netra_root),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return {
                "scan_id": scan_id,
                "pid":     proc.pid,
                "message": f"Resuming scan '{scan_id}'. Use check_status to monitor.",
            }
        except Exception as e:
            return {"error": f"Failed to resume: {e}"}

    @mcp.tool()
    def check_status(scan_id: str) -> dict:
        """
        Get the current status of a NETRA scan.

        Args:
            scan_id: The scan ID to check.

        Returns:
            dict with phase, completed_phases, progress_percent, and finding counts.
        """
        workdir = _scan_workdir(scan_id)
        if not workdir:
            return {"error": f"Scan '{scan_id}' not found"}

        cp_path = workdir / "checkpoint.json"
        if not cp_path.exists():
            return {"error": "Checkpoint not found"}

        try:
            data = json.loads(cp_path.read_text())
        except Exception as e:
            return {"error": f"Cannot read checkpoint: {e}"}

        completed   = data.get("completed_phases", [])
        current     = data.get("phase", "0_input")
        all_phases  = [
            "0_input", "1_osint", "2_subdomains", "3_discovery",
            "4_ports", "5_vulns", "6_pentest", "7_auth_session",
            "8_ai_surface", "9_enrichment", "10_ai_analysis", "11_reports"
        ]
        total_phases  = len(all_phases)
        done_count    = sum(1 for p in all_phases if p in completed)
        pct           = round((done_count / total_phases) * 100)
        is_complete   = "complete" in completed

        # Live finding counts
        db    = _db()
        stats = db.get_stats(scan_id)

        return {
            "scan_id":          scan_id,
            "current_phase":    current,
            "completed_phases": completed,
            "progress_percent": pct,
            "is_complete":      is_complete,
            "started_at":       data.get("started_at", "?")[:19].replace("T", " "),
            "updated_at":       data.get("updated_at", "?")[:19].replace("T", " "),
            "findings":         stats,
            "workdir":          str(workdir),
        }

    # ── Findings ──────────────────────────────────────────────────────

    @mcp.tool()
    def get_findings(
        scan_id: str,
        severity: str = "",
        host: str = "",
        include_evidence: bool = False,
        limit: int = 50,
    ) -> dict:
        """
        Retrieve findings from a scan, with optional filters.

        Args:
            scan_id:          The scan ID to query.
            severity:         Comma-separated severities to filter: critical,high,medium,low.
            host:             Filter by host substring.
            include_evidence: Include raw evidence and PoC fields.
            limit:            Max number of findings to return (default 50).

        Returns:
            dict with findings list and summary stats.
        """
        db = _db()
        findings = db.get_findings(
            scan_id=scan_id,
            severity=severity or None,
            host=host or None,
        )[:limit]

        return {
            "scan_id":  scan_id,
            "count":    len(findings),
            "findings": [_format_finding(f, include_evidence) for f in findings],
            "stats":    db.get_stats(scan_id),
        }

    @mcp.tool()
    def get_finding_detail(finding_id: int) -> dict:
        """
        Get the full detail for a single finding by ID.

        Args:
            finding_id: The integer finding ID.

        Returns:
            Full finding dict including evidence, PoC, and AI analyses.
        """
        db = _db()
        with db._conn() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id=?", (finding_id,)
            ).fetchone()

        if not row:
            return {"error": f"Finding #{finding_id} not found"}

        f         = dict(row)
        analyses  = db.get_ai_analyses(finding_id)

        return {
            **_format_finding(f, include_evidence=True),
            "hipaa_ref":      f.get("hipaa_ref"),
            "pci_ref":        f.get("pci_ref"),
            "owasp_api":      f.get("owasp_api"),
            "impact":         f.get("impact"),
            "notes":          f.get("notes"),
            "found_at":       f.get("found_at"),
            "ai_analyses":    analyses,
        }

    @mcp.tool()
    def mark_false_positive(
        finding_id: int,
        reason: str,
        operator: str = "",
    ) -> dict:
        """
        Mark a finding as a false positive and add it to the FP registry.

        Args:
            finding_id: The integer finding ID.
            reason:     Explanation for why this is a false positive.
            operator:   Operator name (optional, defaults to config value).

        Returns:
            Confirmation dict.
        """
        db       = _db()
        operator = operator or CONFIG.get("operator", "mcp")
        db.mark_fp(finding_id, reason, operator)

        return {
            "finding_id": finding_id,
            "status":     "marked_fp",
            "reason":     reason,
            "operator":   operator,
        }

    @mcp.tool()
    def add_finding_note(
        finding_id: int,
        note: str,
        operator: str = "",
    ) -> dict:
        """
        Append a timestamped note to a finding.

        Args:
            finding_id: The integer finding ID.
            note:       The note text to append.
            operator:   Operator name (optional).

        Returns:
            Confirmation dict.
        """
        db       = _db()
        operator = operator or CONFIG.get("operator", "mcp")
        db.add_note(finding_id, note, operator)

        return {
            "finding_id": finding_id,
            "status":     "note_added",
            "operator":   operator,
        }

    # ── Risk & Scoring ────────────────────────────────────────────────

    @mcp.tool()
    def get_risk_score(scan_id: str) -> dict:
        """
        Get the risk score and grade for a scan.

        Args:
            scan_id: The scan ID to score.

        Returns:
            dict with score (0-100), grade (A/B/C/D), and breakdown.
        """
        db            = _db()
        score, grade  = db.compute_risk_score(scan_id)
        stats         = db.get_stats(scan_id)
        total         = sum(stats.values())

        grade_desc = {
            "A": "Low risk — minimal findings, well-hardened target",
            "B": "Medium risk — some findings, manageable remediation",
            "C": "High risk — significant findings requiring prompt action",
            "D": "Critical risk — severe findings, immediate remediation required",
        }

        return {
            "scan_id":     scan_id,
            "score":       score,
            "grade":       grade,
            "description": grade_desc.get(grade, ""),
            "findings":    stats,
            "total":       total,
        }

    @mcp.tool()
    def compare_scans(scan_id_new: str, scan_id_old: str) -> dict:
        """
        Compare two scans to identify new, fixed, and persistent findings.

        Args:
            scan_id_new: The newer scan ID.
            scan_id_old: The older/baseline scan ID.

        Returns:
            dict with new_findings, fixed_findings, persistent, and summary.
        """
        db   = _db()
        diff = db.compute_diff(scan_id_new, scan_id_old)

        return {
            "scan_new":       scan_id_new,
            "scan_old":       scan_id_old,
            "summary":        diff["summary"],
            "new_findings":   [_format_finding(f) for f in diff["new_findings"][:20]],
            "fixed_findings": [_format_finding(f) for f in diff["fixed_findings"][:20]],
            "persistent":     [_format_finding(f) for f in diff["persistent"][:20]],
        }

    # ── Attack Chains ─────────────────────────────────────────────────

    @mcp.tool()
    def get_attack_chains(scan_id: str) -> dict:
        """
        Get AI-discovered multi-step attack chains for a scan.

        Args:
            scan_id: The scan ID to query.

        Returns:
            dict with list of attack chains, each with MITRE sequence and narrative.
        """
        db     = _db()
        chains = db.get_attack_chains(scan_id)

        formatted = []
        for c in chains:
            nodes = []
            try:
                node_ids = json.loads(c.get("nodes", "[]"))
                for fid in node_ids:
                    with db._conn() as conn:
                        row = conn.execute(
                            "SELECT id,title,severity,cvss_score,host FROM findings WHERE id=?",
                            (fid,)
                        ).fetchone()
                    if row:
                        nodes.append(dict(row))
            except Exception:
                pass

            formatted.append({
                "id":             c["id"],
                "combined_cvss":  c["combined_cvss"],
                "mitre_sequence": c["mitre_sequence"],
                "narrative":      c.get("narrative", "")[:800],
                "nodes":          nodes,
                "created_at":     c.get("created_at"),
            })

        return {
            "scan_id": scan_id,
            "count":   len(formatted),
            "chains":  formatted,
        }

    # ── Reports ───────────────────────────────────────────────────────

    @mcp.tool()
    def generate_report(
        scan_id: str,
        report_type: str = "html",
    ) -> dict:
        """
        Generate a specific report type for a completed scan.

        Args:
            scan_id:     The scan ID to report on.
            report_type: Report format: word|pdf|html|excel|compliance|evidence_zip|all.

        Returns:
            dict with report path(s) and status.
        """
        valid_types = ["word", "pdf", "html", "excel", "compliance", "evidence_zip", "all"]
        if report_type not in valid_types:
            return {"error": f"Invalid type '{report_type}'. Choose from: {valid_types}"}

        workdir = _scan_workdir(scan_id)
        if not workdir:
            return {"error": f"Scan '{scan_id}' not found"}

        db          = _db()
        findings    = db.get_findings(scan_id)
        assets      = db.get_assets(scan_id)
        chains      = db.get_attack_chains(scan_id)
        stats       = db.get_stats(scan_id)
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

        reports_dir = workdir / "reports"
        reports_dir.mkdir(exist_ok=True)
        generated: dict = {}

        def _gen(rtype: str) -> None:
            try:
                if rtype == "word":
                    from netra.reports.word_report import generate_word_report
                    path = generate_word_report(ctx, reports_dir)
                elif rtype == "pdf":
                    from netra.reports.pdf_report import generate_pdf_report
                    path = generate_pdf_report(ctx, reports_dir)
                elif rtype == "html":
                    from netra.reports.html_report import generate_html_report
                    path = generate_html_report(ctx, reports_dir)
                elif rtype == "excel":
                    from netra.reports.excel_report import generate_excel_report
                    path = generate_excel_report(ctx, reports_dir)
                elif rtype == "compliance":
                    from netra.reports.compliance_report import generate_compliance_report
                    path = generate_compliance_report(ctx, reports_dir)
                elif rtype == "evidence_zip":
                    from netra.reports.evidence_zip import generate_evidence_zip
                    path = generate_evidence_zip(ctx, workdir, reports_dir)
                else:
                    return
                db.save_report(scan_id, rtype, str(path))
                generated[rtype] = str(path)
            except Exception as e:
                generated[rtype] = f"ERROR: {e}"

        if report_type == "all":
            for t in ["word", "pdf", "html", "excel", "compliance", "evidence_zip"]:
                _gen(t)
        else:
            _gen(report_type)

        return {
            "scan_id":   scan_id,
            "generated": generated,
            "message":   f"Reports saved to {reports_dir}",
        }

    @mcp.tool()
    def list_reports(scan_id: str) -> dict:
        """
        List all generated reports for a scan.

        Args:
            scan_id: The scan ID to list reports for.

        Returns:
            dict with list of report records.
        """
        db      = _db()
        reports = db.get_reports(scan_id)

        return {
            "scan_id": scan_id,
            "count":   len(reports),
            "reports": [
                {
                    "type":         r["report_type"],
                    "path":         r["path"],
                    "generated_at": r["generated_at"],
                    "exists":       Path(r["path"]).exists() if r.get("path") else False,
                }
                for r in reports
            ],
        }

    # ── Assets ────────────────────────────────────────────────────────

    @mcp.tool()
    def get_assets(
        scan_id: str,
        asset_type: str = "",
        live_only: bool = False,
    ) -> dict:
        """
        Get assets discovered during recon for a scan.

        Args:
            scan_id:    The scan ID to query.
            asset_type: Filter by type: domain|ip|subdomain|url|api_endpoint.
            live_only:  If True, return only live/responsive assets.

        Returns:
            dict with asset list and count.
        """
        db     = _db()
        assets = db.get_assets(
            scan_id,
            asset_type=asset_type or None,
            live_only=live_only,
        )

        return {
            "scan_id":    scan_id,
            "count":      len(assets),
            "asset_type": asset_type or "all",
            "assets": [
                {
                    "value":      a["value"],
                    "type":       a["asset_type"],
                    "is_live":    bool(a.get("is_live")),
                    "tech_stack": a.get("tech_stack"),
                    "ports":      a.get("ports"),
                    "product":    a.get("product"),
                }
                for a in assets
            ],
        }

    # ── AI Analysis ───────────────────────────────────────────────────

    @mcp.tool()
    def run_ai_analysis(
        scan_id: str,
        finding_ids: Optional[List[int]] = None,
    ) -> dict:
        """
        Trigger AI consensus analysis on findings from a scan.
        Uses multi-persona voting (bug_bounty_hunter, code_auditor, pentester + skeptic).

        Args:
            scan_id:     The scan ID to analyse.
            finding_ids: Optional list of specific finding IDs. If None, analyses all.

        Returns:
            dict with analysis results per finding.
        """
        try:
            from netra.ai_brain.consensus import run_consensus_analysis
            db       = _db()
            results  = run_consensus_analysis(scan_id, db, finding_ids=finding_ids)
            return {
                "scan_id":  scan_id,
                "analysed": len(results),
                "results":  results[:20],   # cap for MCP response size
            }
        except Exception as e:
            return {"error": f"AI analysis failed: {e}"}

    @mcp.tool()
    def get_ai_summary(scan_id: str) -> dict:
        """
        Get a Claude-generated executive summary for a scan.

        Args:
            scan_id: The scan ID to summarise.

        Returns:
            dict with executive summary and key findings narrative.
        """
        try:
            from netra.ai_brain.narrative import generate_executive_summary
            db      = _db()
            ctx     = {
                "scan_id":    scan_id,
                "findings":   db.get_findings(scan_id),
                "stats":      db.get_stats(scan_id),
                "chains":     db.get_attack_chains(scan_id),
                "risk_score": db.compute_risk_score(scan_id)[0],
                "risk_grade": db.compute_risk_score(scan_id)[1],
                "client":     CONFIG.get("client_name", ""),
                "engagement": CONFIG.get("engagement_name", ""),
            }
            summary = generate_executive_summary(ctx)
            return {
                "scan_id": scan_id,
                "summary": summary,
            }
        except Exception as e:
            return {"error": f"Summary generation failed: {e}"}

    # ── Scan History ──────────────────────────────────────────────────

    @mcp.tool()
    def list_scans(limit: int = 20) -> dict:
        """
        List recent NETRA scans with their status and risk grades.

        Args:
            limit: Maximum number of scans to return (default 20).

        Returns:
            dict with list of scan records.
        """
        db = _db()
        with db._conn() as conn:
            rows = conn.execute(
                "SELECT scan_id, started_at, completed_at, risk_score, "
                "risk_grade, finding_count, profile "
                "FROM scan_runs ORDER BY started_at DESC LIMIT ?",
                (limit,)
            ).fetchall()

        scans = []
        for r in rows:
            scans.append({
                "scan_id":       r["scan_id"],
                "started_at":    (r["started_at"] or "")[:19].replace("T", " "),
                "completed_at":  (r["completed_at"] or "")[:19].replace("T", " "),
                "is_complete":   bool(r["completed_at"]),
                "risk_score":    r["risk_score"],
                "risk_grade":    r["risk_grade"],
                "finding_count": r["finding_count"],
                "profile":       r["profile"],
            })

        return {
            "count": len(scans),
            "scans": scans,
        }

    @mcp.tool()
    def netra_info() -> dict:
        """
        Return information about the NETRA installation.

        Returns:
            dict with version, config paths, and capabilities summary.
        """
        return {
            "name":        "NETRA नेत्र",
            "tagline":     "The Third Eye of Security",
            "version":     "1.0.0",
            "license":     "AGPL-3.0",
            "author":      "Yash Wardhan Gautam",
            "config_file": str(Path.home() / ".netra.conf"),
            "db_path":     CONFIG.get("db_path", "not configured"),
            "output_dir":  CONFIG.get("output_dir", "not configured"),
            "ai_enabled":  bool(CONFIG.get("claude_api_key") or CONFIG.get("ollama_url")),
            "tools": {
                "scan":     ["start_scan", "resume_scan", "check_status", "list_scans"],
                "findings": ["get_findings", "get_finding_detail", "mark_false_positive",
                             "add_finding_note"],
                "risk":     ["get_risk_score", "compare_scans"],
                "chains":   ["get_attack_chains"],
                "reports":  ["generate_report", "list_reports"],
                "assets":   ["get_assets"],
                "ai":       ["run_ai_analysis", "get_ai_summary"],
                "meta":     ["netra_info"],
            },
            "scan_profiles": ["fast", "balanced", "deep", "healthcare", "legacy", "mobile", "saas"],
        }
