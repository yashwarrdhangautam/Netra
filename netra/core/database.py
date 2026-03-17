"""
netra/core/database.py
SQLite findings database. Single source of truth for all findings.
Supports multiple operators, finding status, FP management,
CVSS scores, compliance mapping, remediation tracking.

For team sharing: sync findings.db via Syncthing / shared mount / git.
WAL mode enabled so multiple readers work concurrently.
"""

import sqlite3
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Engagements (a named scan session or project)
CREATE TABLE IF NOT EXISTS engagements (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    client          TEXT DEFAULT '',
    scope           TEXT DEFAULT '',       -- JSON list of targets
    profile         TEXT DEFAULT 'balanced',
    operator        TEXT DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now')),
    status          TEXT DEFAULT 'active'  -- active|complete|archived
);

-- Scan runs (one per tool execution)
CREATE TABLE IF NOT EXISTS scan_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   INTEGER REFERENCES engagements(id),
    scan_id         TEXT UNIQUE,           -- from checkpoint
    workdir         TEXT,
    operator        TEXT DEFAULT '',
    profile         TEXT DEFAULT 'balanced',
    started_at      TEXT DEFAULT (datetime('now')),
    completed_at    TEXT,
    phases_done     TEXT DEFAULT '[]',     -- JSON list
    target_count    INTEGER DEFAULT 0,
    finding_count   INTEGER DEFAULT 0,
    risk_score      INTEGER,
    risk_grade      TEXT                   -- A/B/C/D
);

-- Assets discovered during recon
CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT,
    asset_type      TEXT,                  -- domain|ip|subdomain|url|api_endpoint
    value           TEXT NOT NULL,
    product         TEXT DEFAULT '',
    is_live         INTEGER DEFAULT 0,     -- 1 = responded to httpx
    tech_stack      TEXT DEFAULT '',       -- JSON: {server, cms, framework, ...}
    ports           TEXT DEFAULT '',       -- JSON list of open ports
    screenshot_path TEXT DEFAULT '',
    first_seen      TEXT DEFAULT (datetime('now')),
    last_seen       TEXT DEFAULT (datetime('now')),
    UNIQUE(scan_id, value)
);

-- Findings (vulnerabilities)
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT,
    engagement_id   INTEGER REFERENCES engagements(id),

    -- Identity
    finding_hash    TEXT,                  -- sha256(template_id+host+path) dedup key
    title           TEXT NOT NULL,
    template_id     TEXT DEFAULT '',       -- nuclei template or custom check ID
    cve_id          TEXT DEFAULT '',
    cwe_id          TEXT DEFAULT '',

    -- Classification
    severity        TEXT DEFAULT 'medium', -- critical|high|medium|low|info
    cvss_score      REAL DEFAULT 0,
    cvss_vector     TEXT DEFAULT '',       -- CVSS:3.1/AV:N/AC:L/...
    category        TEXT DEFAULT '',       -- injection|auth|api|misconfig|...
    owasp_web       TEXT DEFAULT '',       -- A03:2021 etc
    owasp_api       TEXT DEFAULT '',       -- API1:2023 etc
    owasp_llm       TEXT DEFAULT '',       -- LLM01 etc
    mitre_technique TEXT DEFAULT '',       -- T1190 etc
    hipaa_ref       TEXT DEFAULT '',       -- §164.312(a) etc
    pci_ref         TEXT DEFAULT '',

    -- Target
    host            TEXT DEFAULT '',
    url             TEXT DEFAULT '',
    path            TEXT DEFAULT '',
    parameter       TEXT DEFAULT '',
    product         TEXT DEFAULT '',

    -- Evidence
    description     TEXT DEFAULT '',
    evidence        TEXT DEFAULT '',       -- raw HTTP req/resp or details
    request         TEXT DEFAULT '',       -- raw HTTP request
    response        TEXT DEFAULT '',       -- raw HTTP response (truncated)
    screenshot_path TEXT DEFAULT '',
    poc_command     TEXT DEFAULT '',       -- exact command to reproduce

    -- Impact & Fix
    impact          TEXT DEFAULT '',       -- business impact statement
    remediation     TEXT DEFAULT '',       -- exact fix steps
    references      TEXT DEFAULT '',       -- JSON list of URLs
    ai_narrative    TEXT DEFAULT '',       -- Claude-generated finding narrative

    -- Workflow
    status          TEXT DEFAULT 'open',   -- open|fp|fixed|verified|accepted
    confidence      INTEGER DEFAULT 80,    -- 0-100, AI-assigned
    operator        TEXT DEFAULT '',
    verified_by     TEXT DEFAULT '',
    fp_reason       TEXT DEFAULT '',
    notes           TEXT DEFAULT '',

    -- Timestamps
    found_at        TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now')),
    fixed_at        TEXT,
    verified_at     TEXT,

    -- Dedup
    UNIQUE(finding_hash)
);

-- False positive registry (persists across scans)
CREATE TABLE IF NOT EXISTS false_positives (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id     TEXT,
    host            TEXT,
    reason          TEXT DEFAULT '',
    operator        TEXT DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now'))
);

-- Attack chains (multi-step exploit paths discovered by AI)
CREATE TABLE IF NOT EXISTS attack_chains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT,
    nodes           TEXT DEFAULT '[]',     -- JSON list of finding IDs
    combined_cvss   REAL DEFAULT 0,
    mitre_sequence  TEXT DEFAULT '',       -- e.g. "T1190 → T1059 → T1078"
    narrative       TEXT DEFAULT '',       -- Claude-generated chain narrative
    created_at      TEXT DEFAULT (datetime('now'))
);

-- AI analysis results per finding and persona
CREATE TABLE IF NOT EXISTS ai_analysis (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER REFERENCES findings(id),
    persona         TEXT DEFAULT '',       -- bug_bounty_hunter|code_auditor|pentester|skeptic
    verdict         TEXT DEFAULT '',       -- confirm|reject|needs_more_info
    confidence      INTEGER DEFAULT 0,     -- 0-100
    narrative       TEXT DEFAULT '',
    raw_response    TEXT DEFAULT '',
    timestamp       TEXT DEFAULT (datetime('now'))
);

-- Generated reports
CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT,
    report_type     TEXT DEFAULT '',       -- word|pdf|html|excel|compliance|evidence_zip
    path            TEXT DEFAULT '',
    generated_at    TEXT DEFAULT (datetime('now'))
);

-- Compliance findings (mapped from vulnerability findings)
CREATE TABLE IF NOT EXISTS compliance_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT,
    framework       TEXT,                  -- HIPAA|PCI|OWASP
    control         TEXT,                  -- e.g. §164.312(a)
    status          TEXT,                  -- pass|fail|warn|na
    finding_ids     TEXT DEFAULT '[]',     -- JSON list of finding.id
    notes           TEXT DEFAULT ''
);

-- Remediation tracking
CREATE TABLE IF NOT EXISTS remediations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER REFERENCES findings(id),
    action          TEXT,                  -- open|in_progress|fixed|verified|wont_fix
    operator        TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now'))
);

-- Operators / team members
CREATE TABLE IF NOT EXISTS operators (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE,
    email           TEXT DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now'))
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_findings_scan    ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_host    ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status  ON findings(status);
CREATE INDEX IF NOT EXISTS idx_assets_scan      ON assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_chains_scan      ON attack_chains(scan_id);
CREATE INDEX IF NOT EXISTS idx_ai_finding       ON ai_analysis(finding_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan     ON reports(scan_id);
"""


class FindingsDB:
    """
    Main interface to the SQLite findings database.

    Usage:
        db = FindingsDB()                # uses CONFIG["db_path"]
        db = FindingsDB("/path/to/db")   # explicit path

        fid = db.add_finding({...})
        db.mark_fp(fid, "test environment")
        findings = db.get_findings(scan_id="scan_123", severity="critical")
    """

    def __init__(self, db_path: str = None) -> None:
        """Initialise the database, creating it if it doesn't exist."""
        from netra.core.config import CONFIG
        self.path = Path(db_path or CONFIG.get("db_path", "findings.db"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        """Return a new SQLite connection with WAL mode and row factory."""
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        """Create all tables if they don't exist."""
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    # ── Engagements ───────────────────────────────────────────────────

    def create_engagement(self, name: str, client: str = "",
                          scope: list = None, profile: str = "balanced",
                          operator: str = "") -> int:
        """Create a new engagement record. Returns engagement ID."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO engagements(name,client,scope,profile,operator) VALUES(?,?,?,?,?)",
                (name, client, json.dumps(scope or []), profile, operator)
            )
            return cur.lastrowid

    def get_engagement(self, engagement_id: int) -> Optional[dict]:
        """Fetch engagement by ID. Returns dict or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM engagements WHERE id=?", (engagement_id,)
            ).fetchone()
            return dict(row) if row else None

    # ── Scan Runs ─────────────────────────────────────────────────────

    def create_scan_run(self, scan_id: str, workdir: str, operator: str = "",
                        profile: str = "balanced", engagement_id: int = None) -> int:
        """Register a new scan run. Returns row ID."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO scan_runs"
                "(scan_id,workdir,operator,profile,engagement_id) VALUES(?,?,?,?,?)",
                (scan_id, workdir, operator, profile, engagement_id)
            )
            return cur.lastrowid

    def complete_scan_run(self, scan_id: str, risk_score: int,
                          risk_grade: str, phases_done: list) -> None:
        """Mark a scan run as completed with final stats."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE scan_runs SET completed_at=datetime('now'), "
                "risk_score=?, risk_grade=?, phases_done=?, "
                "finding_count=(SELECT COUNT(*) FROM findings WHERE scan_id=?) "
                "WHERE scan_id=?",
                (risk_score, risk_grade, json.dumps(phases_done), scan_id, scan_id)
            )

    def get_scan_run(self, scan_id: str) -> Optional[dict]:
        """Fetch scan run by scan_id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scan_runs WHERE scan_id=?", (scan_id,)
            ).fetchone()
            return dict(row) if row else None

    # ── Assets ────────────────────────────────────────────────────────

    def add_asset(self, scan_id: str, asset_type: str, value: str,
                  product: str = "", is_live: bool = False,
                  tech_stack: dict = None, ports: list = None) -> int:
        """Add an asset record. Silently ignores duplicates."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO assets"
                "(scan_id,asset_type,value,product,is_live,tech_stack,ports) VALUES(?,?,?,?,?,?,?)",
                (scan_id, asset_type, value, product,
                 1 if is_live else 0,
                 json.dumps(tech_stack or {}),
                 json.dumps(ports or []))
            )
            return cur.lastrowid

    def get_assets(self, scan_id: str, asset_type: str = None,
                   live_only: bool = False) -> List[dict]:
        """Retrieve assets for a scan, optionally filtered."""
        query  = "SELECT * FROM assets WHERE scan_id=?"
        params: list = [scan_id]
        if asset_type:
            query  += " AND asset_type=?"
            params.append(asset_type)
        if live_only:
            query  += " AND is_live=1"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # ── Findings ──────────────────────────────────────────────────────

    def add_finding(self, finding: dict) -> Optional[int]:
        """
        Add a finding. Deduplicates by finding_hash.
        Returns finding ID, or None if duplicate or known FP.
        """
        h_input = (
            finding.get("template_id", "") +
            finding.get("host", "") +
            finding.get("path", "") +
            finding.get("title", "")
        ).lower()
        finding["finding_hash"] = hashlib.sha256(h_input.encode()).hexdigest()[:16]

        if self._is_known_fp(finding.get("template_id", ""), finding.get("host", "")):
            return None

        cols = [
            "scan_id", "engagement_id", "finding_hash", "title",
            "template_id", "cve_id", "cwe_id", "severity",
            "cvss_score", "cvss_vector", "category",
            "owasp_web", "owasp_api", "owasp_llm",
            "mitre_technique", "hipaa_ref", "pci_ref",
            "host", "url", "path", "parameter", "product",
            "description", "evidence", "request", "response",
            "screenshot_path", "poc_command",
            "impact", "remediation", "references",
            "ai_narrative", "confidence", "operator",
        ]
        values = [finding.get(c, "") for c in cols]

        try:
            with self._conn() as conn:
                cur = conn.execute(
                    f"INSERT OR IGNORE INTO findings({','.join(cols)}) "
                    f"VALUES({','.join(['?'] * len(cols))})",
                    values
                )
                return cur.lastrowid
        except sqlite3.IntegrityError:
            return None

    def get_findings(self, scan_id: str = None, severity: str = None,
                     status: str = None, host: str = None,
                     product: str = None, exclude_fps: bool = True) -> List[dict]:
        """Retrieve findings with optional filters, ordered by severity."""
        query  = "SELECT * FROM findings WHERE 1=1"
        params: list = []
        if scan_id:
            query  += " AND scan_id=?"
            params.append(scan_id)
        if severity:
            sevs = [s.strip() for s in severity.split(",")]
            query  += f" AND severity IN ({','.join(['?'] * len(sevs))})"
            params.extend(sevs)
        if status:
            query  += " AND status=?"
            params.append(status)
        if host:
            query  += " AND host LIKE ?"
            params.append(f"%{host}%")
        if product:
            query  += " AND product=?"
            params.append(product)
        if exclude_fps:
            query  += " AND status != 'fp'"
        query += (" ORDER BY CASE severity "
                  "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
                  "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END")

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def mark_fp(self, finding_id: int, reason: str = "", operator: str = "") -> None:
        """Mark a finding as false positive and persist to FP registry."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT template_id,host FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE findings SET status='fp', fp_reason=?, "
                    "updated_at=datetime('now') WHERE id=?",
                    (reason, finding_id)
                )
                conn.execute(
                    "INSERT OR IGNORE INTO false_positives"
                    "(template_id,host,reason,operator) VALUES(?,?,?,?)",
                    (row["template_id"], row["host"], reason, operator)
                )

    def mark_fixed(self, finding_id: int, verified_by: str = "") -> None:
        """Mark a finding as fixed and record verification."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE findings SET status='fixed', fixed_at=datetime('now'), "
                "verified_by=?, verified_at=datetime('now'), "
                "updated_at=datetime('now') WHERE id=?",
                (verified_by, finding_id)
            )

    def add_note(self, finding_id: int, note: str, operator: str = "") -> None:
        """Append a timestamped note to a finding."""
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT notes FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
            old_notes = existing["notes"] if existing else ""
            ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            new_notes = f"{old_notes}\n[{ts}] {operator}: {note}".strip()
            conn.execute(
                "UPDATE findings SET notes=?, updated_at=datetime('now') WHERE id=?",
                (new_notes, finding_id)
            )

    def update_ai_narrative(self, finding_id: int, narrative: str) -> None:
        """Update the AI-generated narrative for a finding."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE findings SET ai_narrative=?, updated_at=datetime('now') WHERE id=?",
                (narrative, finding_id)
            )

    def _is_known_fp(self, template_id: str, host: str) -> bool:
        """Check if a template_id + host combo is in the FP registry."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM false_positives WHERE template_id=? AND host=?",
                (template_id, host)
            ).fetchone()
            return row is not None

    # ── Attack Chains ─────────────────────────────────────────────────

    def save_attack_chain(self, scan_id: str, nodes: list,
                          combined_cvss: float, mitre_sequence: str,
                          narrative: str) -> int:
        """Persist a discovered attack chain. Returns chain ID."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO attack_chains"
                "(scan_id,nodes,combined_cvss,mitre_sequence,narrative) VALUES(?,?,?,?,?)",
                (scan_id, json.dumps(nodes), combined_cvss, mitre_sequence, narrative)
            )
            return cur.lastrowid

    def get_attack_chains(self, scan_id: str) -> List[dict]:
        """Retrieve all attack chains for a scan."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM attack_chains WHERE scan_id=? ORDER BY combined_cvss DESC",
                (scan_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── AI Analysis ───────────────────────────────────────────────────

    def save_ai_analysis(self, finding_id: int, persona: str, verdict: str,
                         confidence: int, narrative: str,
                         raw_response: str = "") -> int:
        """Persist an AI persona analysis result."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO ai_analysis"
                "(finding_id,persona,verdict,confidence,narrative,raw_response) "
                "VALUES(?,?,?,?,?,?)",
                (finding_id, persona, verdict, confidence, narrative, raw_response)
            )
            return cur.lastrowid

    def get_ai_analyses(self, finding_id: int) -> List[dict]:
        """Retrieve all AI analyses for a finding."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ai_analysis WHERE finding_id=? ORDER BY timestamp",
                (finding_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Reports ───────────────────────────────────────────────────────

    def save_report(self, scan_id: str, report_type: str, path: str) -> int:
        """Record a generated report. Returns row ID."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO reports(scan_id,report_type,path) VALUES(?,?,?)",
                (scan_id, report_type, path)
            )
            return cur.lastrowid

    def get_reports(self, scan_id: str) -> List[dict]:
        """Retrieve all reports for a scan."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM reports WHERE scan_id=? ORDER BY generated_at",
                (scan_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Stats & Summary ───────────────────────────────────────────────

    def get_stats(self, scan_id: str) -> Dict[str, int]:
        """Return finding counts per severity for a scan."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings "
                "WHERE scan_id=? AND status!='fp' GROUP BY severity",
                (scan_id,)
            ).fetchall()
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in rows:
            counts[r["severity"]] = r["cnt"]
        return counts

    def compute_risk_score(self, scan_id: str) -> tuple:
        """
        Compute risk score and grade for a scan.

        Returns:
            (score: int, grade: str) where score is 0-100 and grade is A/B/C/D.
        """
        stats = self.get_stats(scan_id)

        with self._conn() as conn:
            takeovers = conn.execute(
                "SELECT COUNT(*) as c FROM findings WHERE scan_id=? "
                "AND category='takeover' AND status!='fp'", (scan_id,)
            ).fetchone()["c"]
            js_secrets = conn.execute(
                "SELECT COUNT(*) as c FROM findings WHERE scan_id=? "
                "AND category='js_secrets' AND status!='fp'", (scan_id,)
            ).fetchone()["c"]
            exposed_panels = conn.execute(
                "SELECT COUNT(*) as c FROM findings WHERE scan_id=? "
                "AND template_id LIKE '%default-login%' AND status!='fp'", (scan_id,)
            ).fetchone()["c"]

        score = 100
        score -= min(stats["critical"] * 25, 60)
        score -= min(stats["high"] * 8, 30)
        score -= stats["medium"] * 2
        score -= takeovers * 20
        score -= exposed_panels * 5
        score -= js_secrets * 15
        score = max(score, 0)

        if score >= 85:
            grade = "A"
        elif score >= 65:
            grade = "B"
        elif score >= 40:
            grade = "C"
        else:
            grade = "D"

        return score, grade

    def compute_diff(self, scan_id_new: str, scan_id_old: str) -> dict:
        """
        Compare two scans to identify new, fixed, and persistent findings.

        Returns:
            dict with keys: new_findings, fixed_findings, persistent, summary
        """
        def finding_key(f: dict) -> str:
            """Build a deduplication key from finding fields."""
            return f"{f['template_id']}|{f['host']}|{f['path']}"

        new_findings = {finding_key(f): f for f in self.get_findings(scan_id_new)}
        old_findings = {finding_key(f): f for f in self.get_findings(scan_id_old)}

        added   = [f for k, f in new_findings.items() if k not in old_findings]
        fixed   = [f for k, f in old_findings.items() if k not in new_findings]
        persist = [f for k, f in new_findings.items() if k in old_findings]

        sort_key = lambda x: x.get("cvss_score", 0)
        return {
            "new_findings":   sorted(added,   key=sort_key, reverse=True),
            "fixed_findings": sorted(fixed,   key=sort_key, reverse=True),
            "persistent":     sorted(persist, key=sort_key, reverse=True),
            "summary": {
                "new":   len(added),
                "fixed": len(fixed),
                "same":  len(persist),
            }
        }

    def get_open_findings_count(self, scan_id: str) -> Dict[str, int]:
        """Quick count for display. Alias for get_stats."""
        return self.get_stats(scan_id)
