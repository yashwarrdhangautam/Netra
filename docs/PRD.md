# NETRA — Product Requirements Document (PRD)

**Version:** 1.0.0
**Last Updated:** 2026-03-29
**Status:** Production Ready (Phase 3 Complete)
**License:** AGPL-3.0
**Author:** Yash Wardhan Gautam

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Target Users & Jobs-to-be-Done](#3-target-users--jobs-to-be-done)
4. [Product Vision & Core Principles](#4-product-vision--core-principles)
5. [Feature Specifications by Phase](#5-feature-specifications-by-phase)
6. [Technical Architecture](#6-technical-architecture)
7. [API Specification](#7-api-specification)
8. [Database Schema](#8-database-schema)
9. [Security Requirements](#9-security-requirements)
10. [Non-Functional Requirements](#10-non-functional-requirements)
11. [Testing Strategy](#11-testing-strategy)
12. [Deployment Options](#12-deployment-options)
13. [Success Metrics](#13-success-metrics)
14. [Acceptance Criteria](#14-acceptance-criteria)
15. [Appendices](#15-appendices)

---

## 1. Executive Summary

### What Is NETRA?

NETRA (नेत्र) is an open-source, AI-augmented unified cybersecurity platform that automates vulnerability assessment and penetration testing (VAPT). It integrates 23 security scanning tools into a single orchestrator, applies multi-persona AI consensus analysis, and auto-maps findings to 6 compliance frameworks (ISO 27001, PCI-DSS, NIST CSF, HIPAA, SOC2, CIS Controls).

**Core Value Proposition:**
- **Unified Discovery:** Single platform replaces 10-15 disparate tools (Nmap, Nuclei, Subfinder, SAST, CSPM, etc.)
- **AI-Agnostic Analysis:** Works with Ollama (local), Anthropic Claude (cloud), or no AI—builder's choice
- **Compliance Automation:** Findings auto-mapped to 101+ CWE controls across 6 frameworks
- **Professional Reports:** 13 output formats indistinguishable from Big 4 consulting deliverables
- **100% Open Source:** AGPL-3.0 licensed, no vendor lock-in, no SaaS dependency

### Target Market

- **Solo pentetesters & bug bounty hunters** seeking free, offline tools
- **Security teams at SMBs/mid-market** handling compliance audits
- **DevOps/DevSecOps engineers** integrating security into CI/CD pipelines
- **Academic/research institutions** studying AI-augmented security analysis

### Key Differentiators

| Feature | NETRA | Snyk | Qualys | Nessus | Burp Suite |
|---------|-------|------|--------|--------|-----------|
| Open Source | ✓ | ✗ | ✗ | ✗ | ✗ |
| Offline (Local LLM) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Multi-Tool Orchestration | ✓ | Limited | Limited | Limited | Single |
| AI Consensus (4 Personas) | ✓ | ✗ | ✗ | ✗ | ✗ |
| 6 Compliance Frameworks | ✓ | 1-3 | 3+ | 2-3 | Limited |
| Price | Free | $$ | $$$ | $$$ | $$ |
| Self-Hosted | ✓ | Hybrid | SaaS | On-prem | Both |

---

## 2. Problem Statement

### Current State of Cybersecurity

Security teams today face a fragmented tooling landscape:

**Pain Point 1: Tool Sprawl**
- Typical enterprise uses 12-15 separate tools (Nmap, Burp, Snyk, Qualys, etc.)
- Each tool has its own UI, config, credentials, output format
- No normalized view of findings across all tools
- Maintenance overhead: updates, license renewals, training

**Pain Point 2: Manual Report Generation**
- Security analysts spend 4-8 hours per scan compiling findings
- Copy-pasting results from multiple tools into Excel/Word templates
- Compliance mapping is manual: which CWE → which PCI control? Which NIST CSF category?
- Reports lack narrative context: what chains these findings into attack paths?

**Pain Point 3: False Positive Fatigue**
- Tool X flags SQL injection, Tool Y's SAST finds it too, Tool Z's fuzz-testing says different
- Teams waste time investigating redundant alerts
- Consensus on severity/exploitability is lacking
- Business context (risk vs. remediation cost) is lost

**Pain Point 4: Expensive AI Analysis**
- Commercial platforms charge per scan or per finding for AI analysis
- LLM API costs balloon with scale: $0.01/finding × 10,000 findings = $100+
- Cloud-based LLMs raise data residency/privacy concerns

**Pain Point 5: Compliance Audit Burden**
- Mapping findings to CIS Controls, NIST, PCI-DSS manually is error-prone
- Gap analysis requires spreadsheet gymnastics
- Auditors expect findings grouped by control, not by tool

---

## 3. Target Users & Jobs-to-be-Done

### Persona 1: Solo Pentester / Bug Bounty Hunter

**Profile:**
- Independent contractor or agency pentester
- Handles 5-10 client engagements per year
- Needs fast, reliable tooling without enterprise budget

**Jobs-to-be-Done:**
1. Scan client websites/networks for all classes of vulns in <4 hours
2. Generate a professional report clients are willing to pay for
3. Prove attack chains (e.g., "SQL injection → data exfiltration") to justify findings
4. Run scans offline—no cloud, no API keys, no privacy concerns

**Success Metrics:**
- Scan time < 3 hours for typical target
- Report quality matches Burp Suite Pro output
- Zero data leaves client's network

---

### Persona 2: Security Team Lead (SMB/Mid-Market)

**Profile:**
- 2-5 person security team
- Responsible for quarterly security audits + compliance (PCI, HIPAA, ISO 27001)
- Limited budget for expensive SaaS platforms

**Jobs-to-be-Done:**
1. Run standardized scans across 20+ internal/external assets
2. Consolidate findings in a searchable database with audit trail
3. Auto-generate compliance reports showing control coverage
4. Track remediation status with SLA enforcement (Critical = 24hrs, High = 7 days)
5. Share findings with developers in a JIRA/Linear integration

**Success Metrics:**
- Audit prep time reduced 60% (from 16 hrs to 6 hrs)
- Finding duplication rate < 5%
- Compliance report generation automated, not manual
- Developers can view/filter findings via API

---

### Persona 3: DevOps / DevSecOps Engineer

**Profile:**
- Part of platform engineering / infrastructure team
- Responsible for shifting security left (dev → CI/CD → ops)
- Uses GitHub Actions, GitLab CI, or Jenkins

**Jobs-to-be-Done:**
1. Run security scans on every PR / container push
2. Fail build if Critical/High severity findings detected
3. Generate SARIF output for GitHub Security tab
4. Integrate with existing compliance dashboards
5. Scan IaC (Terraform, CloudFormation) for misconfigs

**Success Metrics:**
- Scan time in CI/CD pipeline < 5 minutes
- SARIF output integrates with GitHub/GitLab without friction
- False positives automatically suppressed after verification
- Developers see findings in IDE (via SARIF) before pushing

---

## 4. Product Vision & Core Principles

### Vision Statement

> NETRA is the open-source unified security brain — automating VAPT scanning, AI analysis, and compliance reporting so security teams can focus on remediation, not tooling.

### Core Principles

#### Principle 1: Open Source First
- **AGPL-3.0 licensed:** Modifications must be shared
- **Community-driven:** Plugins, integrations, personas come from community
- **No vendor lock-in:** Built on standard tech (Python, FastAPI, SQLAlchemy, React)
- **Transparent development:** All issues, PRs, security advisories public

#### Principle 2: AI-Agnostic
- Works with **any LLM:** Ollama (local), Anthropic Claude, OpenAI GPT, Qwen, Llama, Mistral
- Supports **offline operation:** Ollama local inference, zero external calls
- Supports **no AI:** Can run pure scanning mode if LLM unavailable
- Allows **model swapping:** Change models in config, no code changes
- **Future-proof:** When GPT-7 drops, swap it in—no redesign needed

#### Principle 3: API-First
- **Single source of truth:** API backend (FastAPI + SQLAlchemy)
- **Multiple frontends:** CLI, React dashboard, MCP server (Claude Desktop), Jupyter
- **Composable:** All features accessible via REST; CLI/UI are just API clients
- **Scriptable:** Security teams can build custom automation on top

#### Principle 4: Compliance-Native
- **Built-in mappings:** 101+ CWE → PCI/NIST/ISO/HIPAA controls (not bolted-on)
- **Auto-mapping:** Findings get control labels without manual intervention
- **Gap analysis:** Show which controls have no findings (potential blind spots)
- **Audit-ready:** Reports show control status (Met/Not Met/Partial)

#### Principle 5: Professional Quality
- **Enterprise-grade reports:** PDF, Word, Excel—indistinguishable from Deloitte/EY
- **Attack chain narratives:** AI generates context: "Attacker could exploit SQL injection → UNION-based exfil → RCE"
- **Evidence artifacts:** Screenshots, logs, code samples attached to findings
- **Consistent branding:** Client logos, custom sections, executive summaries

#### Principle 6: Transparent Reasoning
- **AI personas logged:** Show why each persona voted (Attacker: Yes, Defender: Yes, Analyst: Maybe, Skeptic: No)
- **Tool attribution:** Every finding shows which scanner discovered it
- **Audit trail:** All changes (finding status, report edits) timestamped and versioned
- **Reproducible:** Checkpoint system allows re-running scans from any phase

---

## 5. Feature Specifications by Phase

### Phase 1: Core Scanning Engine (COMPLETE ✓)

**Objective:** Unified VAPT orchestrator + AI consensus + baseline reports

#### 5.1.1 Tool Integration (23 Scanners)

**Reconnaissance (7 tools)**
- `subfinder` — Passive subdomain enumeration via 40+ sources
- `amass` — Deep subdomain discovery with DNS brute-force
- `assetfinder` — Fast subdomain finder via certificate transparency
- `dnsx` — DNS resolver with filtering
- `httpx` — Live web server detection + metadata grab
- `gau` — Fetch all known URLs from Wayback Machine + URLScan
- `katana` — Web crawler: endpoints, forms, JS files

**Scanning (4 tools)**
- `nmap` — Port scanner + service detection
- `naabu` — Fast port scanning
- `nuclei` — Template-based vuln scanner (9000+ templates)
- `nikto` — Web server scanner for dangerous files/outdated software

**Penetration Testing (6 tools)**
- `dalfox` — XSS vulnerability scanner
- `ffuf` — Fast web fuzzer (directory brute-force)
- `sqlmap` — SQL injection detection and exploitation
- `wpscan` — WordPress vulnerability scanner
- `subzy` — Subdomain takeover detection

**White-box Analysis (6 tools)**
- `semgrep` — SAST code scanning
- `gitleaks` — Secret scanning in source code
- `trivy` — Container/image scanner
- `checkov` — IaC vulnerability scanner
- `prowler` — AWS/Azure/GCP CSPM
- `dependency_scan` — NPM/Python dependency auditing

**AI/LLM Security (1 tool)**
- `llm_security` — OWASP LLM Top 10 assessment

#### 5.1.2 Scan Orchestrator (7-Phase Pipeline)

```
Phase 1: Reconnaissance
  ├─ Passive subdomain enumeration (subfinder, assetfinder, amass)
  ├─ DNS resolution (dnsx)
  └─ Live host discovery (httpx probe)

Phase 2: Discovery
  ├─ Web crawling (katana)
  ├─ Historical URL fetch (gau)
  └─ Endpoint identification

Phase 3: Port Scanning
  ├─ Port discovery (nmap, naabu)
  ├─ Service/version detection
  └─ OS fingerprinting

Phase 4: Vulnerability Scanning
  ├─ Nuclei template-based scan
  ├─ Web vulnerability scan (nikto, dalfox, ffuf, sqlmap)
  ├─ Service-specific scanners (wpscan)
  └─ SSL/TLS assessment

Phase 5: Advanced Testing (Conditional)
  ├─ White-box: SAST (semgrep), secrets (gitleaks)
  ├─ Cloud: CSPM (prowler), IaC scan (checkov)
  ├─ Container: Registry scan (trivy)
  └─ Dependency: Supply chain audit

Phase 6: AI Analysis
  ├─ 4-persona consensus on each finding
  ├─ False positive filtering (Skeptic vote)
  ├─ Attack chain discovery
  ├─ CVSS re-scoring
  └─ Compliance mapping

Phase 7: Reporting
  ├─ Report generation (13 formats)
  ├─ Evidence collection (screenshots, logs)
  └─ Database persistence
```

**Scan Profiles (9 defined, customizable)**

| Profile | Duration | Tools | Use Case |
|---------|----------|-------|----------|
| quick | 30 min | Recon only | Initial assessment |
| standard | 2-3 hrs | Recon + scanning | Typical VAPT |
| deep | 4-6 hrs | All tools | Comprehensive audit |
| api_only | 1 hr | HTTP-focused tools | API testing |
| cloud | 2 hrs | Cloud-specific tools | Cloud infrastructure |
| mobile | 1.5 hrs | Mobile-specific tools | Mobile app security |
| container | 1 hr | Container tools | Supply chain |
| ai_llm | 30 min | AI/LLM assessment | LLM app security |
| custom | Variable | User-selected tools | Tailored scans |

#### 5.1.3 Finding Lifecycle & Deduplication

**Finding States**
- `NEW` — Discovered by scanner, not yet analyzed
- `CONFIRMED` — Analyst verified; requires remediation
- `RESOLVED` — Developer claims fixed; awaiting re-test
- `VERIFIED` — Re-test confirms fix; closed
- `FALSE_POSITIVE` — Marked by analyst; not a real issue
- `WONT_FIX` — Accepted risk; documented business decision

**Deduplication Strategy**
- **Hash-based:** SHA256(severity + title + target + location) groups duplicates
- **Tool aliasing:** Same vuln found by Nuclei + Nikto counted once
- **Cross-phase:** Finding from Phase 4 with matching hash in Phase 6 → increase confidence

**SLA Tracking**
- Critical: 24 hours to remediation
- High: 7 days
- Medium: 30 days
- Low: 90 days

#### 5.1.4 AI Brain: 4-Persona Consensus

**System Architecture**

Each finding analyzed by 4 independent persona prompts (via FastMCP wrapping LLM):

1. **Attacker Persona** — "Can I exploit this for profit/impact?"
   - Votes: Yes / No / Maybe
   - Rationale: Attack vector, exploit availability, impact

2. **Defender Persona** — "How do we mitigate this?"
   - Votes: Easy / Medium / Hard / Unfeasible
   - Rationale: Detection method, remediation cost

3. **Analyst Persona** — "What's the business risk?"
   - Votes: Critical / High / Medium / Low / Info
   - Rationale: Business impact, CVSS justification

4. **Skeptic Persona** — "Is this a false positive?"
   - Votes: Confirmed / Likely / Uncertain / Likely FP / Definite FP
   - Rationale: Detection confidence, false positive likelihood

**Voting Algorithm**
```
CONFIRMED = (Attacker=Yes OR Analyst=Critical) AND Skeptic≠DefiniteFP
UPGRADED = All 3 agree + Skeptic ok → Severity +1 level
DOWNGRADED = Skeptic confident FP + 2 others uncertain → Mark FP
REJECTED = Skeptic=DefiniteFP AND Attacker=No → Filter out
```

**Execution**
- **Parallel:** All 4 personas query simultaneously (asyncio.gather)
- **Local:** Ollama inference on-machine; zero external calls (unless API LLM)
- **Cached:** Identical findings reuse cached persona responses

#### 5.1.5 Initial Report Types (3)

**Report 1: Executive PDF**
- 2-3 page summary for C-suite
- Finding summary table (severity breakdown, remediation timeline)
- Attack flow narrative (1-2 paragraphs)
- Risk score, compliance status
- Tools: ReportLab for PDF generation

**Report 2: Technical DOCX**
- 5-10 pages, detailed for technical audience
- Finding details: title, CVSS, CWE, remediation steps
- Proof-of-concept (PoC) per finding
- Tool-specific findings grouped
- Tools: python-docx for Word generation

**Report 3: Pentest PDF**
- 10-15 pages, standard pentest report
- Executive summary + detailed findings
- Attack chains + impact narrative
- Evidence: screenshots, logs, code samples
- Tools: ReportLab + images

#### 5.1.6 CLI with Rich Interactive Menu

- **Entry:** `netra.py` or `python3 netra.py`
- **Menu-driven:** Rich-formatted interactive prompts
- **Profiles:** Select predefined or custom profile
- **Output:** Table-based progress, finding summaries
- **Commands:**
  - `netra.py -t example.com --profile balanced`
  - `netra.py --resume` (resume last scan)
  - `netra.py --status` (show DB summary)
  - `netra.py --check-deps` (tool status)

#### 5.1.7 MCP Server for Claude Desktop (FastMCP)

**14 Tool Endpoints**
- `/mcp/nuclei` — Template-based scanning
- `/mcp/nmap` — Port scanning
- `/mcp/subfinder` — Subdomain enumeration
- `/mcp/dalfox` — XSS scanning
- `/mcp/sqlmap` — SQL injection testing
- `/mcp/semgrep` — SAST analysis
- `/mcp/prowler` — Cloud security posture
- `/mcp/trivy` — Container scanning
- `/mcp/checkov` — IaC validation
- `/mcp/gitleaks` — Secret detection
- `/mcp/httpx` — HTTP probing
- `/mcp/katana` — Web crawling
- `/mcp/ffuf` — Fuzzing
- `/mcp/analyze_findings` — AI consensus

**6 System Prompts**
1. `attacker_brain.txt` — Exploitation analysis
2. `defender_brain.txt` — Mitigation guidance
3. `analyst_brain.txt` — Risk quantification
4. `skeptic_brain.txt` — False positive filtering
5. `compliance_mapper.txt` — CWE → Control mapping
6. `narrative_generator.txt` — Attack chain storytelling

---

### Phase 2: Full Coverage (COMPLETE ✓)

**Objective:** Add white-box scanning, cloud security, LLM assessment + full compliance mappings + extended reports

#### 5.2.1 New Tool Categories

**Code & Secrets (3 tools)**
- `semgrep` — SAST scanning (Java, Python, Go, JS, Ruby)
- `gitleaks` — Git secret detection (passwords, API keys)
- `dependency_scan` — NPM/Python package auditing

**Cloud Security (2 tools)**
- `prowler` — AWS/Azure/GCP CSPM, compliance scanning
- Risk assessment for cloud misconfigurations

**Container & IaC (2 tools)**
- `trivy` — Container image vulnerabilities
- `checkov` — IaC (Terraform, CloudFormation, K8s) scanner

**LLM Security (1 tool)**
- `llm_security` — OWASP LLM Top 10 assessment (injection, data leakage, etc.)

#### 5.2.2 Compliance Mappings (6 Frameworks, 101+ CWE Links)

**Framework 1: ISO 27001:2022**
- 114 controls mapped to CWE categories
- Example: A.5.1 (Policies) ← CWE-200 (Info Exposure)

**Framework 2: PCI-DSS v4.0**
- 332 requirements across 6 pillars
- Example: Req 6.2.4 (Vulnerable code) ← CWE-79 (XSS), CWE-89 (SQL Injection)

**Framework 3: NIST Cybersecurity Framework 2.0**
- 23 functions mapped to CWE risk areas
- Example: Detect.DE-AE-1 (Event logging) ← CWE-778 (Insufficient logging)

**Framework 4: HIPAA §164.312**
- 18 security rule categories
- Example: §164.312(a)(2)(i) (Access controls) ← CWE-287 (Auth bypass)

**Framework 5: SOC 2 Type II**
- 7 trust service categories
- Example: CC6.1 (Change management) ← CWE-434 (Unrestricted upload)

**Framework 6: CIS Controls v8**
- 18 controls across 5 categories
- Example: IG1.3 (Continuous scanning) ← CWE-269 (Improper access control)

**CWE Mappings (101 total)**
- Database: SQLAlchemy model `ComplianceMapping`
- Structure: CWE → Control → Framework → Finding
- Auto-linking: Finding with CWE-79 auto-linked to all frameworks containing CWE-79

#### 5.2.3 Extended Report Types (10 New)

| Report Type | Pages | Audience | Tools |
|-------------|-------|----------|-------|
| HTML Interactive | 20+ | Technical + executives | React components |
| Excel 9-Sheet | Variable | Analyst review | openpyxl |
| Evidence ZIP | Compressed | Audit trail | stdlib zipfile |
| Compliance Gap | 5-8 | Compliance officer | ReportLab |
| Delta/Diff Report | 5-10 | Change tracking | Custom diff engine |
| API Security Report | 8-12 | API teams | Specialized templates |
| Cloud Security Report | 8-12 | Cloud teams | AWS/Azure/GCP specific |
| Full Comprehensive | 30+ | Auditors | All findings + controls |
| SARIF JSON | Variable | CI/CD systems | SARIF specification |
| Full Report | 50+ | Final deliverable | Everything combined |

**Report Generation Pipeline**
```
Findings + Metadata
  → Formatter (PDF/DOCX/HTML/XLSX/JSON)
  → Asset attachment (screenshots, logs)
  → Control mapping (compliance labels)
  → Narrative injection (AI-generated chains)
  → Output file (signed, timestamped)
```

#### 5.2.4 Alembic Database Migrations

**Migration: 001_initial_schema.py**
- Creates: Users, Targets, Scans, ScanPhases, Findings, Reports

**Migration: 002_phase2_coverage.py**
- Adds: ComplianceMapping, ScanDiff, CloudAsset enums
- New columns: Finding.cwe, Finding.compliance_labels, Finding.ai_consensus

#### 5.2.5 AI Consensus Persistence

- **Storage:** Finding.ai_consensus (JSONB) stores all 4 persona votes + rationales
- **Query:** `SELECT * FROM findings WHERE ai_consensus->'skeptic'->'vote'='confirmed'`
- **Audit trail:** Timestamp + persona version logged

---

### Phase 3: Dashboard + Agent + Launch (COMPLETE ✓)

**Objective:** Web UI, distributed scanning, CI/CD integration, production deployment

#### 5.3.1 React Dashboard (13 Pages, 28 Components)

**Core Pages**

1. **Dashboard (/ )** — Landing page with KPI cards
   - Total findings by severity
   - Scan history (last 7 days)
   - Compliance control coverage %
   - Latest scan status

2. **Scans (/scans)** — Scan list with filters/search
   - Pagination: 20 per page
   - Filters: Status, profile, target, date range
   - Actions: View, resume, delete, export

3. **Scan Detail (/scans/:id)** — Single scan deep-dive
   - Phases: Show progress per phase (enum: pending → running → completed)
   - Timeline: Gantt-style phase execution
   - Stats: Finding breakdown by severity/status
   - Download reports

4. **Findings (/findings)** — Unified finding search
   - Table: 50 rows per page (TanStack Table)
   - Filters: severity, status, CWE, framework, scan
   - Search: Full-text on title + description
   - Bulk actions: Mark confirmed, false positive, resolved

5. **Finding Detail (/findings/:id)** — Single finding with full context
   - Title, CVSS, CWE, severity, status
   - Tool attribution, first/last seen
   - AI personas votes + rationales
   - Compliance control mappings
   - PoC, remediation, evidence

6. **Reports (/reports)** — Report history
   - List: Type, date, scan, status
   - Actions: Download, preview, delete
   - Filters: Type, scan

7. **Compliance (/compliance)** — Compliance dashboard
   - Framework selector (dropdown: ISO 27001, PCI-DSS, etc.)
   - Control status heatmap
   - Gap analysis: Controls with no findings
   - Remediation roadmap

8. **Targets (/targets)** — Asset management
   - CRUD: Create, read, update, delete targets
   - Import: CSV, Excel, API
   - Groups: Organize by business unit

9. **Attack Graph (/attack-graph)** — Force-directed visualization
   - Nodes: Findings as circles, colored by severity
   - Edges: Attack chains (A → B → C → RCE)
   - Physics: D3-Force for layout
   - Hover: Show finding details

10. **Settings (/settings)** — User preferences
    - Account: Name, email, password
    - API tokens: Generate/revoke
    - Notifications: Email, Slack preferences
    - Theme: Dark mode (only)

11. **Users (/users)** — User management (admin only)
    - Table: Users with roles + last login
    - Actions: Create, edit, delete, reset password
    - RBAC matrix: Show permissions per role

12. **Scan Compare (/scans/compare)** — Side-by-side comparison
    - Select 2 scans
    - Findings diff: New, fixed, unchanged
    - Severity trending

13. **Login (/login)** — Authentication
    - Email + password
    - JWT token to localStorage
    - Session expiry handling

**Components (28 total)**

**Charts (4)**
- `SeverityChart` — Pie/bar of findings by severity
- `TimelineChart` — Scan execution over time
- `ComplianceChart` — Control coverage heatmap
- `TrendChart` — Finding trend over 30 days

**Findings (4)**
- `FindingTable` — Paginated, sortable table with TanStack Table
- `FindingCard` — Card view for findings
- `FindingFilter` — Multi-select filter panel
- `FindingBulkActions` — Bulk status change dialog

**Scans (4)**
- `ScanTable` — Scan list with actions
- `ScanCreateDialog` — Form to create new scan
- `ScanPhaseTimeline` — Phase execution timeline
- `ScanProgressBar` — Real-time phase % complete

**Shared (4)**
- `Pagination` — Page navigation
- `SearchBar` — Global search (findings, scans)
- `NotificationBanner` — Toast alerts
- `DataTable` — Reusable table component

**Layout (4)**
- `Header` — Logo, nav, user menu
- `Sidebar` — Nav menu with collapse
- `Footer` — Links, version
- `AuthLayout` — Login page wrapper

**UI (4)**
- `Button` — shadcn-style button
- `Input` — Text input with validation
- `Dialog` — Modal dialog
- `Select` — Dropdown with search

**Hooks (3)**
- `useWebSocket` — Real-time scan updates
- `useKeyboardShortcuts` — Ctrl+K search, etc.
- `useFaviconStatus` — Favicon badge (● = scan running)

#### 5.3.2 RBAC (4 Roles)

**Role Matrix**

| Permission | Admin | Analyst | Viewer | Client |
|-----------|-------|---------|--------|--------|
| Create scan | ✓ | ✓ | ✗ | ✗ |
| View findings | ✓ | ✓ | ✓ | Limited |
| Mark confirmed | ✓ | ✓ | ✗ | ✗ |
| Generate report | ✓ | ✓ | ✗ | ✗ |
| Edit users | ✓ | ✗ | ✗ | ✗ |
| Delete findings | ✓ | ✗ | ✗ | ✗ |
| View audit logs | ✓ | ✓ | ✗ | ✗ |

#### 5.3.3 WebSocket Real-Time Updates

**Endpoint:** `WS /ws/scans/{scan_id}`

**Messages**
```json
{"type": "phase_start", "phase": "reconnaissance", "timestamp": "2026-03-29T10:00:00Z"}
{"type": "finding_discovered", "finding_id": "uuid", "severity": "high", "count": 5}
{"type": "phase_complete", "phase": "reconnaissance", "duration_seconds": 120}
{"type": "scan_complete", "scan_id": "uuid", "total_findings": 42}
```

#### 5.3.4 Attack Graph Visualization

- **Library:** D3.js Force simulation
- **Nodes:** Findings, color-coded by severity
  - Red = Critical
  - Orange = High
  - Yellow = Medium
  - Blue = Low
  - Gray = Info
- **Edges:** Attack chains with arrows
  - Labeled: "SQL Injection → Auth Bypass → RCE"
- **Physics:** Spring forces + collision detection
- **Interactivity:**
  - Drag nodes
  - Hover for details
  - Click to navigate to finding detail

#### 5.3.5 CI/CD Integration (3 GitHub Actions Workflows)

**Workflow 1: On-Push Security Scan**
```yaml
# .github/workflows/security-scan.yml
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run NETRA scan
        run: docker run netra:latest -t . --profile api_only --output-sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: sarif.json
      - name: Fail on Critical
        run: |
          CRITICAL=$(jq '.runs[0].results[] | select(.level=="error") | length' sarif.json)
          if [ "$CRITICAL" -gt 0 ]; then exit 1; fi
```

**Workflow 2: Scheduled Nightly Scan**
```yaml
# .github/workflows/scheduled-scan.yml
on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM UTC daily
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run NETRA deep scan
        run: docker run netra:latest -t example.com --profile deep --output-email
```

**Workflow 3: PR Comment with Findings**
```yaml
# .github/workflows/pr-findings.yml
on: [pull_request]
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - name: Scan & comment
        run: |
          FINDINGS=$(netra -t . --quick --json | jq '.findings | length')
          gh pr comment -b "🔍 Found $FINDINGS security findings"
```

#### 5.3.6 Docker Multi-Stage Deployment

**Services**

1. **netra-api** (FastAPI)
   - Port 8000, healthcheck /api/v1/health
   - Env: DATABASE_URL, OLLAMA_HOST, REDIS_URL

2. **netra-worker** (Celery)
   - Workers: 4 (configurable)
   - Queues: scan, report, compliance

3. **netra-frontend** (React)
   - Port 3000, Nginx reverse proxy
   - Built artifacts only (no Node runtime)

4. **postgres** (Database)
   - Port 5432, volume: /var/lib/postgresql/data
   - Init script: alembic upgrade head

5. **redis** (Cache + Message Broker)
   - Port 6379, no persistence (in-memory)

6. **ollama** (LLM Inference)
   - Port 11434, models in /root/.ollama/models

**Docker Compose File** (docker-compose.yml, 95 lines)
```yaml
version: '3.9'
services:
  netra-api:
    build:
      context: .
      dockerfile: Dockerfile
      target: api
    ports:
      - "8000:8000"
    depends_on:
      - postgres
      - redis
      - ollama
    environment:
      DATABASE_URL: postgresql://netra:password@postgres:5432/netra_db
      REDIS_URL: redis://redis:6379/0
      OLLAMA_HOST: http://ollama:11434
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
      interval: 30s
      timeout: 10s

  # ... worker, frontend, postgres, redis, ollama services ...
```

#### 5.3.7 Documentation Site (MkDocs Material)

- **Location:** `docs/` directory
- **Sections:**
  - Getting started (install, quickstart)
  - User guide (scanning, reports, compliance)
  - API docs (OpenAPI + examples)
  - Deployment (Docker, Kubernetes)
  - Contributing (dev setup, code standards)
  - Troubleshooting (FAQs, known issues)

#### 5.3.8 CLI Enhancements

**New Flags**
- `--output-sarif` — Export findings as SARIF JSON
- `--fail-on [critical|high|medium]` — Exit code 1 if findings at severity
- `--output-json` — JSON export for scripting
- `--quiet` — Suppress progress output

**Example Commands**
```bash
netra -t example.com --profile deep --output-sarif > findings.sarif
netra -t . --profile api_only --fail-on critical  # In CI/CD
netra --resume --output-json | jq '.findings[] | select(.severity=="critical")'
```

---

### Phase 4: v1.1+ Roadmap (PLANNED)

#### 5.4.1 Distributed Scanning (Celery)

**Current:** Scans run on single machine
**Future:** Wire Celery tasks to orchestrator

- **Phase tasks:** Each phase as async Celery task
- **Worker pool:** 4+ workers for parallel execution
- **Task chaining:** Phase 1 → Phase 2 → ... → Phase 7 (automatic)
- **Result tracking:** Flower dashboard for task monitoring

**Tasks**
```python
@celery.task(queue='scan')
async def run_reconnaissance(scan_id: UUID) -> dict: ...

@celery.task(queue='scan')
async def run_port_scan(scan_id: UUID) -> dict: ...

@celery.signature([
    run_reconnaissance.s(scan_id),
    run_port_scan.s(),
    run_vuln_scan.s(),
    # ...
]).apply_async()
```

#### 5.4.2 Notification System (Slack + Email)

**Current:** Stub in `src/netra/notifications/`
**Future:** Full implementation

**Slack Integration**
- Finding discovered → Slack channel alert
- Scan complete → Report link
- SLA breach → Escalation message
- Custom templates per organization

**Email Integration**
- Report delivery (PDF attachment)
- Finding digest (daily/weekly)
- SLA reminders
- Compliance audit ready

#### 5.4.3 Authentication Enhancements

**Current:** JWT with hardcoded secret
**Future:**

- **Refresh token rotation** — Automatic token refresh with rotation
- **Token blacklist** — Revoke tokens immediately on logout
- **OAuth2/OIDC** — Integration with enterprise SSO (Okta, Azure AD)
- **MFA** — TOTP (Time-based One-Time Password)
- **Session management** — Concurrent session limits

#### 5.4.4 Security Hardening

- **SSRF protection** — Validate all scan targets (not internal IPs)
- **Rate limiting** — 100 req/min per API key
- **WAF rules** — Slow HTTP, large payloads, injection patterns
- **Secrets rotation** — Auto-rotate API keys, DB credentials

#### 5.4.5 Performance Optimization

- **Async personas** — Concurrent AI consensus (asyncio.gather)
- **Finding caching** — Redis cache for identical scans
- **Pagination optimization** — Keyset pagination for large result sets
- **Database indexing** — Composite indexes on (scan_id, severity), (target_id, status)

#### 5.4.6 Advanced Features

**Global Search**
- Cross-finding, cross-scan search in dashboard
- Elasticsearch integration for full-text search

**Scan Scheduling**
- Cron-based recurring scans
- UI calendar picker
- Auto-remediation checks

**Plugin System**
- Community tools: plugins/custom_scanner.py
- Custom report types
- Custom compliance frameworks

**Integrations**
- **DefectDojo:** Sync findings bidirectionally
- **Jira:** Auto-create tickets from findings
- **Slack:** Real-time alerts + approvals
- **Datadog:** Metrics + dashboards
- **Splunk:** Log aggregation

---

## 6. Technical Architecture

### 6.1 System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER INTERFACES                             │
├──────────┬──────────────┬───────────────────┬─────────────────────┤
│   CLI    │  React       │     MCP Server    │  REST API Clients   │
│ (Rich)   │  Dashboard   │  (Claude Desktop) │  (Scripts, IFTTT)   │
└──────────┴──────────────┴───────────────────┴─────────────────────┘
                                  ▲
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
            HTTP (8000)              WebSocket
                    │                           │
        ┌───────────▼─────────────────────────┬┴──┐
        │                                     │   │
        │      FastAPI Backend (/api/v1)      │WS │
        │  ┌─────────────────────────────────┐│Route
        │  │ Routes:                         ││
        │  │ • /auth/login, /register       ││
        │  │ • /scans (CRUD)                ││
        │  │ • /findings (CRUD + bulk)      ││
        │  │ • /reports (generate)          ││
        │  │ • /compliance (framework)      ││
        │  │ • /targets (CRUD)              ││
        │  │ • /agent/chat (AI)             ││
        │  └─────────────────────────────────┘│
        │                                     │
        │  Middleware:                        │
        │  • JWT auth + RBAC                 │
        │  • Rate limiting (slowapi)         │
        │  • CORS                            │
        │  • Request logging (structlog)     │
        └─────────────┬──────────────────────┘
                      │
        ┌─────────────┴──────────────────────────────────┐
        │                                                 │
        ▼                                                 ▼
    ┌────────────────┐                          ┌────────────────┐
    │  Scanner Pool  │                          │  AI Brain      │
    │ (23 tools)     │                          │ (4 personas)   │
    │ ┌──────────────┤                          │ ┌──────────────┤
    │ │nmap, nuclei, │                          │ │Attacker      │
    │ │subfinder,    │  ◄──────────┬────────►  │ │Defender      │
    │ │semgrep, +18  │  Findings   │           │ │Analyst       │
    │ │more...       │             │           │ │Skeptic       │
    │ └──────────────┘             │           │ └──────────────┘
    │                              │           │
    │  Orchestrator:               │           │  Ollama (Local) or
    │  7-phase pipeline            │           │  Anthropic API
    │  (recon→discovery→ports→...  │           │
    │   vuln→advanced→ai→report)   │           │  Cached responses:
    │                              │           │  Redis
    │                              │           │
    └────────────────┬─────────────┘           └────────────┬─────┘
                     │                                      │
                     └──────────────────┬───────────────────┘
                                        │
                                        ▼
                        ┌────────────────────────────┐
                        │  Report Generation Engine  │
                        │ (13 formats)               │
                        │ ┌────────────────────────┐ │
                        │ │ PDF (Executive, Tech,  │ │
                        │ │  Pentest)              │ │
                        │ │ DOCX (Technical)       │ │
                        │ │ HTML (Interactive)     │ │
                        │ │ XLSX (9 sheets)        │ │
                        │ │ ZIP (Evidence)         │ │
                        │ │ SARIF (CI/CD)          │ │
                        │ │ + 7 more...            │ │
                        │ └────────────────────────┘ │
                        └────────────┬────────────────┘
                                     │
                ┌────────────────────┼────────────────────┐
                ▼                    ▼                    ▼
        ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
        │  PostgreSQL    │  │     Redis      │  │  File Storage  │
        │  Database      │  │   (Cache +     │  │   /scans/      │
        │                │  │    Queue)      │  │  (reports,     │
        │ • Users        │  │                │  │   screenshots) │
        │ • Targets      │  │ Tasks:         │  │                │
        │ • Scans        │  │ • Scan jobs    │  │ Asset pyramid: │
        │ • Findings     │  │ • Persona      │  │ • Raw outputs  │
        │ • Reports      │  │   responses    │  │ • Evidence     │
        │ • Compliance   │  │ • Notifications  │  │ • Exports      │
        │   Mappings     │  │                │  │                │
        │ • Audit logs   │  └────────────────┘  └────────────────┘
        └────────────────┘
```

### 6.2 Data Model (Entity Relationships)

```sql
-- Core entities
TABLE users
  id UUID PRIMARY KEY
  email VARCHAR(255) UNIQUE
  hashed_password VARCHAR(255)
  full_name VARCHAR(255)
  role ENUM(admin, analyst, viewer, client)
  is_active BOOLEAN
  created_at TIMESTAMP

TABLE targets
  id UUID PRIMARY KEY
  name VARCHAR(255)
  url VARCHAR(2048)
  type ENUM(domain, ip, cidr, mobile_app, api)
  scope TEXT  -- JSON: in-scope paths/methods
  notes TEXT
  created_by UUID FK users.id
  created_at TIMESTAMP

TABLE scans
  id UUID PRIMARY KEY
  name VARCHAR(255)
  target_id UUID FK targets.id
  profile ENUM(quick, standard, deep, api_only, cloud, mobile, container, ai_llm, custom)
  status ENUM(pending, running, paused, completed, failed, cancelled)
  started_at TIMESTAMP
  completed_at TIMESTAMP
  config JSONB  -- {tools: [...], flags: {...}}
  error_message TEXT
  checkpoint_data JSONB  -- Phase state for resume
  created_at TIMESTAMP

TABLE scan_phases
  id UUID PRIMARY KEY
  scan_id UUID FK scans.id
  phase_name ENUM(reconnaissance, discovery, port_scan, vuln_scan, advanced, ai_analysis, reporting)
  status ENUM(pending, running, completed, failed)
  started_at TIMESTAMP
  completed_at TIMESTAMP
  findings_count INT
  errors TEXT

TABLE findings
  id UUID PRIMARY KEY
  scan_id UUID FK scans.id
  title VARCHAR(255)
  severity ENUM(critical, high, medium, low, info)
  cvss_score DECIMAL(3,1)
  cwe INT  -- CWE ID (e.g., 79 for XSS)
  description TEXT
  remediation TEXT
  proof_of_concept TEXT
  tool_name VARCHAR(100)  -- Which scanner found this
  status ENUM(new, confirmed, resolved, verified, false_positive, wont_fix)
  first_seen TIMESTAMP
  last_seen TIMESTAMP
  hash_signature VARCHAR(64)  -- SHA256 for deduplication
  ai_consensus JSONB  -- {attacker: {vote, rationale}, defender: {...}, ...}
  compliance_labels JSONB  -- {iso27001: [A.5.1, A.5.2], pci_dss: [6.2.4], ...}
  created_at TIMESTAMP

TABLE compliance_mappings
  id UUID PRIMARY KEY
  cwe INT  -- CWE ID
  framework VARCHAR(50)  -- iso27001, pci_dss, nist_csf, hipaa, soc2, cis_controls
  control_id VARCHAR(50)  -- A.5.1, 6.2.4, PR.AC-1, etc.
  control_description TEXT
  created_at TIMESTAMP

TABLE reports
  id UUID PRIMARY KEY
  scan_id UUID FK scans.id
  report_type ENUM(executive_pdf, technical_docx, pentest_pdf, html, excel, ...)
  status ENUM(generating, ready, failed)
  file_path VARCHAR(2048)
  file_size_bytes INT
  generated_at TIMESTAMP

TABLE audit_logs
  id UUID PRIMARY KEY
  user_id UUID FK users.id
  action VARCHAR(255)  -- created_scan, marked_confirmed, generated_report
  resource_type VARCHAR(50)  -- Scan, Finding, Report
  resource_id UUID
  changes JSONB  -- What changed
  created_at TIMESTAMP

TABLE credentials
  id UUID PRIMARY KEY
  user_id UUID FK users.id
  api_key VARCHAR(255)
  name VARCHAR(100)
  created_at TIMESTAMP
  last_used_at TIMESTAMP
```

**Key Relationships**
- User → Targets (1:M) — One user, many targets
- Target → Scans (1:M) — One target, many scans
- Scan → ScanPhases (1:M) — One scan, 7 phases
- Scan → Findings (1:M) — One scan, many findings
- Scan → Reports (1:M) — One scan, 13 max reports
- Finding → ComplianceMapping (M:M via compliance_labels) — One finding, multiple controls
- User → AuditLogs (1:M) — One user, audit trail

**Indexes**
- `scans(target_id, status)` — Filter by target + status
- `scans(created_at DESC)` — List recent scans
- `findings(scan_id, severity)` — Severity breakdown per scan
- `findings(hash_signature)` — Deduplication lookup
- `findings(first_seen, last_seen)` — Timeline queries
- `audit_logs(user_id, created_at)` — User activity audit

### 6.3 API Design (OpenAPI Specification)

#### Authentication Endpoints

```yaml
POST /api/v1/auth/login
  Request:
    email: string
    password: string
  Response:
    access_token: string (JWT)
    refresh_token: string
    expires_in: integer (seconds)

POST /api/v1/auth/register
  Request:
    email: string
    password: string (min 12 chars)
    full_name: string
  Response:
    user_id: UUID
    email: string
    status: 201 Created

POST /api/v1/auth/refresh
  Request:
    refresh_token: string
  Response:
    access_token: string (new)
    expires_in: integer

POST /api/v1/auth/logout
  Headers:
    Authorization: Bearer {access_token}
  Response:
    status: 204 No Content
```

#### Scan Endpoints

```yaml
POST /api/v1/scans
  Create and start new scan
  Request:
    target_id: UUID
    name: string
    profile: string (quick, standard, deep, ...)
    config: object (optional, tool-specific flags)
  Response:
    scan_id: UUID
    status: pending
    created_at: ISO8601

GET /api/v1/scans
  List scans with pagination
  Query:
    page: int = 1
    per_page: int = 20
    status: string? (filter)
    profile: string? (filter)
  Response:
    data: [ScanListResponse]
    pagination: {page, per_page, total}

GET /api/v1/scans/{scan_id}
  Get scan details
  Response:
    scan_id: UUID
    name: string
    target_id: UUID
    status: string
    phases: [ScanPhaseResponse]
    findings_summary: {critical: 5, high: 12, ...}
    created_at: ISO8601

PATCH /api/v1/scans/{scan_id}
  Update scan (pause/resume)
  Request:
    action: string (pause, resume, cancel)
  Response:
    scan_id: UUID
    status: string

DELETE /api/v1/scans/{scan_id}
  Delete scan and findings
  Response:
    status: 204 No Content
```

#### Finding Endpoints

```yaml
GET /api/v1/findings
  List findings with filters
  Query:
    scan_id: UUID?
    severity: string? (critical, high, ...)
    status: string? (confirmed, false_positive, ...)
    page: int = 1
    per_page: int = 20
  Response:
    data: [FindingResponse]
    pagination: {...}

GET /api/v1/findings/{finding_id}
  Get finding details with AI consensus
  Response:
    finding_id: UUID
    title: string
    severity: string
    cvss_score: float
    cwe: integer
    ai_consensus: {attacker: {...}, defender: {...}, analyst: {...}, skeptic: {...}}
    compliance_labels: {iso27001: [A.5.1], pci_dss: [6.2.4]}
    PoC: string

PATCH /api/v1/findings/{finding_id}
  Update finding status
  Request:
    status: string (confirmed, false_positive, resolved, ...)
  Response:
    finding_id: UUID
    status: string

POST /api/v1/findings/bulk-action
  Bulk update findings
  Request:
    finding_ids: [UUID]
    action: string (mark_confirmed, mark_fp, resolve)
  Response:
    updated_count: integer
```

#### Report Endpoints

```yaml
POST /api/v1/reports/generate
  Initiate report generation
  Request:
    scan_id: UUID
    report_type: string (executive_pdf, technical_docx, ...)
    config: object? (custom sections, logos)
  Response:
    report_id: UUID
    status: generating

GET /api/v1/reports/{report_id}
  Get report status and metadata
  Response:
    report_id: UUID
    scan_id: UUID
    type: string
    status: string (generating, ready, failed)
    file_path: string
    file_size_bytes: integer
    generated_at: ISO8601

GET /api/v1/reports/{report_id}/download
  Download report file
  Response:
    Content-Type: application/pdf | application/vnd.openxmlformats-officedocument.wordprocessingml.document | ...
    Content-Disposition: attachment; filename=...
    [file binary]
```

#### Compliance Endpoints

```yaml
GET /api/v1/compliance/frameworks
  List available frameworks
  Response:
    frameworks: [
      {id: iso27001, name: ISO/IEC 27001:2022, controls: 114},
      {id: pci_dss, name: PCI-DSS v4.0, controls: 332},
      ...
    ]

GET /api/v1/compliance/frameworks/{framework_id}/controls
  List controls in framework
  Query:
    scan_id: UUID? (to show coverage)
  Response:
    controls: [
      {id: A.5.1, name: Policies, status: met, findings: [UUID, UUID]}
    ]

POST /api/v1/compliance/gap-analysis
  Generate compliance gap report
  Request:
    scan_id: UUID
    framework: string (iso27001, pci_dss, ...)
  Response:
    framework: string
    controls_met: integer
    controls_not_met: integer
    gap_analysis: [
      {control: A.5.2, status: not_met, findings: [], remediation_time_est: hours}
    ]
```

#### Agent Endpoint (AI)

```yaml
POST /api/v1/agent/chat
  Chat with AI brain about findings
  Request:
    scan_id: UUID
    message: string (e.g., "What's the attack chain for critical findings?")
  Response:
    response: string (AI-generated narrative)
    reasoning: {tool_calls: [...], model_used: string}
```

#### Target Endpoints

```yaml
POST /api/v1/targets
  Create target
  Request:
    name: string
    url: string (domain/IP/CIDR)
    type: string (domain, ip, cidr, mobile_app, api)
    scope: object? {in_scope: [paths], out_of_scope: [paths]}
  Response:
    target_id: UUID
    created_at: ISO8601

GET /api/v1/targets
  List targets with pagination
  Response:
    data: [TargetResponse]
    pagination: {...}

DELETE /api/v1/targets/{target_id}
  Delete target (cascades to scans? or prevent if scans exist?)
  Response:
    status: 204 No Content
```

### 6.4 Authentication & Authorization Flow

```
User Login (Email + Password)
    ▼
POST /api/v1/auth/login
    ▼
Verify credentials (bcrypt compare)
    ▼
Generate JWT token (HS256, exp=15min) + Refresh token (exp=7d)
    ▼
Response: {access_token, refresh_token, expires_in}
    ▼
Client stores in localStorage
    ▼
All subsequent requests:
  Authorization: Bearer {access_token}
    ▼
Middleware validates JWT signature + expiry
    ▼
If expired: POST /api/v1/auth/refresh with refresh_token
    ▼
New access_token issued
    ▼
Check user.role in JWT claims
    ▼
RBAC: Allow/deny based on route + role
```

**JWT Payload**
```json
{
  "sub": "user_id_uuid",
  "email": "user@example.com",
  "role": "analyst",
  "exp": 1711700400,
  "iat": 1711700100
}
```

**RBAC Matrix (In Code)**
```python
PERMISSIONS = {
    "admin": ["create_scan", "view_all_findings", "delete_scan", "manage_users"],
    "analyst": ["create_scan", "view_all_findings", "mark_confirmed"],
    "viewer": ["view_findings"],
    "client": ["view_own_findings"]  # Limited to their target
}
```

### 6.5 Scan Pipeline Flow

```
ScanOrchestrator.execute(scan_id)
    ▼
Phase 1: Reconnaissance (20 min)
  ├─ subfinder, amass, assetfinder
  ├─ dnsx resolution
  ├─ httpx live detection
  └─ Save subdomains to DB
    ▼
Phase 2: Discovery (15 min)
  ├─ katana web crawl
  ├─ gau historical URLs
  ├─ Deduplicate URLs
  └─ Save endpoints to DB
    ▼
Phase 3: Port Scanning (30 min)
  ├─ nmap full scan
  ├─ naabu fast scan (complement)
  ├─ Parse results
  └─ Save open ports to DB
    ▼
Phase 4: Vulnerability Scanning (60 min)
  ├─ nuclei run
  ├─ nikto
  ├─ dalfox
  ├─ ffuf
  ├─ sqlmap
  ├─ wpscan
  ├─ Parse findings
  ├─ Deduplication (SHA256 hash)
  └─ Save findings to DB
    ▼
Phase 5: Advanced Testing (30 min, conditional)
  ├─ semgrep (if source code accessible)
  ├─ gitleaks (if git repo found)
  ├─ prowler (if cloud detected)
  ├─ trivy (if docker images found)
  ├─ checkov (if IaC detected)
  └─ llm_security (if LLM app detected)
    ▼
Phase 6: AI Analysis (15 min per finding)
  ├─ For each finding:
  │  ├─ Query 4 personas (parallel via asyncio.gather)
  │  ├─ Attacker: exploitable?
  │  ├─ Defender: mitigatable?
  │  ├─ Analyst: business impact?
  │  ├─ Skeptic: false positive?
  │  └─ Voting algorithm → Validate/Reject/Downgrade
  │
  ├─ Compliance mapping:
  │  ├─ Finding.cwe → ComplianceMapping
  │  ├─ Aggregate per framework
  │  └─ Label finding with controls
  │
  ├─ Attack chain discovery:
  │  ├─ Build graph: SQL injection → Auth bypass → RCE
  │  └─ Generate narrative per chain
  │
  └─ Save all to DB (ai_consensus, compliance_labels)
    ▼
Phase 7: Reporting (10 min)
  ├─ Request report type (Executive PDF, Technical DOCX, etc.)
  ├─ Format findings per report type
  ├─ Inject compliance control tables
  ├─ Embed evidence (screenshots, logs)
  ├─ Generate file (PDF/DOCX/XLSX/etc.)
  └─ Save to /scans/{scan_id}/reports/
    ▼
Scan Complete
  ├─ Update scan status = completed
  ├─ Set completed_at timestamp
  ├─ Notify user (Slack/Email)
  └─ Trigger webhooks
```

**Checkpoint & Resume**
- After each phase, save state to `scan.checkpoint_data` (JSONB)
- `checkpoint_data = {phase: "port_scanning", progress: 0.65, last_tool: "nmap"}`
- Resume command loads checkpoint, skips to phase, reuses existing findings

### 6.6 AI Consensus Algorithm

```
Finding.title = "SQL Injection in login.php"
Finding.severity = "high"  (provisional)
    ▼
CONSENSUS_VOTE():
    ▼
    ┌─────────────────────────────────────────┐
    │ Attacker Persona Query:                 │
    │ "Can this SQL injection be exploited?"  │
    │                                         │
    │ Response: "Yes, UNION-based extraction  │
    │  of user credentials possible. Impact:  │
    │  Data breach. Effort: low. Likelihood:  │
    │  90%"                                   │
    │                                         │
    │ Vote: YES                               │
    └─────────────────────────────────────────┘
                      ║
    ┌─────────────────────────────────────────┐
    │ Defender Persona Query:                 │
    │ "How do we remediate this?"             │
    │                                         │
    │ Response: "Use parameterized queries,   │
    │  input validation, WAF rules.           │
    │  Time: 2 hours. Cost: $0 (dev time)"    │
    │                                         │
    │ Vote: EASY                              │
    └─────────────────────────────────────────┘
                      ║
    ┌─────────────────────────────────────────┐
    │ Analyst Persona Query:                  │
    │ "What's the business risk?"             │
    │                                         │
    │ Response: "Customer PII at risk, HIPAA  │
    │  violation potential, reputational      │
    │  damage. Severity: CRITICAL"            │
    │                                         │
    │ Vote: CRITICAL                          │
    └─────────────────────────────────────────┘
                      ║
    ┌─────────────────────────────────────────┐
    │ Skeptic Persona Query:                  │
    │ "Is this a false positive?"             │
    │                                         │
    │ Response: "No. SQL injection confirmed  │
    │  via error-based testing. Not a false   │
    │  positive. Confidence: 95%"             │
    │                                         │
    │ Vote: CONFIRMED                         │
    └─────────────────────────────────────────┘
                      ║
    ▼
VOTING_ALGORITHM():
  if (Attacker=YES OR Analyst=CRITICAL) AND Skeptic≠DEFINITE_FP:
    Finding.validated = True
    Finding.severity = max(Analyst.severity, current)  # CRITICAL
    Finding.status = CONFIRMED

  if Skeptic.confidence_fp > 0.8:
    Finding.status = FALSE_POSITIVE
    Finding.reason = Skeptic.explanation

  Store all votes in Finding.ai_consensus = {
    attacker: {vote: "yes", rationale: "...", model: "qwen:14b", timestamp: ...},
    defender: {vote: "easy", rationale: "...", ...},
    analyst: {vote: "critical", rationale: "...", ...},
    skeptic: {vote: "confirmed", rationale: "...", ...}
  }
    ▼
Result:
  Finding.status = CONFIRMED
  Finding.severity = CRITICAL (upgraded from HIGH)
  Finding.ai_consensus = {...all 4 votes...}
  Finding.compliance_labels = {
    pci_dss: ["6.2.4"],
    cwe_id: 89,
    nist_csf: ["DE.CM-1"]
  }
```

### 6.7 Report Generation Pipeline

```
ReportGenerator.generate(scan_id, report_type="executive_pdf")
    ▼
Fetch scan + findings + compliance mappings from DB
    ▼
Formatter Branch (per type):

┌─ Executive PDF ─────────────────┐
│ • ReportLab PDF writer          │
│ • Template: 2-3 pages           │
│ • Summary + finding breakdown   │
│ • Risk score, SLA tracking      │
│ • Recommendations (4-6 items)   │
└─────────────────────────────────┘

┌─ Technical DOCX ────────────────┐
│ • python-docx                   │
│ • Template: 5-10 pages          │
│ • Each finding: detailed section │
│ • PoC, remediation, tool source │
│ • Code samples, screenshots      │
└─────────────────────────────────┘

┌─ HTML Interactive ──────────────┐
│ • React components rendered to  │
│ • Static HTML + embedded CSS    │
│ • Searchable table of findings  │
│ • Attack graph (D3.js)          │
│ • Client-side filtering         │
└─────────────────────────────────┘

┌─ Excel 9-Sheet ─────────────────┐
│ • openpyxl                      │
│ • Sheet 1: Summary              │
│ • Sheet 2: All findings         │
│ • Sheet 3: Severity breakdown   │
│ • Sheet 4: Timeline             │
│ • Sheet 5: Compliance controls  │
│ • Sheet 6: CWE mapping          │
│ • Sheet 7: Tool output (raw)    │
│ • Sheet 8: SLA tracking         │
│ • Sheet 9: Remediation roadmap  │
└─────────────────────────────────┘

┌─ SARIF JSON ────────────────────┐
│ • SARIF 2.1.0 spec              │
│ • GitHub/GitLab compatible      │
│ • Tool run: {tool, version}     │
│ • Results: {message, locations} │
│ • Taxonomies: CWE, OWASP        │
└─────────────────────────────────┘

[... 7 more report types ...]
    ▼
Asset Collection:
  ├─ Screenshots (if taken)
  ├─ Raw tool output (JSON/XML)
  ├─ Logs (per-phase)
  └─ Evidence files
    ▼
Compliance Injection:
  ├─ For each finding: find mapped controls
  ├─ Generate control status table
  ├─ Insert gap analysis section
  └─ Add control remediation recommendations
    ▼
Narrative Injection:
  ├─ AI generates attack chain stories
  ├─ Example: "SQL injection → Auth bypass → RCE"
  ├─ Insert into "Executive Summary" section
  └─ Quote AI persona rationales
    ▼
Output:
  ├─ File written to /scans/{scan_id}/reports/
  ├─ Filename: {scan_id}_{report_type}_{timestamp}.{ext}
  ├─ Update DB: Report.status = ready, Report.file_path = path
  └─ Return download URL
```

---

## 7. API Specification

### 7.1 Request/Response Examples

#### Create Scan
```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Q1 2026 Security Assessment",
    "profile": "standard",
    "config": {
      "tools": ["nuclei", "nmap", "semgrep"],
      "timeout_minutes": 120
    }
  }'
```

**Response (201 Created)**
```json
{
  "scan_id": "650e8400-e29b-41d4-a716-446655440111",
  "name": "Q1 2026 Security Assessment",
  "target_id": "550e8400-e29b-41d4-a716-446655440000",
  "profile": "standard",
  "status": "pending",
  "created_at": "2026-03-29T10:00:00Z",
  "phases": []
}
```

#### List Findings with Filters
```bash
curl -X GET "http://localhost:8000/api/v1/findings?scan_id=650e8400-e29b-41d4-a716-446655440111&severity=critical,high&page=1&per_page=20" \
  -H "Authorization: Bearer {token}"
```

**Response (200 OK)**
```json
{
  "data": [
    {
      "finding_id": "750e8400-e29b-41d4-a716-446655440222",
      "scan_id": "650e8400-e29b-41d4-a716-446655440111",
      "title": "SQL Injection in /api/login",
      "severity": "critical",
      "cvss_score": 9.8,
      "cwe": 89,
      "status": "confirmed",
      "tool_name": "sqlmap",
      "ai_consensus": {
        "attacker": {
          "vote": "yes",
          "rationale": "Union-based extraction of user credentials possible"
        },
        "defender": {
          "vote": "easy",
          "rationale": "Use parameterized queries"
        },
        "analyst": {
          "vote": "critical",
          "rationale": "Customer PII at risk"
        },
        "skeptic": {
          "vote": "confirmed",
          "confidence_fp": 0.05
        }
      },
      "compliance_labels": {
        "pci_dss": ["6.2.4", "6.5.1"],
        "cwe_id": 89,
        "iso27001": ["A.14.2.1"]
      },
      "created_at": "2026-03-29T10:15:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 47,
    "pages": 3
  }
}
```

#### Generate Report
```bash
curl -X POST http://localhost:8000/api/v1/reports/generate \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "650e8400-e29b-41d4-a716-446655440111",
    "report_type": "executive_pdf",
    "config": {
      "client_name": "ACME Corp",
      "client_logo_url": "https://acme.com/logo.png"
    }
  }'
```

**Response (202 Accepted)**
```json
{
  "report_id": "850e8400-e29b-41d4-a716-446655440333",
  "scan_id": "650e8400-e29b-41d4-a716-446655440111",
  "report_type": "executive_pdf",
  "status": "generating",
  "created_at": "2026-03-29T10:20:00Z"
}
```

### 7.2 Error Responses

```json
{
  "detail": "Not found",
  "status_code": 404
}
```

```json
{
  "detail": "Insufficient permissions for this action",
  "status_code": 403
}
```

```json
{
  "detail": "Invalid credentials",
  "status_code": 401
}
```

---

## 8. Database Schema

### 8.1 DDL (SQLAlchemy Models)

**Note:** Full schema defined in `src/netra/db/models/`

```python
# users.py
class User(Base):
    __tablename__ = "users"
    id: UUID = Column(primary_key=True, default=uuid4)
    email: str = Column(String(255), unique=True, nullable=False)
    hashed_password: str = Column(String(255), nullable=False)
    full_name: str = Column(String(255))
    role: str = Column(String(20), default="viewer")  # admin, analyst, viewer, client
    is_active: bool = Column(Boolean, default=True)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow)

# targets.py
class Target(Base):
    __tablename__ = "targets"
    id: UUID = Column(primary_key=True, default=uuid4)
    name: str = Column(String(255), nullable=False)
    url: str = Column(String(2048), nullable=False)
    type: str = Column(String(50))  # domain, ip, cidr, mobile_app, api
    scope: dict = Column(JSONB, default=dict)
    notes: str = Column(Text)
    created_by: UUID = Column(ForeignKey("users.id"))
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow)

# scan.py
class Scan(Base):
    __tablename__ = "scans"
    id: UUID = Column(primary_key=True, default=uuid4)
    name: str = Column(String(255), nullable=False)
    target_id: UUID = Column(ForeignKey("targets.id"), nullable=False)
    profile: str = Column(String(20))  # quick, standard, deep, ...
    status: str = Column(String(20), default="pending")  # pending, running, completed, failed
    started_at: datetime = Column(DateTime(timezone=True))
    completed_at: datetime = Column(DateTime(timezone=True))
    config: dict = Column(JSONB, default=dict)
    error_message: str = Column(Text)
    checkpoint_data: dict = Column(JSONB, default=dict)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow)

# finding.py
class Finding(Base):
    __tablename__ = "findings"
    id: UUID = Column(primary_key=True, default=uuid4)
    scan_id: UUID = Column(ForeignKey("scans.id"), nullable=False)
    title: str = Column(String(255), nullable=False)
    severity: str = Column(String(20))  # critical, high, medium, low, info
    cvss_score: float = Column(Numeric(3, 1))
    cwe: int = Column(Integer)
    description: str = Column(Text)
    remediation: str = Column(Text)
    proof_of_concept: str = Column(Text)
    tool_name: str = Column(String(100))
    status: str = Column(String(20), default="new")
    first_seen: datetime = Column(DateTime(timezone=True))
    last_seen: datetime = Column(DateTime(timezone=True))
    hash_signature: str = Column(String(64))  # SHA256
    ai_consensus: dict = Column(JSONB)
    compliance_labels: dict = Column(JSONB)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow)

# compliance.py
class ComplianceMapping(Base):
    __tablename__ = "compliance_mappings"
    id: UUID = Column(primary_key=True, default=uuid4)
    cwe: int = Column(Integer, nullable=False)
    framework: str = Column(String(50))  # iso27001, pci_dss, nist_csf, ...
    control_id: str = Column(String(50))  # A.5.1, 6.2.4, PR.AC-1, ...
    control_description: str = Column(Text)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow)

# report.py
class Report(Base):
    __tablename__ = "reports"
    id: UUID = Column(primary_key=True, default=uuid4)
    scan_id: UUID = Column(ForeignKey("scans.id"), nullable=False)
    report_type: str = Column(String(50))  # executive_pdf, technical_docx, ...
    status: str = Column(String(20), default="generating")  # generating, ready, failed
    file_path: str = Column(String(2048))
    file_size_bytes: int = Column(Integer)
    generated_at: datetime = Column(DateTime(timezone=True))
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow)

# audit_logs.py
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: UUID = Column(primary_key=True, default=uuid4)
    user_id: UUID = Column(ForeignKey("users.id"), nullable=False)
    action: str = Column(String(255))
    resource_type: str = Column(String(50))  # Scan, Finding, Report
    resource_id: UUID = Column()
    changes: dict = Column(JSONB)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow)
```

### 8.2 Indexes & Query Optimization

```sql
-- Indexes for common queries
CREATE INDEX idx_scans_target_status ON scans(target_id, status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_findings_scan_id_severity ON findings(scan_id, severity);
CREATE INDEX idx_findings_hash_signature ON findings(hash_signature);
CREATE INDEX idx_findings_first_seen ON findings(first_seen);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_compliance_mapping_cwe ON compliance_mappings(cwe, framework);
```

---

## 9. Security Requirements

### 9.1 OWASP Top 10 Mitigation

| Vulnerability | NETRA Mitigation |
|---------------|------------------|
| A01: Broken Access Control | RBAC matrix; JWT claims; column-level security |
| A02: Cryptographic Failures | bcrypt password hashing; HTTPS only (TLS 1.2+) |
| A03: Injection | SQLAlchemy ORM (no raw SQL); Pydantic input validation |
| A04: Insecure Design | Threat modeling in code; security by default |
| A05: Security Misconfiguration | Env vars (no hardcoded secrets); Docker defaults |
| A06: Vulnerable/Outdated Components | Poetry lock file; dependabot; security patches |
| A07: Authentication Failures | JWT + refresh tokens; MFA-ready; rate limiting |
| A08: Data Integrity Failures | Audit logs; checksums; signed reports |
| A09: Logging & Monitoring Failures | structlog JSON logging; audit trail DB |
| A10: SSRF | URL validation; IP allowlist; DNS rebind checks |

### 9.2 Secure Coding Standards

**Parameterized Queries (SQLAlchemy ORM)**
```python
# ✓ GOOD: ORM (no SQL injection)
findings = db.query(Finding).filter(Finding.severity == severity).all()

# ✗ BAD: Raw SQL
findings = db.execute(f"SELECT * FROM findings WHERE severity = '{severity}'")
```

**Input Validation (Pydantic)**
```python
class ScanCreate(BaseModel):
    target_id: UUID  # UUID type enforced
    name: str = Field(..., min_length=1, max_length=255)
    profile: ScanProfile  # Enum enforced
```

**Password Hashing (bcrypt)**
```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
hashed = pwd_context.hash(password)
verified = pwd_context.verify(password, hashed)
```

**JWT Token Handling**
```python
from datetime import timedelta
from jose import jwt

token = jwt.encode(
    {"sub": user_id, "exp": datetime.utcnow() + timedelta(minutes=15)},
    SECRET_KEY,
    algorithm="HS256"
)
```

**Rate Limiting**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@router.get("/findings")
@limiter.limit("100/minute")
async def list_findings(...):
    pass
```

### 9.3 Environment Variable Management

**No Hardcoded Secrets**
```python
# ✗ BAD
DATABASE_URL = "postgresql://user:password@localhost/db"

# ✓ GOOD
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str  # Loaded from .env or Docker env

    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()
```

**.env.example (checked in)**
```
DATABASE_URL=postgresql://user:password@localhost/netra_db
REDIS_URL=redis://localhost:6379/0
OLLAMA_HOST=http://localhost:11434
JWT_SECRET_KEY=change-me-in-production
```

### 9.4 CORS & Security Headers

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Not "*"
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

### 9.5 Audit Logging

Every sensitive action logged:
```python
# Example: User marks finding as false positive
async def mark_finding_false_positive(finding_id: UUID, user: User, db: AsyncSession):
    finding = await db.get(Finding, finding_id)
    old_status = finding.status
    finding.status = "false_positive"

    # Audit log
    audit = AuditLog(
        user_id=user.id,
        action="mark_false_positive",
        resource_type="Finding",
        resource_id=finding_id,
        changes={"status": {old_status: "false_positive"}}
    )
    db.add(audit)
    await db.commit()
```

---

## 10. Non-Functional Requirements

### 10.1 Performance

| Requirement | Target | Notes |
|-------------|--------|-------|
| Scan 1000 findings through AI consensus | < 5 min | 4 personas parallel via asyncio.gather |
| Generate PDF report (50+ page) | < 2 min | ReportLab streaming |
| API response time (p95) | < 500ms | Database indexes, caching |
| WebSocket message latency | < 100ms | Real-time scan updates |
| Dashboard page load (p95) | < 1.5s | React SPA, assets cached |

### 10.2 Scalability

- **Horizontal:** Celery workers scale to 10+ machines
- **Vertical:** Single machine handles 100+ concurrent API requests (Uvicorn + 4 workers)
- **Database:** PostgreSQL connection pooling (20 connections)
- **Cache:** Redis in-memory caching for personas (1GB default)

### 10.3 Availability

- **Uptime:** 99.9% (Docker orchestration with health checks)
- **Failover:** Automated container restart on crash
- **Data:** PostgreSQL ACID guarantees, nightly backups
- **Circuit breaker:** Fallback if Ollama/API LLM unavailable (pure scanning mode)

### 10.4 Observability

**Logging (structlog)**
```python
import structlog

logger = structlog.get_logger()
logger.info("scan_started", scan_id=scan_id, target=target_url)
logger.error("tool_error", tool="nuclei", error=str(e), scan_id=scan_id)
```

**Output:** JSON lines, parseable by Datadog/Splunk
```json
{"event": "scan_started", "scan_id": "uuid", "target": "example.com", "timestamp": "2026-03-29T10:00:00Z"}
{"event": "tool_error", "tool": "nuclei", "error": "...", "scan_id": "uuid", "timestamp": "2026-03-29T10:05:00Z"}
```

**Metrics:** Prometheus-compatible (future phase)
- `scan_duration_seconds` — Histogram
- `findings_count` — Gauge
- `api_request_duration_seconds` — Histogram
- `celery_task_duration_seconds` — Histogram

### 10.5 Cross-Platform Support

| OS | Status | Notes |
|----|--------|-------|
| Linux (Ubuntu, Debian) | ✓ | Primary target |
| macOS (Intel + ARM) | ✓ | Homebrew formulae provided |
| Windows | ✓ | Docker + WSL2 required |
| Kubernetes | ✓ (Phase 4) | Helm charts planned |

---

## 11. Testing Strategy

### 11.1 Unit Tests

**Target:** 80%+ code coverage

```python
# tests/unit/test_consensus.py
import pytest
from netra.ai.consensus import ConsensusVoter

@pytest.mark.asyncio
async def test_consensus_validates_finding_with_3_votes():
    voter = ConsensusVoter()
    votes = {
        "attacker": {"vote": "yes", "confidence": 0.9},
        "defender": {"vote": "easy", "confidence": 0.8},
        "analyst": {"vote": "critical", "confidence": 0.85},
        "skeptic": {"vote": "confirmed", "confidence": 0.05}
    }
    result = voter.aggregate(votes)
    assert result["validated"] == True
    assert result["severity"] == "critical"
```

**Tools:** pytest, pytest-asyncio, pytest-cov, factory-boy

### 11.2 Integration Tests

**Test:** API endpoints with test database

```python
# tests/integration/test_scan_api.py
@pytest.mark.asyncio
async def test_create_scan_with_valid_target(client, db_session):
    target = await create_test_target(db_session)
    response = await client.post(
        "/api/v1/scans",
        json={
            "target_id": str(target.id),
            "name": "Test Scan",
            "profile": "quick"
        }
    )
    assert response.status_code == 201
    assert response.json()["status"] == "pending"
```

### 11.3 E2E Tests

**Test:** Full user flows via Playwright (frontend)

```python
# tests/e2e/test_scan_flow.py
import pytest
from playwright.async_api import async_playwright

@pytest.mark.asyncio
async def test_create_and_view_scan():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        # Login
        await page.goto("http://localhost:3000/login")
        await page.fill("[name=email]", "analyst@example.com")
        await page.fill("[name=password]", "password123")
        await page.click("button:has-text('Login')")

        # Create scan
        await page.click("[href='/scans']")
        await page.click("button:has-text('New Scan')")
        await page.fill("[name=name]", "E2E Test Scan")
        await page.click("button:has-text('Start Scan')")

        # Verify success
        await page.wait_for_selector("text=Scan running")
        assert "running" in page.url()
```

### 11.4 Load Testing

```bash
# tests/load/locustfile.py
from locust import HttpUser, task

class ScanUser(HttpUser):
    @task
    def list_findings(self):
        self.client.get("/api/v1/findings", headers={"Authorization": "Bearer {token}"})

# Run
locust -f tests/load/locustfile.py --users 100 --spawn-rate 10 -H http://localhost:8000
```

### 11.5 Coverage Reports

```bash
pytest --cov=netra --cov-report=html --cov-report=term-missing
# Output: htmlcov/index.html
```

---

## 12. Deployment Options

### 12.1 Option 1: CLI Mode (pip install)

**Target Users:** Pentetesters, researchers
**Database:** SQLite (local)
**LLM:** Ollama (local, must be running)

```bash
pip install netra
ollama serve &  # In another terminal
netra -t example.com --profile standard
```

**Pros:**
- Zero DevOps
- No Docker required
- Full offline capability

**Cons:**
- Single-user
- No collaboration
- No web UI

### 12.2 Option 2: Docker Compose (Full Stack)

**Target Users:** Small teams, self-hosted
**Database:** PostgreSQL (containerized)
**LLM:** Ollama (containerized)
**UI:** React Dashboard (on port 3000)
**API:** FastAPI (on port 8000)

```bash
git clone https://github.com/yashwg/netra.git && cd netra
docker compose up -d
# Wait 30s for services to start
docker compose exec api alembic upgrade head  # Migrations
```

**Pros:**
- Complete stack
- Multi-user support
- Dashboard + CLI
- Persistent database

**Cons:**
- 8GB+ RAM minimum
- Docker knowledge required

### 12.3 Option 3: Kubernetes (Scale)

**Target Users:** Enterprise deployments
**Database:** Managed PostgreSQL (AWS RDS, GCP Cloud SQL, Azure Database)
**LLM:** Hosted inference (Together.ai, RunPod, or local K8s Pod)
**UI:** Kubernetes Ingress
**API:** Kubernetes Deployment (3+ replicas)
**Workers:** Kubernetes Deployment (HPA scaling)

```bash
# Deploy via Helm (Phase 4)
helm repo add netra https://charts.netra.io
helm install netra netra/netra --values values.yaml
```

**Pros:**
- Auto-scaling
- High availability
- Enterprise-ready

**Cons:**
- Complex
- Requires Kubernetes
- Higher cost

### 12.4 Option 4: MCP Server (Claude Desktop)

**Target Users:** AI enthusiasts, Claude users
**Database:** Shared PostgreSQL
**LLM:** Claude API (Anthropic)
**Interface:** Claude Desktop application

```bash
# Register in Claude Desktop config
{
  "mcpServers": {
    "netra": {
      "command": "python",
      "args": ["-m", "netra.mcp.server"]
    }
  }
}
```

**Pros:**
- Integrates with Claude
- No separate UI needed
- Scriptable in Claude

**Cons:**
- Requires Claude subscription
- Cloud LLM costs

---

## 13. Success Metrics

### 13.1 Adoption Metrics

| Metric | Target (Y1) | Measurement |
|--------|------------|-------------|
| GitHub Stars | 5,000+ | GitHub API |
| npm Downloads | 50,000+ | npm stats |
| Docker Hub Pulls | 100,000+ | Docker Hub stats |
| Active Users | 5,000+ | Opt-in telemetry |
| Contributors | 50+ | Git history |

### 13.2 Engagement Metrics

| Metric | Target | Measurement |
|--------|--------|------------|
| Scans/week/user | 5+ | Database queries |
| Reports generated/month | 1,000+ | Report count |
| Average compliance frameworks used | 3+ | Scan config analysis |
| Dashboard page views/month | 100,000+ | Analytics |
| API requests/month | 1,000,000+ | API logs |

### 13.3 Quality Metrics

| Metric | Target | Measurement |
|--------|--------|------------|
| Bug reports/month | < 20 | GitHub issues |
| Security advisories/year | 0 | responsible disclosure |
| Test coverage | 80%+ | pytest coverage |
| Average response time (p95) | < 500ms | APM |
| Uptime (Docker Compose) | 99.9% | health checks |

### 13.4 Community Metrics

| Metric | Target | Measurement |
|--------|--------|------------|
| Forum posts/month | 500+ | Discourse |
| Slack members | 2,000+ | Slack workspace |
| Plugins published | 20+ | Plugin registry |
| Blog posts/month | 4+ | Medium, Dev.to |

---

## 14. Acceptance Criteria

### Phase 1 Acceptance (Scanning + AI + Reports)

- [ ] All 23 tools integrated and functional
- [ ] 7-phase orchestrator executes end-to-end
- [ ] 4-persona consensus voting system deployed
- [ ] 3 report types generated (Executive PDF, Technical DOCX, Pentest PDF)
- [ ] CLI with Rich menu operational
- [ ] MCP server with 14 endpoints deployed
- [ ] Unit tests: 80%+ coverage
- [ ] Docker Compose builds and runs
- [ ] 100 findings processed in < 5 minutes

**Acceptance Date:** 2026-01-31 ✓ (COMPLETE)

### Phase 2 Acceptance (White-box + Cloud + Compliance)

- [ ] SAST (Semgrep), secrets (Gitleaks), container (Trivy), IaC (Checkov) integrated
- [ ] Cloud CSPM (Prowler) integrated
- [ ] LLM security assessment tool deployed
- [ ] 101+ CWE mappings loaded to database
- [ ] 6 compliance frameworks (ISO, PCI, NIST, HIPAA, SOC2, CIS) auto-mapping functional
- [ ] 10 additional report types generated
- [ ] Alembic migrations 001 + 002 applied
- [ ] Finding.ai_consensus stored and queryable
- [ ] Finding.compliance_labels populated correctly
- [ ] Compliance gap analysis endpoint operational

**Acceptance Date:** 2026-02-28 ✓ (COMPLETE)

### Phase 3 Acceptance (Dashboard + Launch)

- [ ] React dashboard with 13 pages deployed
- [ ] 28 components built and tested
- [ ] RBAC (4 roles) enforced at API + frontend
- [ ] WebSocket real-time scan updates working
- [ ] Attack graph D3.js visualization interactive
- [ ] 3 GitHub Actions workflows tested
- [ ] Docker multi-stage builds optimized
- [ ] MkDocs documentation complete
- [ ] CLI flags (--output-sarif, --fail-on) working
- [ ] End-to-end tests (Playwright) passing
- [ ] Production-ready deployment checklist complete

**Acceptance Date:** 2026-03-29 ✓ (COMPLETE)

### Phase 4 Acceptance (Scaling + Integrations)

- [ ] Celery tasks wired to orchestrator
- [ ] Distributed scanning across 4+ workers functional
- [ ] Slack + Email notifications deployed
- [ ] Refresh token rotation implemented
- [ ] SSRF protection on scan targets enforced
- [ ] Async persona queries (asyncio.gather) optimized
- [ ] Global search in dashboard functional
- [ ] Scan scheduling (cron) working
- [ ] Plugin system for community tools functional
- [ ] DefectDojo / Jira integrations tested

**Acceptance Date:** Q2 2026 (PLANNED)

---

## 15. Appendices

### Appendix A: Compliance Framework Control Counts

| Framework | Total Controls | Mapped to CWE | Coverage |
|-----------|----------------|---------------|----------|
| ISO 27001:2022 | 114 | 89 | 78% |
| PCI-DSS v4.0 | 332 | 101 | 98% |
| NIST CSF 2.0 | 23 | 67 | 91% |
| HIPAA §164.312 | 18 | 42 | 89% |
| SOC 2 Type II | 7 | 51 | 85% |
| CIS Controls v8 | 18 | 76 | 93% |

### Appendix B: CWE Mapping Categories

```
Injection Attacks (CWE-79, 89, 90, 94, 95, 917, 942)
  → 23 findings in typical VAPT
  → Maps to: PCI 6.2, NIST DE.CM-1, ISO 12.6.1

Authentication/Authorization (CWE-287, 295, 306, 613)
  → 15 findings per scan
  → Maps to: PCI 6.5, NIST PR.AC-1, ISO 9.4.2

Cryptography (CWE-327, 331, 347, 916)
  → 8 findings
  → Maps to: PCI 3.2, NIST PR.DS-1, HIPAA 164.312(a)

Information Disclosure (CWE-200, 209, 215, 532, 541)
  → 20 findings
  → Maps to: PCI 2.1, NIST DE.AE-1, ISO 8.2.3

Software Defects (CWE-434, 451, 613, 639, 776)
  → 10 findings
  → Maps to: PCI 6.1, NIST DE.CM-1, ISO 14.2.1
```

### Appendix C: Scanner Tool Capabilities Matrix

| Tool | Type | Categories | Output | Speed | Accuracy |
|------|------|-----------|--------|-------|----------|
| nuclei | Vuln | Web, Network, Cloud | JSON | Fast | High |
| nmap | Recon | Ports, Services | XML | Medium | Very High |
| semgrep | SAST | Code defects, secrets | JSON | Fast | High |
| gitleaks | Secrets | API keys, creds | JSON | Very Fast | Medium |
| trivy | Container | CVEs, misconfig | JSON | Fast | High |
| prowler | CSPM | Cloud misconfig | JSON | Medium | Very High |
| checkov | IaC | Terraform, K8s | JSON | Fast | High |
| sqlmap | Exploitation | SQL injection | JSON | Slow | Very High |
| dalfox | XSS | Cross-site scripting | JSON | Fast | Medium |
| ffuf | Fuzzing | Endpoints, dirs | JSON | Very Fast | Medium |

### Appendix D: Report Type Comparison Table

| Report Type | Pages | Audience | Format | Time to Generate |
|-------------|-------|----------|--------|------------------|
| Executive PDF | 2-3 | C-suite | PDF | 30s |
| Technical DOCX | 5-10 | Engineers | DOCX | 1m |
| Pentest PDF | 10-15 | Security teams | PDF | 2m |
| HTML Interactive | 20+ | All | HTML | 45s |
| Excel 9-Sheet | Variable | Analysts | XLSX | 1.5m |
| Evidence ZIP | Compressed | Auditors | ZIP | 3m |
| Compliance Gap | 5-8 | Compliance | PDF | 2m |
| Delta/Diff | 5-10 | Trending | PDF | 1m |
| API Security | 8-12 | API teams | PDF | 2m |
| Cloud Security | 8-12 | Cloud teams | PDF | 2m |
| Full Comprehensive | 30+ | Final delivery | PDF | 5m |
| SARIF JSON | Variable | CI/CD | JSON | 10s |
| Full Report | 50+ | Archives | PDF | 10m |

### Appendix E: CLI Command Reference

```bash
# Scanning
netra -t example.com                          # Quick scan
netra -t example.com --profile deep           # Full VAPT
netra -f targets.txt                          # Multi-target from file
netra -x assets.xlsx                          # From Excel
netra --resume                                # Resume last scan
netra --resume --scan-id {uuid}               # Resume specific scan

# Status & Management
netra --status                                # DB summary table
netra --check-deps                            # Tool status
netra --install-deps                          # Install all tools
netra --list-scans                            # List all scans
netra --show-scan {scan_id}                   # Scan details

# Output Options
netra -t example.com --output-json            # JSON export
netra -t example.com --output-sarif           # SARIF export (CI/CD)
netra -t example.com --output-html            # HTML report
netra -t example.com --output-pdf             # PDF report
netra -t example.com --output-xlsx            # Excel export

# Advanced
netra -t example.com --fail-on critical       # Exit code 1 if critical
netra -t example.com --timeout 120            # 2-hour limit
netra --web                                   # Start web dashboard (Phase 3+)
netra --mcp-server                            # Start MCP server (Claude)
```

### Appendix F: Database Migration Checklist

**Pre-Migration**
- [ ] Backup production database
- [ ] Review migration script
- [ ] Test on staging environment
- [ ] Estimate downtime
- [ ] Notify users

**Migration**
- [ ] Stop all workers
- [ ] Run `alembic upgrade head`
- [ ] Verify schema changes
- [ ] Run smoke tests
- [ ] Start workers

**Post-Migration**
- [ ] Monitor logs
- [ ] Verify data integrity
- [ ] Update documentation
- [ ] Archive migration script

### Appendix G: Security Checklist (Pre-Production)

- [ ] JWT secret key rotated (not default)
- [ ] Database password changed
- [ ] Redis password set
- [ ] CORS origins restricted (not "*")
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] HTTPS enforced (TLS 1.2+)
- [ ] Security headers added (HSTS, CSP, X-Frame-Options)
- [ ] OWASP dependency scan passes
- [ ] SQL injection tests pass
- [ ] CSRF token validation enabled
- [ ] MFA ready for implementation

### Appendix H: Performance Tuning Guidelines

**Database**
```sql
-- Add indexes for common queries
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_findings_scan_severity ON findings(scan_id, severity);

-- Vacuum & analyze
VACUUM ANALYZE;
```

**Cache (Redis)**
- Set eviction policy: `maxmemory-policy allkeys-lru`
- Monitor with: `redis-cli info stats`

**Ollama**
- Pre-load model: `ollama pull qwen:14b`
- Monitor memory: `ollama ps`

**FastAPI**
- Increase workers: `uvicorn main:app --workers 8`
- Enable gzip: `middleware=[GZipMiddleware(minimum_size=1000)]`

### Appendix I: Troubleshooting Guide

**Issue:** Scan hangs in Phase 4 (Vulnerability Scanning)
- Check Ollama status: `ollama ps`
- Check disk space: `df -h`
- Check RAM: `free -h`
- Restart workers: `docker compose restart netra-worker`

**Issue:** False positives in AI consensus
- Review Skeptic votes in Finding.ai_consensus
- Adjust Skeptic prompt in `src/netra/ai/prompts/skeptic_brain.txt`
- Re-run AI analysis on finding

**Issue:** Reports not generating
- Check disk space for /scans directory
- Verify ReportLab/python-docx installed
- Check logs: `docker compose logs -f netra-api`

**Issue:** Database migrations fail
- Check Alembic version: `alembic current`
- Review migration script for syntax
- Rollback: `alembic downgrade -1`

### Appendix J: Version History

| Version | Release Date | Major Features | Status |
|---------|------------|-----------------|--------|
| v1.0.0 | 2026-03-29 | Scanning, AI, Reports, Dashboard | ✓ CURRENT |
| v1.1.0 | Q2 2026 | Celery scaling, Notifications, Integrations | 📋 PLANNED |
| v2.0.0 | Q4 2026 | Plugin system, Kubernetes, Advanced AI | 📋 PLANNED |
| v2.1.0 | Q2 2027 | TBD | 📋 FUTURE |

---

## Document Control

| Field | Value |
|-------|-------|
| Document ID | NETRA-PRD-001 |
| Version | 1.0.0 |
| Status | APPROVED |
| Last Updated | 2026-03-29 |
| Next Review | 2026-06-29 |
| Owner | Yash Wardhan Gautam |
| Reviewers | Security Team, Product Team, Engineering Team |

---

**END OF DOCUMENT**

This PRD is a living document. For the latest version, visit: https://github.com/yashwg/netra/docs/PRD.md
