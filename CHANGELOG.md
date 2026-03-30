# Changelog

All notable changes to NETRA नेत्र will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] - 2026-03-28

### Added

**Phase 3: Dashboard + Agent + Launch**

- **React Dashboard** — 10 pages with real-time WebSocket updates
  - Dashboard overview with risk gauge and severity charts
  - Scans list with filters and pagination
  - Scan detail with phase timeline
  - Findings list with bulk actions
  - Finding detail with AI analysis tabs
  - Reports generator with 11 types
  - Compliance dashboard with framework tabs
  - Targets management
  - Attack graph visualization
  - Settings page

- **Autonomous Pentest Agent**
  - Claude Agent SDK orchestration
  - Human-in-the-loop approval workflow
  - Safety limits (50 tool calls, 30 min, $5 cost)
  - Audit trail logging
  - WebSocket conversation streaming
  - Tools requiring approval: sqlmap, dalfox, ffuf

- **CI/CD Integration**
  - GitHub Actions workflow
  - Reusable workflow for other repos
  - SARIF output for GitHub Security tab
  - CLI exit codes for pipeline failure

- **Documentation Site**
  - MkDocs with Material theme
  - Installation, Quick Start, Configuration guides
  - Scan Profiles, Reports, Compliance docs
  - Dashboard, Agent, CI/CD guides
  - Full API reference

**Phase 2: Full Coverage**

- **White-Box Testing**
  - Semgrep SAST wrapper
  - Gitleaks secret detection
  - Dependency scanning (pip-audit, npm audit, govulncheck)

- **Cloud Security (CSPM)**
  - Prowler wrapper (AWS, Azure, GCP)
  - Trivy container/filesystem scanning
  - Checkov IaC scanning

- **AI/LLM Security**
  - OWASP LLM Top 10 scanner
  - Prompt injection testing
  - Jailbreak detection
  - Data exfiltration tests
  - Excessive agency detection

- **Compliance Expansion**
  - 100+ CWE-to-control mappings
  - 6 frameworks: ISO 27001, PCI DSS, SOC 2, HIPAA, NIST CSF, CIS Controls
  - Framework-specific gap analysis

- **Report Generators (8 new)**
  - HTML interactive dashboard
  - Excel 9-sheet workbook
  - Evidence ZIP with SHA256 chain of custody
  - Delta/Diff scan comparison
  - API Security report
  - Cloud Security report
  - Compliance Gap report
  - Full Comprehensive report

**Phase 1: Scanning Engine**

- **10 Tool Wrappers**
  - Nuclei, Nmap, Subfinder, Httpx, Ffuf
  - Dalfox, Nikto, Sqlmap, Amass, Shodan

- **Scan Orchestrator**
  - 6-phase pipeline with checkpoint resume
  - 4 scan profiles: quick, standard, deep, api_only

- **Finding Service**
  - SHA256 deduplication
  - Lifecycle management (NEW → VERIFIED)
  - SLA tracking by severity

- **AI Brain**
  - 4 personas: Attacker, Defender, Analyst, Skeptic
  - Consensus voting system
  - Attack chain discovery

- **Initial Reports**
  - Executive PDF
  - Technical Word
  - Pentest PDF

- **MCP Server**
  - 14 tool endpoints
  - 6 prompt templates

### Changed

- Updated version to 1.0.0
- Updated README with full documentation
- Added comprehensive docs site

### Security

- Self-scan with zero critical findings
- Dependency audit clean
- Secret scan clean

---

## [0.1.0] - 2026-03-17

### Added

**Core Platform**
- Full VAPT scanning pipeline: OSINT, subdomain enumeration, port scanning, vulnerability scanning, pentest modules
- 15 scanning modules covering web, API, network, cloud, auth, injection, misconfig, WAF evasion
- Phase-aware checkpoint system — resume any interrupted scan from last completed phase
- SQLite findings database with WAL mode, scan history, attack chains, AI analysis tables

**AI Brain (Ollama-powered, no API keys needed)**
- 4-persona multi-agent consensus system: Bug Bounty Hunter, Code Auditor, Pentester, Skeptic
- Qwen 14B as default model (also supports: llama2, mistral, neural-chat)
- Skeptic veto mechanism — rejects findings at 80%+ false-positive confidence
- 3/4 persona majority required to confirm a finding (~60% fewer false positives)
- CVSS v3.1 automatic scoring with full metric parsing
- DFS attack chain discovery with MITRE ATT&CK phase sequencing
- AI-powered narrative generation for findings and executive summaries

**Compliance & Auditing**
- CIS Benchmarks (Linux, Docker, Kubernetes)
- NIST Cybersecurity Framework (CSF)
- PCI-DSS v4.0
- HIPAA §164.312
- SOC2 Type II
- Auto-mapping of findings to compliance controls

**Report Engine (6 formats)**
- Interactive single-file HTML with dark/light mode, filter, sort, CVE linking
- PDF (ReportLab, color-coded, branded cover page)
- Word (.docx, python-docx, executive-ready)
- Excel (9 sheets: summary, findings, risk scorecard, MITRE map, remediation)
- Compliance PDF (per-standard control status tables)
- Evidence ZIP with SHA-256 chain-of-custody manifest

**Screenshot Capture**
- Playwright-based headless browser capture for all discovered live URLs
- Full-page screenshots stored per-scan in `screenshots/`
- Thumbnails embedded in HTML reports and Evidence ZIP

**Cloud Detection**
- Auto-detection of AWS, Azure, GCP services in scanned scope
- S3 bucket enumeration, Azure Blob discovery, GCP service fingerprinting
- Interactive CSPM prompt when cloud services are found
- DNS CNAME, HTTP header, IP range, and SSL cert-based detection

**Infrastructure**
- `~/.netra/` structured data hierarchy (tools, data, scans, cache, logs)
- Smart tool manager: searches PATH first, installs locally to `~/.netra/tools/bin/`
- `install.sh` — one-command setup (Python, Go, Ollama, all tools)
- Docker + docker-compose support
- GitHub Actions CI (lint, syntax check, tests)

### Known Limitations
- MCP server (Claude Desktop integration) built but deferred to v2
- Screenshot capture requires `playwright install chromium` after pip install
- Cloud CSPM deep audit deferred to v2

---

## [Unreleased]

### Planned for v2.0.0
- MCP server with 17 tools for Claude Desktop integration
- REST API with JWT auth
- Plugin system for custom scan modules
- DefectDojo integration
- Scan scheduling (cron-based)
- ISO 27001 + BSI C5 compliance standards
- Real-time monitoring dashboard
