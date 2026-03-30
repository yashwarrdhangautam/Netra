# NETRA नेत्र

**The Third Eye of Security**

[![version](https://img.shields.io/badge/version-1.0.0-blue?logo=semver)](https://github.com/yashwarrdhangautam/netra/releases)
[![license](https://img.shields.io/badge/license-AGPL--3.0-green)](LICENSE)
[![python](https://img.shields.io/badge/python-3.11+-yellow?logo=python)](https://www.python.org/)
[![maintained](https://img.shields.io/badge/maintained-yes-success)](https://github.com/yashwarrdhangautam/netra)
[![stars](https://img.shields.io/github/stars/yashwarrdhangautam/netra?style=flat)](https://github.com/yashwarrdhangautam/netra)

Open-source AI-augmented vulnerability assessment and penetration testing platform. Combines 23 security tools, local AI consensus analysis, and compliance mapping. No API keys. No cloud. 100% offline.

---

## Why NETRA?

- **Unified platform** — Stop juggling 14+ separate tools, API keys, and manual report aggregation. NETRA orchestrates nmap, nuclei, subfinder, sqlmap, and 19 others into a single workflow.
- **AI-augmented analysis** — 4-persona consensus voting reduces false positives by ~60%. No ChatGPT API costs. Your Qwen or Llama model runs locally via Ollama.
- **Compliance built-in** — Auto-map findings to CIS, NIST, PCI-DSS, HIPAA, SOC2, and 101 CWE mappings. Export executive reports in minutes, not weeks.
- **Open source & transparent** — AGPL-3.0. Audit the code. No vendor lock-in. Community-driven roadmap.

---

## Key Features

**Scanning** — 23 security tools, 7-phase pipeline
- OSINT recon (subfinder, amass, assetfinder, gau)
- Port scanning (nmap, naabu) + service enumeration
- Vulnerability scanning (nuclei: 9000+ templates, nikto, sqlmap)
- Web crawling (katana, ffuf) + screenshot capture via Playwright
- Cloud detection (AWS/Azure/GCP) + S3 bucket enumeration

**AI Brain** — 4-persona consensus voting
- Bug Bounty Hunter, Code Auditor, Pentester, Skeptic personas
- CVSS scoring + attack chain discovery (DFS graph analysis)
- MITRE ATT&CK technique mapping
- ~60% fewer false positives vs. single-model analysis

**Reports** — 13 professional formats
- Interactive HTML with evidence, screenshots, proof-of-concept
- PDF (executive + technical) • Word documents • Excel (9 sheets)
- Compliance audit PDF • Evidence ZIP archive with raw tool output
- Integrates with DefectDojo, GitHub Issues (planned v2.0)

**Compliance** — 6 frameworks, 101 CWE mappings
- CIS Benchmarks (Linux, Docker, Kubernetes)
- NIST CSF (PR.AC, PR.DS, DE.AE, RS.AN)
- PCI-DSS v4.0 (encryption, segmentation, scanning)
- HIPAA §164.312 (workforce, access, PHI)
- SOC2 Type II (change management, monitoring)

**Dashboard** — 13 pages, real-time updates
- Finding timeline + risk heat map
- Scan history with phase-aware resumption
- Attack chain visualization
- Compliance control status dashboard (v2.0)

**CI/CD Integration** — GitHub Actions + SARIF export
- Auto-trigger scans on PR/push
- Reusable workflow: `.github/workflows/netra.yml`
- SARIF output for GitHub code scanning
- Slack/email notifications

**MCP (Claude Desktop)** — AI assistant integration
- Query findings via natural language
- Generate narratives + attack chain summaries
- Ask Claude: "What are the critical findings?"

---

## Quick Start

**Option 1: One-Command Install** (recommended)

```bash
bash <(curl -s https://raw.githubusercontent.com/yashwarrdhangautam/netra/main/install.sh)
netra --help
```

**Option 2: pip Install**

```bash
pip install netra
netra --help
netra scan --target scanme.nmap.org --profile quick
```

**Option 3: Docker**

```bash
git clone https://github.com/yashwarrdhangautam/netra.git
cd netra
docker compose up -d
docker compose exec netra netra scan --target scanme.nmap.org --profile quick
```

---

## First Scan

```bash
# Start a scan
netra scan --target scanme.nmap.org --profile quick
# ✓ Recon phase: 2 min  (subfinder, assetfinder)
# ✓ Port scan: 3 min    (nmap -sV)
# ✓ Vuln scan: 5 min    (nuclei + nikto)
# ✓ AI analysis: 2 min  (consensus voting)
# → Scan ID: scan_20260329_scanme.nmap.org

# Generate report
netra report --scan-id scan_20260329_scanme.nmap.org --type executive
# → Executive summary: 3 critical, 7 high, 12 medium findings
# → compliance_audit.pdf: CIS fails on 4 controls

# View findings
netra findings --scan-id scan_20260329_scanme.nmap.org --severity critical
```

---

## Dashboard Preview

After a scan completes, browse to `http://localhost:3000`:

- **Overview** — risk gauge (critical, high, medium, low counts)
- **Findings** — filterable table with CVSS, CWE, affected systems
- **Attack Chains** — graph visualization of chained vulnerabilities
- **Compliance** — control-by-control audit status (red/yellow/green)
- **Screenshots** — web page thumbnails with highlighted findings
- **Scan History** — phase timeline, tool execution logs, resume option
- **Reports** — one-click download (HTML, PDF, Word, Excel, ZIP)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  CLI / Dashboard / REST API / MCP (Claude Desktop)          │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │      Scan Orchestrator              │
        │   (phase control + checkpoints)     │
        └──────────────────┬──────────────────┘
                           │
    ┌──────────────────────┼──────────────────────┐
    │                      │                      │
┌───▼─────┐          ┌────▼────┐          ┌─────▼──┐
│ Tools   │          │ AI Brain │          │Compliance
│ (23)    │          │(Ollama)  │          │Mapper
├─────────┤          ├──────────┤          ├────────┤
│nmap     │          │Consensus │          │CIS
│nuclei   │          │Voting    │          │NIST
│sqlmap   │          │Personas  │          │PCI
│ffuf     │          │(4x)      │          │HIPAA
│...      │          │CVSS      │          │SOC2
└──┬──────┘          └────┬─────┘          └────┬───┘
   │                      │                     │
   └──────────────────────┼─────────────────────┘
                          │
              ┌───────────┴──────────┐
              │                      │
           ┌──▼──┐           ┌──────▼──┐
           │  DB │           │ Reports │
           │     │           │  (13)   │
           └─────┘           └─────────┘
           SQLite            HTML/PDF/DOCX
```

---

## Scan Profiles

| Profile | Duration | Scope | Best For |
|---------|----------|-------|----------|
| **quick** | 30 min | Recon only (subdomain enum, DNS resolution) | Initial assessment, tight schedules |
| **standard** | 2-3 hrs | Full VAPT (recon + ports + vulns + AI) | Regular penetration tests |
| **deep** | 4-6 hrs | Everything + fuzz + cloud enum + screenshots | Red team, compliance audit |
| **cloud** | 3-4 hrs | Cloud-focused (S3 enum, IAM, misconfig) | AWS/Azure/GCP assessments |
| **api_only** | 1-2 hrs | API security (endpoint discovery, auth, fuzz) | API-first / SaaS assessments |

---

## Security Tools (23 Total)

| Tool | Purpose | Category |
|------|---------|----------|
| **nmap** | Port scanning + service/version detection | Scanning |
| **naabu** | Fast port scanning (Go-based) | Scanning |
| **nuclei** | Template-based vuln scanner (9000+ CVE/misconfig) | Scanning |
| **nikto** | Web server scanner (dangerous files, outdated software) | Scanning |
| **subfinder** | Passive subdomain enum (40+ sources) | Recon |
| **amass** | Deep subdomain discovery (DNS brute-force) | Recon |
| **assetfinder** | Cert transparency + API subdomain finder | Recon |
| **dnsx** | DNS resolver (bulk verification) | Recon |
| **httpx** | HTTP prober (live hosts, titles, status codes) | Recon |
| **gau** | Fetch URLs from Wayback, OTX, URLScan | Recon |
| **katana** | Web crawler (endpoints, forms, JS files) | Recon |
| **sqlmap** | Automated SQL injection detection | Pentesting |
| **ffuf** | Web fuzzer (dirs, files, vhost discovery) | Pentesting |
| **gobuster** | Directory/DNS/S3 brute-force | Pentesting |
| **gowitness** | Headless browser screenshots (Playwright) | Pentesting |
| **subzy** | Subdomain takeover detection | Pentesting |
| **wpscan** | WordPress vulnerability scanner | Pentesting |
| **theHarvester** | Email + subdomain harvesting | Recon |
| **massdns** | Bulk DNS resolution | Recon |
| **shuffledns** | Permutation-based subdomain enum | Recon |
| **httpprobe** | Simple HTTP prober | Recon |
| **jq** | JSON query/manipulation | Utility |
| **curl** | URL data fetching | Utility |

---

## Compliance Frameworks

| Framework | Controls | Audit Scope |
|-----------|----------|------------|
| **CIS Benchmarks** | 40+ | Linux, Docker, Kubernetes hardening |
| **NIST CSF** | 22 | PR.AC (access), PR.DS (data security), DE.AE (anomalies), RS.AN (analysis) |
| **PCI-DSS v4.0** | 12 | Network segmentation, encryption, scanning, access control |
| **HIPAA §164.312** | 8 | Workforce security, access management, PHI protection |
| **SOC2 Type II** | 6 | Change management, system monitoring, audit logging |
| **CWE Mappings** | 101 | MITRE CWE-to-finding cross-reference |

---

## Report Types (13 Formats)

| Report Type | Format | Audience | Contents |
|-------------|--------|----------|----------|
| **Executive Summary** | PDF | C-level | Risk gauge, KPIs, compliance status, top 10 findings |
| **Technical Report** | PDF | Security team | Full findings, CVSS, CWE, MITRE, PoC, evidence |
| **Interactive HTML** | HTML | Stakeholders | Searchable tables, screenshots, attack chain graph |
| **Word Document** | DOCX | Legal/compliance | Formatted report, tables, evidence links |
| **Excel Workbook** | XLSX | Ops team | 9 sheets (summary, findings, recon, cloud, compliance, etc.) |
| **Compliance Audit** | PDF | Auditors | Control-by-control status, CIS/NIST/PCI mappings |
| **Evidence ZIP** | ZIP | Forensics | Raw tool output (nmap.xml, nuclei.json, logs) |
| **SARIF Export** | JSON | GitHub | GitHub code scanning integration |
| **DefectDojo** | JSON | DefectDojo | Auto-import findings to DefectDojo |
| **Slack Summary** | JSON | Notifications | Risk summary + link to findings |
| **Email Report** | MIME | Email | Formatted email with findings table |
| **CSV Export** | CSV | Data analysis | Flat findings table for Excel/Splunk |
| **JSON API** | JSON | Integrations | Full findings + metadata for webhooks |

---

## CI/CD Integration

### GitHub Actions

Add to `.github/workflows/netra.yml`:

```yaml
name: NETRA Security Scan
on:
  pull_request:
    paths: ['src/**', 'package.json']

jobs:
  netra-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run NETRA scan
        run: |
          bash <(curl -s https://raw.githubusercontent.com/yashwarrdhangautam/netra/main/install.sh)
          netra scan --target ${{ github.server_url }}/${{ github.repository }} \
            --profile standard \
            --output sarif > netra-report.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: netra-report.sarif

      - name: Comment PR with findings
        if: always()
        run: netra report --scan-id last --type slack-json > pr-comment.json
```

---

## Configuration

### Default Config: `~/.netra/config.yaml`

```yaml
scanning:
  timeout: 3600           # seconds per tool
  threads: 4              # parallel tool execution
  retries: 2

ai_brain:
  model: qwen:14b         # options: qwen:14b, llama2, mistral
  temperature: 0.7
  consensus_threshold: 3  # 3/4 personas must agree

compliance:
  frameworks:
    - cis
    - nist
    - pci_dss

reporting:
  formats: [html, pdf, xlsx, sarif]
  include_screenshots: true
```

**Environment variables:**

```bash
NETRA_DB_PATH=~/.netra/data/findings.db
OLLAMA_MODEL=qwen:14b
OLLAMA_BASE_URL=http://localhost:11434
NETRA_WORKERS=4
NETRA_LOG_LEVEL=INFO
```

See [docs/configuration.md](docs/configuration.md) for full reference.

---

## Documentation

| Topic | Link |
|-------|------|
| **Installation** | [docs/installation.md](docs/installation.md) |
| **Usage Guide** | [docs/usage.md](docs/usage.md) |
| **Configuration** | [docs/configuration.md](docs/configuration.md) |
| **Scan Profiles** | [docs/profiles.md](docs/profiles.md) |
| **Report Templates** | [docs/reports.md](docs/reports.md) |
| **Compliance Mapping** | [docs/compliance.md](docs/compliance.md) |
| **API Reference** | [docs/api.md](docs/api.md) |
| **MCP (Claude)** | [docs/mcp.md](docs/mcp.md) |
| **Contributing** | [CONTRIBUTING.md](CONTRIBUTING.md) |
| **Security Policy** | [SECURITY.md](SECURITY.md) |

---

## Requirements

| Requirement | Version | Notes |
|:---|:---|:---|
| **Python** | 3.11+ | Core runtime |
| **Go** | 1.22+ | Go-based tools (subfinder, nuclei, httpx, etc.) — install.sh handles this |
| **Ollama** | latest | Local LLM backend — install.sh handles this |
| **Qwen** | 14B | Default model (~8GB). Swap in config.yaml for `llama2` or `mistral` (4GB) |
| **OS** | Linux / macOS | Windows via Docker |
| **RAM** | 16GB+ | 8GB minimum; 16GB recommended for Qwen 14B + parallel tools |

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Coding standards (type hints, async/await, SQLAlchemy ORM)
- Test coverage requirements
- PR review process

Quick start:

```bash
git clone https://github.com/yashwarrdhangautam/netra.git
cd netra
poetry install
pytest
```

---

## Security

Found a vulnerability? Please report privately to [SECURITY.md](SECURITY.md) or email security@netra.dev. Do not open public issues for security vulnerabilities.

---

## License

NETRA is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).

**Commercial licensing available.** Contact: yashwarrdhangautam@gmail.com

---

## Acknowledgments

Built on the shoulders of giants:
- [OWASP](https://owasp.org/) — Web security standards
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversary tactics framework
- [NVD](https://nvd.nist.gov/) — Vulnerability database
- [Nuclei](https://github.com/projectdiscovery/nuclei) — Template-based scanning
- [Nmap](https://nmap.org/) — Port scanning
- [Ollama](https://ollama.ai/) — Local LLMs

---

<div align="center">

**Made with care by [Yash Wardhan Gautam](https://github.com/yashwarrdhangautam)**

Securing the digital world, one scan at a time.

</div>
