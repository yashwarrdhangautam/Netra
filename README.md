<p align="center">
  <img src="https://img.shields.io/badge/NETRA-%E0%A4%A8%E0%A5%87%E0%A4%A4%E0%A5%8D%E0%A4%B0-8B5CF6?style=for-the-badge&labelColor=1e1e2e" alt="NETRA" />
</p>

<h1 align="center">NETRA &nbsp;<sub>The Third Eye of Security</sub></h1>

<p align="center">
  <a href="https://github.com/yashwarrdhangautam/netra/releases"><img src="https://img.shields.io/badge/version-1.0.0-8B5CF6?style=flat-square&logo=semver&logoColor=white" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-22c55e?style=flat-square" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white" /></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/react-18-61DAFB?style=flat-square&logo=react&logoColor=black" /></a>
  <a href="https://github.com/yashwarrdhangautam/netra"><img src="https://img.shields.io/github/stars/yashwarrdhangautam/netra?style=flat-square&color=f59e0b" /></a>
  <a href="https://github.com/yashwarrdhangautam/netra/actions"><img src="https://img.shields.io/github/actions/workflow/status/yashwarrdhangautam/netra/ci.yml?style=flat-square&label=CI" /></a>
</p>

<p align="center">
  Open-source, AI-augmented vulnerability assessment &amp; penetration testing platform.<br/>
  Orchestrates 18 security tools, applies 4-persona AI consensus analysis, maps findings to 6 compliance frameworks, and exports 13 report formats &mdash; all from a single CLI command or dashboard.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="docs/api.md">API Docs</a> &bull;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## What's New in v1.0.0

- 18 scanner tool wrappers with phased pipeline orchestration and checkpoint-based resumption
- 4-persona AI consensus engine (Attacker, Defender, Analyst, Skeptic) with parallel execution via asyncio.gather
- 13 report formats (Executive PDF, Technical PDF, Interactive HTML, SARIF, Excel, Pentest, Cloud, Delta, and more)
- Full React 18 dashboard with TypeScript, dark mode, attack chain visualization, and real-time WebSocket updates
- Enterprise security: JWT + MFA + RBAC + CSRF + SSRF protection + rate limiting + CSP headers
- 6 compliance frameworks with 101 CWE cross-reference mappings
- Production-hardened Docker deployment with strict secret enforcement
- MCP server integration for Claude Desktop (18 tools exposed)
- CI/CD pipeline with GitHub Actions, SARIF upload, and frontend build verification

---

## Why NETRA?

Most security teams juggle a dozen CLI tools, manually correlate outputs, and spend days writing reports. NETRA replaces that workflow with a unified pipeline: scan, analyze, map, report.

**Unified orchestration** &mdash; 18 tool wrappers (nmap, nuclei, sqlmap, semgrep, trivy, prowler, and more) execute as a phased pipeline with checkpoint-based resumption. No more shell scripts gluing tools together.

**AI-augmented analysis** &mdash; A 4-persona consensus engine (Attacker, Defender, Analyst, Skeptic) evaluates every finding. Supports Claude (Anthropic API) or local models via Ollama. The Skeptic persona aggressively flags false positives, reducing noise by ~60%.

**Compliance out of the box** &mdash; Findings auto-map to CIS Benchmarks, NIST CSF, PCI-DSS v4.0, HIPAA, SOC2, and 101 CWE entries. Generate audit-ready reports without manual mapping.

**API-first architecture** &mdash; CLI, React dashboard, CI/CD workflows, and Claude Desktop (MCP) all call the same FastAPI backend. Build your own integrations with the REST API.

---

## Features

### Scanning Engine
18 tool wrappers organized into a multi-phase pipeline: subdomain enumeration (subfinder, amass), HTTP probing (httpx), port scanning (nmap), vulnerability scanning (nuclei with 9000+ templates, nikto), active testing (sqlmap, dalfox XSS, ffuf fuzzing), SAST (semgrep), secrets detection (gitleaks), dependency scanning (dependency_scan), cloud security (prowler, checkov), container scanning (trivy), OSINT (shodan), WordPress (wpscan), and AI/LLM security testing (llm_security).

### AI Consensus Engine
Four specialized personas analyze each finding independently, then vote. The Attacker persona assesses exploitability and builds attack chains via DFS graph analysis. The Defender proposes remediation with effort estimates. The Analyst maps to compliance frameworks. The Skeptic challenges evidence quality. Consensus requires 3/4 agreement. Supports Anthropic (Claude Sonnet 4) and Ollama (Llama 3.1, Mistral, Qwen).

### 13 Report Formats
Executive PDF (C-level summary with risk gauge), technical PDF (full findings with CVSS/CWE/MITRE), interactive HTML (searchable tables + attack chain graph), Word document, Excel workbook (9 sheets), compliance audit PDF, evidence ZIP (raw tool output), SARIF (GitHub Security tab), pentest report, cloud security report, API security report, delta report (scan comparison), and full combined report.

### 6 Compliance Frameworks
CIS Benchmarks (Linux, Docker, Kubernetes), NIST Cybersecurity Framework (PR.AC, PR.DS, DE.AE, RS.AN), PCI-DSS v4.0 (12 requirement areas), HIPAA §164.312 (technical safeguards), SOC2 Type II (trust services criteria), and 101 CWE cross-reference mappings. Each finding automatically links to applicable controls.

### React Dashboard
Dark-mode-only React 18 frontend with TypeScript, Vite, Tailwind CSS, and shadcn/ui components. Pages include: overview dashboard with risk gauge and severity charts, findings table with filters and AI analysis panels, scan history with phase timeline and resume capability, compliance control status, report generation, attack chain visualization (react-force-graph-2d), and real-time WebSocket progress updates.

### Enterprise Security
JWT authentication with refresh tokens, TOTP-based MFA with backup codes, role-based access control (Admin/Analyst/Viewer/Client), CSRF protection, SSRF detection, Content Security Policy headers, rate limiting (SlowAPI), account lockout after 5 failed attempts, and encrypted credential storage for third-party API keys.

### Integrations
DefectDojo (finding import), Jira (ticket creation), Slack (webhook notifications), email (SMTP), Claude Desktop via MCP server (18 tool wrappers exposed), and GitHub Actions CI/CD with SARIF upload.

---

## Quick Start

### Option 1: One-command install (recommended)

```bash
bash <(curl -s https://raw.githubusercontent.com/yashwarrdhangautam/netra/main/install.sh)
netra --help
```

### Option 2: pip + Poetry

```bash
git clone https://github.com/yashwarrdhangautam/netra.git && cd netra
poetry install
cp .env.example .env
netra --help
```

### Option 3: Docker (full stack)

```bash
git clone https://github.com/yashwarrdhangautam/netra.git && cd netra
cp .env.example .env
docker compose up -d
# API: http://localhost:8000/docs
# Dashboard: http://localhost:5173
# Flower (task monitor): http://localhost:5555
```

### Your first scan

```bash
# Quick scan (~30 min)
netra scan --target scanme.nmap.org --profile quick

# Standard VAPT (~2-3 hrs)
netra scan --target example.com --profile standard

# View findings
netra findings --scan-id <scan-id> --severity critical

# Generate executive report
netra report --scan-id <scan-id> --type executive
```

---

## Architecture

```
                    ┌────────────────────────────────────────────┐
                    │  CLI  |  Dashboard  |  REST API  |  MCP    │
                    └───────────────────┬────────────────────────┘
                                        │
                    ┌───────────────────┴────────────────────────┐
                    │           FastAPI  (async)                  │
                    │  JWT + MFA + CSRF + Rate Limit + SSRF      │
                    └───────────────────┬────────────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
   ┌──────────▼──────────┐  ┌──────────▼──────────┐  ┌──────────▼──────────┐
   │   Scan Orchestrator  │  │      AI Brain       │  │  Compliance Mapper  │
   │  (Celery + Redis)    │  │  (4-Persona Vote)   │  │  (6 Frameworks)     │
   │  18 phases, resume   │  │  Claude / Ollama    │  │  101 CWE mappings   │
   └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘
              │                         │                         │
   ┌──────────▼──────────┐              │              ┌─────────▼──────────┐
   │   18 Tool Wrappers   │             │              │   13 Report Types   │
   │  nmap, nuclei, sqlmap│             │              │  PDF, HTML, SARIF   │
   │  semgrep, trivy, ... │             │              │  Excel, Word, ZIP   │
   └──────────┬──────────┘              │              └─────────┬──────────┘
              │                         │                         │
              └─────────────────────────┼─────────────────────────┘
                                        │
                            ┌───────────▼───────────┐
                            │   PostgreSQL / SQLite  │
                            │   (SQLAlchemy 2.0)     │
                            └────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Pydantic 2 |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui, Zustand |
| **Task Queue** | Celery 5.3 + Redis 7 |
| **Database** | PostgreSQL 16 (production) / SQLite (development) |
| **AI** | Anthropic Claude SDK / Ollama (local LLMs) |
| **MCP** | FastMCP — 18 tools exposed to Claude Desktop |
| **CI/CD** | GitHub Actions (lint, test, Docker build) |
| **Containerization** | Multi-stage Docker (Go builder + Python runtime) |

---

## Scan Profiles

| Profile | Duration | What It Runs |
|---------|----------|-------------|
| `quick` | ~30 min | Subdomain enum + DNS + port scan |
| `standard` | 2-3 hrs | Full VAPT: recon, ports, vulns, active testing, AI analysis |
| `deep` | 4-6 hrs | Everything + fuzzing + cloud enum + SAST + container scan |
| `cloud` | 3-4 hrs | AWS/Azure/GCP focus (prowler, checkov, S3 enum) |
| `api_only` | 1-2 hrs | API endpoints, auth testing, fuzzing |
| `container` | 1-2 hrs | Trivy + Checkov + IaC scanning |
| `ai_llm` | 1-2 hrs | LLM prompt injection, model security |
| `mobile` | 2-3 hrs | Mobile API + web backend scanning |
| `custom` | varies | User-defined tool selection |

---

## Security Tools

### Phase 1: Reconnaissance & Vulnerability Scanning

| Tool | Purpose |
|------|---------|
| **subfinder** | Passive subdomain enumeration (40+ sources) |
| **amass** | Active/passive subdomain discovery with DNS brute-force |
| **httpx** | HTTP probing for live hosts, status codes, titles |
| **nmap** | Port scanning + service/version detection |
| **nuclei** | Template-based vulnerability scanner (9000+ CVE/misconfig templates) |
| **nikto** | Web server misconfiguration scanner |
| **shodan** | Internet-wide port intelligence lookup |

### Phase 2: Active Testing

| Tool | Purpose |
|------|---------|
| **sqlmap** | Automated SQL injection detection and exploitation |
| **dalfox** | XSS vulnerability scanner with DOM analysis |
| **ffuf** | Web fuzzer for directories, files, and vhost discovery |
| **wpscan** | WordPress-specific vulnerability scanner |

### Phase 3: Code & Cloud Security

| Tool | Purpose |
|------|---------|
| **semgrep** | Static analysis with custom security rules |
| **gitleaks** | Secrets detection in git history |
| **dependency_scan** | Python dependency vulnerability scanning |
| **trivy** | Container image + filesystem vulnerability scanner |
| **prowler** | AWS/Azure/GCP security posture auditing |
| **checkov** | Infrastructure-as-Code misconfiguration scanner |
| **llm_security** | AI/LLM model prompt injection testing |

---

## CI/CD Integration

Add NETRA to your GitHub Actions pipeline:

```yaml
name: NETRA Security Scan
on:
  pull_request:
    paths: ['src/**', 'package.json']

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run NETRA scan
        run: |
          pip install netra
          netra scan --target ${{ github.server_url }}/${{ github.repository }} \
            --profile standard --output sarif > results.sarif
      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## MCP Server (Claude Desktop)

NETRA exposes all 18 scanner tools as MCP tools for Claude Desktop integration:

```json
{
  "mcpServers": {
    "netra": {
      "command": "python",
      "args": ["-m", "netra.mcp.server"]
    }
  }
}
```

Ask Claude: *"Run a nuclei scan on example.com"* or *"What are the critical findings from the last scan?"*

---

## Configuration

Copy `.env.example` to `.env` and customize:

```bash
# Database (PostgreSQL for production, SQLite for dev)
NETRA_DATABASE_URL=sqlite+aiosqlite:///./netra.db

# AI Provider: anthropic | ollama | none
NETRA_AI_PROVIDER=ollama
NETRA_OLLAMA_BASE_URL=http://localhost:11434
NETRA_OLLAMA_MODEL=llama3.1:8b

# Auth (auto-generated in dev, REQUIRED in production)
NETRA_JWT_SECRET_KEY=your-secret-here

# Scanning
NETRA_DEFAULT_SCAN_PROFILE=standard
NETRA_MAX_CONCURRENT_SCANS=3
```

See [docs/configuration.md](docs/configuration.md) for the full reference.

---

## Project Structure

```
netra/
├── src/netra/           # Python package
│   ├── ai/              # 4-persona AI brain + consensus engine
│   ├── api/             # FastAPI routes, middleware, auth
│   ├── cli/             # Rich TUI command-line interface
│   ├── core/            # Config, security, logging, rate limiting
│   ├── db/              # SQLAlchemy models, migrations, seeds
│   ├── integrations/    # DefectDojo, Jira clients
│   ├── mcp/             # MCP server (Claude Desktop)
│   ├── notifications/   # Slack, email alerting
│   ├── reports/         # 13 report generators
│   ├── scanner/         # Tool wrappers + orchestrator
│   ├── schemas/         # Pydantic request/response models
│   ├── services/        # Business logic layer
│   └── worker/          # Celery tasks + scheduler
├── frontend/            # React 18 + TypeScript + Vite
├── tests/               # pytest (API, models, services, MCP)
├── docs/                # MkDocs documentation site
├── docker/              # Dockerfile + nginx config
├── alembic/             # Database migrations
└── .github/             # CI/CD workflows + issue templates
```

---

## Documentation

| Topic | Link |
|-------|------|
| Installation Guide | [docs/installation.md](docs/installation.md) |
| Configuration Reference | [docs/configuration.md](docs/configuration.md) |
| Scan Profiles | [docs/profiles.md](docs/profiles.md) |
| REST API Reference | [docs/api.md](docs/api.md) |
| AI Agent Guide | [docs/agent.md](docs/agent.md) |
| Compliance Mapping | [docs/compliance.md](docs/compliance.md) |
| Report Formats | [docs/reports.md](docs/reports.md) |
| Dashboard Guide | [docs/dashboard.md](docs/dashboard.md) |
| CI/CD Setup | [docs/cicd.md](docs/cicd.md) |

---

## Requirements

| Requirement | Minimum | Recommended |
|:---|:---|:---|
| **Python** | 3.12+ | 3.12 |
| **OS** | Linux / macOS | Ubuntu 22.04 |
| **RAM** | 8 GB | 16 GB (for local AI models) |
| **Go** | 1.22+ | For building Go-based tools (handled by Docker/install.sh) |
| **Ollama** | latest | Required only if using local AI models |
| **Docker** | 24+ | For production deployment |

---

## Contributing

We welcome contributions. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards (type hints, async/await, SQLAlchemy ORM, pytest), and the PR review process.

```bash
git clone https://github.com/yashwarrdhangautam/netra.git
cd netra
poetry install
pytest                  # Run tests
ruff check src/         # Lint
mypy src/               # Type check
```

---

## Security

Found a vulnerability? Please report privately via [SECURITY.md](SECURITY.md) or email security@netra.dev. Do not open public issues for security vulnerabilities.

---

## License

NETRA is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

Commercial licensing available — contact yashwarrdhangautam@gmail.com.

---

## Acknowledgments

Built on the shoulders of giants: [OWASP](https://owasp.org/), [MITRE ATT&CK](https://attack.mitre.org/), [NVD](https://nvd.nist.gov/), [ProjectDiscovery](https://github.com/projectdiscovery) (nuclei, subfinder, httpx), [Nmap](https://nmap.org/), [Ollama](https://ollama.ai/), and the open-source security community.

---

<p align="center">
  <strong>Made by <a href="https://github.com/yashwarrdhangautam">Yash Wardhan Gautam</a></strong><br/>
  <sub>Securing the digital world, one scan at a time.</sub>
</p>
