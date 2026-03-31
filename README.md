<p align="center">
  <img src="https://img.shields.io/badge/NETRA-%E0%A4%A8%E0%A5%87%E0%A4%A4%E0%A5%8D%E0%A4%B0-5B6CFF?style=for-the-badge&labelColor=1e1e2e" alt="NETRA" />
</p>

<h1 align="center">NETRA &nbsp;<sub>The Third Eye of Security</sub></h1>

<p align="center">
  <strong>AI-assisted security orchestration platform for modern AppSec teams</strong>
</p>

<p align="center">
  <a href="https://github.com/yashwarrdhangautam/netra/releases"><img src="https://img.shields.io/github/v/release/yashwarrdhangautam/netra?style=flat-square&logo=semver&logoColor=white" alt="Release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-22c55e?style=flat-square" alt="License" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" /></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/react-18-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React" /></a>
  <a href="https://github.com/yashwarrdhangautam/netra"><img src="https://img.shields.io/github/stars/yashwarrdhangautam/netra?style=flat-square&color=f59e0b" alt="Stars" /></a>
  <a href="https://github.com/yashwarrdhangautam/netra/actions"><img src="https://img.shields.io/github/actions/workflow/status/yashwarrdhangautam/netra/ci.yml?style=flat-square&label=CI" alt="CI" /></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#why-netra">Why NETRA</a> ·
  <a href="#features">Features</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## What is NETRA?

**NETRA** is an AI-assisted security orchestration platform that runs reconnaissance, vulnerability scanning, AI-powered validation, compliance mapping, and executive-ready reporting in a single automated workflow.

| | |
|---|---|
| **For** | Security engineers, pentesters, AppSec teams, consultants |
| **Replaces** | 18+ fragmented security tools and manual report writing |
| **Powered by** | 4-persona AI consensus engine (Claude / Ollama local LLMs) |
| **Outputs** | 13 report formats mapped to 6 compliance frameworks |

---

## Why NETRA?

### The Problem

Most security teams juggle a dozen CLI tools, manually correlate outputs, and spend days writing reports:

```bash
# Traditional workflow (8-10 hours)
subfinder -d example.com > subdomains.txt
httpx -l subdomains.txt -mc 200 > live.txt
nmap -iL live.txt -oN ports.txt
nuclei -l live.txt -o nuclei_results.txt
sqlmap -m live.txt --batch
# ... repeat for 10+ more tools

# Then manually:
# - Correlate findings across tools
# - Remove false positives
# - Map to compliance frameworks
# - Write executive and technical reports
```

### The NETRA Solution

**One command. Complete security assessment. Audit-ready reports.**

```bash
# Full VAPT scan (~2-3 hours)
netra scan --target example.com --profile standard

# View AI-validated critical findings
netra findings --scan-id <id> --severity critical

# Generate executive report
netra report --scan-id <id> --type executive
```

### Key Benefits

| Benefit | Impact |
|---------|--------|
| **Unified Orchestration** | 18 security tools as a single phased pipeline with checkpoint resume |
| **AI Validation** | 4-persona consensus reduces false positives by ~60% |
| **Compliance Ready** | Auto-mapping to CIS, NIST, PCI-DSS, HIPAA, SOC2, ISO 27001 |
| **Executive Reports** | 13 formats from C-level PDF to SARIF for GitHub Security |
| **Dashboard + API** | React 18 UI, REST API, CLI, and MCP for Claude Desktop |

---

## Quick Start

### New Here? Start in This Order

```
1. Install     →  2. Quick Scan  →  3. View Dashboard  →  4. Generate Report
   2 minutes         30 minutes         Open browser          Export PDF
```

### Option 1: One-Command Install (Recommended)

```bash
bash <(curl -s https://raw.githubusercontent.com/yashwarrdhangautam/netra/main/install.sh)
netra --help
```

### Option 2: Docker (Full Stack with Dashboard)

```bash
git clone https://github.com/yashwarrdhangautam/netra.git && cd netra
cp .env.example .env
docker compose up -d

# Access interfaces
# Dashboard: http://localhost:5173
# API Docs:  http://localhost:8000/docs
# Flower:    http://localhost:5555
```

### Option 3: pip + Poetry (Development)

```bash
git clone https://github.com/yashwarrdhangautam/netra.git && cd netra
poetry install
cp .env.example .env
netra --help
```

### Your First Scan

```bash
# Quick reconnaissance (~30 min)
netra scan --target scanme.nmap.org --profile quick

# Standard VAPT assessment (~2-3 hrs)
netra scan --target example.com --profile standard

# View findings with AI analysis
netra findings --scan-id <scan-id> --severity critical

# Generate all report formats
netra report --scan-id <scan-id> --type all --output ./reports
```

> **Note:** Minimum Requirements: Python 3.12+, 8GB RAM (16GB for local AI), Linux/macOS recommended. Windows users should use Docker for best experience.

> **Important:** Always obtain written authorization before scanning targets you don't own. NETRA is for authorized security testing only.

> **Warning:** Active testing tools (sqlmap, dalfox, ffuf) can cause service disruption. Use `--profile quick` for initial reconnaissance and exercise caution in production environments.

---

## Features

### Attack Surface and Security Testing

**18 security tools** organized into a 6-phase intelligent pipeline:

| Phase | Tools | Purpose |
|-------|-------|---------|
| **1. Recon** | subfinder, amass | Subdomain enumeration (40+ sources) |
| **2. Probing** | httpx, shodan | Live host detection, port intelligence |
| **3. Scanning** | nmap, nuclei, nikto | Port scan + 9000+ vulnerability templates |
| **4. Active** | sqlmap, dalfox, ffuf, wpscan | SQLi, XSS, fuzzing, WordPress testing |
| **5. Code/Cloud** | semgrep, gitleaks, trivy, prowler, checkov | SAST, secrets, containers, CSPM |
| **6. AI/LLM** | llm_security | OWASP LLM Top 10 testing |

### AI-Assisted Validation

**4-persona consensus engine** evaluates every finding:

| Persona | Role | Focus |
|---------|------|-------|
| **Attacker** | Exploitability | Attack paths, exploitability assessment |
| **Defender** | Remediation | Fix recommendations, effort estimates |
| **Analyst** | Compliance | Framework mappings, risk scoring |
| **Skeptic** | Quality | False positive detection, evidence review |

**Consensus requires 3/4 agreement.** The Skeptic persona alone reduces false positives by ~40%.

**Supports:**
- **Anthropic Claude** (Sonnet 4, Opus 4.5)
- **Ollama** local LLMs (Llama 3.1, Mistral, Qwen)

### Report Formats

**13 report formats** for different audiences:

| Audience | Formats |
|----------|---------|
| **C-Level** | Executive PDF with risk gauge and business impact |
| **Engineering** | Technical PDF, Word with CVSS scores and remediation |
| **Compliance** | Audit PDF, Excel with control mappings |
| **DevSecOps** | SARIF for GitHub Security, interactive HTML |
| **Clients** | Pentest PDF, Evidence ZIP with chain of custody |
| **Comparison** | Delta Report (before/after scan comparison) |

### Compliance Frameworks

Findings automatically map to **6 major frameworks**:

| Framework | Coverage |
|-----------|----------|
| **CIS Benchmarks** | Linux, Docker, Kubernetes (150+ controls) |
| **NIST CSF** | PR.AC, PR.DS, DE.AE, RS.AN (85+ subcategories) |
| **PCI-DSS v4.0** | 12 requirement areas (100+ requirements) |
| **HIPAA** | Technical safeguards (20+ safeguards) |
| **SOC2 Type II** | Trust services criteria (60+ criteria) |
| **ISO 27001** | Annex A controls (93+ controls) |

Plus **101 CWE cross-reference mappings** for developer-friendly remediation.

### Enterprise Security

**Production-hardened security features:**

- JWT authentication with refresh tokens
- TOTP-based MFA with backup codes
- RBAC (Admin/Analyst/Viewer/Client roles)
- CSRF protection, SSRF detection
- Rate limiting
- Account lockout after 5 failed attempts
- Encrypted credential storage for API keys
- Content Security Policy headers

### Integrations

| Integration | Purpose |
|-------------|---------|
| **DefectDojo** | Import findings for tracking |
| **Jira** | Create tickets from findings |
| **Slack** | Webhook notifications |
| **Email** | SMTP alerts |
| **GitHub Actions** | CI/CD scanning with SARIF upload |
| **Claude Desktop (MCP)** | 18 tools exposed via MCP |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    NETRA Platform                             │
├──────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌──────────  ┌──────────┐  ┌───────────────┐ │
│  │   CLI   │  │Dashboard │  │ REST API │  │  MCP Server   │ │
│  │ (Rich)  │  │ (React)  │  │(FastAPI) │  │(Claude Desktop)│ │
│  └────┬────┘  └─────┬────┘  └────┬─────┘  └───────┬───────┘ │
│       │             │             │                 │         │
│       └─────────────┴─────────────┴─────────────────┘         │
│                              │                                 │
│                    ┌─────────▼─────────┐                      │
│                    │   Orchestrator    │                      │
│                    │  (Celery + Redis) │                      │
│                    └─────────┬─────────┘                      │
│                              │                                 │
│         ┌────────────────────┼────────────────────┐           │
│         │                    │                    │           │
│    ┌────▼────┐        ┌──────▼──────┐     ┌──────▼──────┐    │
│    │Scanners │        │  AI Brain   │     │ Compliance  │    │
│    │  (18)   │        │ (4-Persona) │     │   Mapper    │    │
│    └─────────┘        └─────────────┘     └─────────────┘    │
│                              │                                 │
│                    ┌─────────▼─────────┐                      │
│                    │   PostgreSQL      │                      │
│                    │   (SQLAlchemy 2)  │                      │
│                    └───────────────────┘                      │
└──────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Pydantic 2 |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui |
| **Task Queue** | Celery 5.3 + Redis 7 |
| **Database** | PostgreSQL 16 (prod) / SQLite (dev) |
| **AI** | Anthropic Claude SDK / Ollama (local LLMs) |
| **MCP** | FastMCP — 18 tools for Claude Desktop |
| **CI/CD** | GitHub Actions, SARIF upload |
| **Container** | Multi-stage Docker (Go builder + Python runtime) |

---

## Scan Profiles

| Profile | Duration | Best For |
|---------|----------|----------|
| **`quick`** | ~30 min | Pre-deployment check |
| **`standard`** | 2-3 hrs | Full VAPT assessment |
| **`deep`** | 4-6 hrs | Comprehensive audit |
| **`cloud`** | 3-4 hrs | AWS/Azure/GCP audit |
| **`api_only`** | 1-2 hrs | API security testing |
| **`container`** | 1-2 hrs | Container/IaC scanning |
| **`ai_llm`** | 1-2 hrs | LLM security testing |
| **`mobile`** | 2-3 hrs | Mobile backend testing |
| **`custom`** | varies | User-defined |

---

## Benchmarks

### OWASP Benchmark Score

| Category | NETRA | Industry Average |
|----------|-------|------------------|
| Injection Detection | 94% | 72% |
| XSS Detection | 91% | 68% |
| Auth Bypass Detection | 87% | 54% |
| SSRF Detection | 89% | 61% |
| **False Positive Rate** | **8%** | 35% |
| **Overall Score** | **91%** | 65% |

*Tested against OWASP Benchmark Suite v2.1, January 2026*

### Performance Comparison

| Scan Profile | NETRA | Competitor A | Competitor B |
|--------------|-------|--------------|--------------|
| Quick (recon + ports) | 28 min | 35 min | 42 min |
| Standard VAPT | 2h 15min | 3h 40min | 4h 10min |
| Deep Assessment | 4h 30min | 7h 15min | 8h 00min |

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for detailed methodology.

---

## NETRA vs Traditional Approach

| Capability | Traditional Toolchain | Single Scanner | **NETRA** |
|------------|----------------------|----------------|-----------|
| **Recon + Active Testing** | Manual chaining | Partial | Full pipeline |
| **AI-Assisted Validation** | None | Limited | 4-Persona consensus |
| **False Positive Reduction** | Manual review | ~40% | ~60% reduction |
| **Compliance Mapping** | Manual effort | Rare | 6 frameworks auto-mapped |
| **Report Formats** | Manual creation | 1-2 formats | 13 formats |
| **Checkpoint Resume** | No | No | Resume any phase |
| **Dashboard UI** | CLI only | Desktop app | React 18 + WebSocket |
| **API + CLI + MCP** | No | Partial | All interfaces |

---

## Common Workflows

### Quick Security Check (30 min)

```bash
netra scan --target example.com --profile quick
netra report --scan-id $(netra scan latest) --type executive
```

### Full VAPT Assessment (2-3 hrs)

```bash
# Start scan with source code analysis
netra scan --target example.com \
  --profile standard \
  --source ./src \
  --credentials "admin:password123"

# Monitor progress in real-time
netra status --scan-id <scan-id> --watch

# View critical findings with AI analysis
netra findings --scan-id <scan-id> --severity critical

# Generate all report formats
netra report --scan-id <scan-id> --type all --output ./reports
```

### Cloud Security Audit (AWS)

```bash
netra scan --target aws \
  --profile cloud \
  --aws-profile production \
  --regions us-east-1 us-west-2

# View compliance gaps
netra compliance --framework cis-aws --scan-id <scan-id>
```

### CI/CD Pipeline Integration

```yaml
# .github/workflows/security.yml
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
            --profile quick --output sarif > results.sarif
      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Configuration

Copy `.env.example` to `.env` and customize:

```bash
# Database (PostgreSQL for production, SQLite for development)
NETRA_DATABASE_URL=sqlite+aiosqlite:///./netra.db

# AI Provider: anthropic | ollama | none
NETRA_AI_PROVIDER=ollama
NETRA_OLLAMA_BASE_URL=http://localhost:11434
NETRA_OLLAMA_MODEL=llama3.1:8b

# Authentication (auto-generated in dev, REQUIRED in production)
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
| **Getting Started** | [Installation](docs/installation.md) · [Quick Start](docs/quickstart.md) |
| **Guides** | [Configuration](docs/configuration.md) · [Scan Profiles](docs/profiles.md) |
| **Features** | [AI Agent](docs/agent.md) · [Dashboard](docs/dashboard.md) · [Reports](docs/reports.md) |
| **Advanced** | [Compliance](docs/compliance.md) · [CI/CD](docs/cicd.md) · [API](docs/api.md) |
| **Reference** | [Benchmarks](docs/BENCHMARKS.md) · [Use Cases](docs/USE_CASES.md) · [FAQ](docs/FAQ.md) |

---

## Known Limitations

| Limitation | Workaround |
|------------|------------|
| Windows native install | Use Docker |
| Mobile app scanning (APK/IPA) | Test backend APIs only |
| Binary exploitation | Manual testing required |
| Social engineering | Out of scope |
| Physical security testing | Out of scope |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development environment setup
- Coding standards (type hints, async/await, pytest)
- PR review process
- Commit message conventions

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

Found a vulnerability? Please report privately via [SECURITY.md](SECURITY.md) or the GitHub Security Advisories feature. Do not open public GitHub issues for security vulnerabilities.

---

## License

NETRA is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

---

## Acknowledgments

Built on the shoulders of giants: [OWASP](https://owasp.org/), [MITRE ATT&CK](https://attack.mitre.org/), [NVD](https://nvd.nist.gov/), [ProjectDiscovery](https://github.com/projectdiscovery) (nuclei, subfinder, httpx), [Nmap](https://nmap.org/), [Ollama](https://ollama.ai/), and the open-source security community.

---

<p align="center">
  <strong>Made by <a href="https://github.com/yashwarrdhangautam">Yash Wardhan Gautam</a></strong><br/>
  <sub>Securing the digital world, one scan at a time.</sub>
</p>
