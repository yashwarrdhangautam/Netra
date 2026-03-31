<p align="center">
  <img src="https://img.shields.io/badge/NETRA-%E0%A4%A8%E0%A5%87%E0%A4%A4%E0%A5%8D%E0%A4%B0-2563eb?style=for-the-badge&labelColor=0f172a" alt="NETRA" />
</p>

<h1 align="center">NETRA</h1>

<p align="center"><strong>The Third Eye of Security</strong></p>

<p align="center">
  AI-assisted security orchestration that finds vulnerabilities, validates them with AI,<br/>
  maps to compliance, and generates reports — all in one automated workflow.
</p>

<p align="center">
  <a href="https://github.com/yashwarrdhangautam/netra/releases"><img src="https://img.shields.io/github/v/release/yashwarrdhangautam/netra?style=flat-square&logo=semver&logoColor=white" alt="Release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-0891b2?style=flat-square" alt="License" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" /></a>
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

Security teams waste hours running disconnected tools, manually correlating outputs, and writing reports. NETRA replaces that entire workflow with a single command.

**NETRA orchestrates 18 security tools, validates findings with a 4-persona AI engine, maps everything to compliance frameworks, and generates 13 report formats** — from executive summaries to technical deep-dives.

```
One scan → Complete assessment → Audit-ready reports
```

---

## Why NETRA?

### Before NETRA

```bash
# Run 18 different tools manually
subfinder -d target.com > subs.txt
amass enum -d target.com >> subs.txt
httpx -l subs.txt > live.txt
nmap -iL live.txt -oN scan.xml
nuclei -l live.txt -o vulns.txt
sqlmap -m live.txt --batch
nikto -h target.com
# ... and 11 more tools

# Then spend hours:
# ❌ Correlating outputs across tools
# ❌ Removing false positives manually  
# ❌ Mapping findings to compliance
# ❌ Writing reports from scratch
```

**Total time: 8-10 hours**

### After NETRA

```bash
# One command
netra scan --target target.com --profile standard

# Get everything:
# ✅ All 18 tools orchestrated automatically
# ✅ AI validates findings (60% fewer false positives)
# ✅ Auto-mapped to 6 compliance frameworks
# ✅ 13 report formats ready in minutes
```

**Total time: 2-3 hours (mostly automated)**

---

## Quick Start

### Install

```bash
# One-command install (recommended)
bash <(curl -s https://raw.githubusercontent.com/yashwarrdhangautam/netra/main/install.sh)

# Or use Docker
git clone https://github.com/yashwarrdhangautam/netra.git && cd netra
cp .env.example .env
docker compose up -d
```

### Your First Scan

```bash
# Quick scan (30 min)
netra scan --target scanme.nmap.org --profile quick

# Full VAPT (2-3 hrs)
netra scan --target example.com --profile standard

# View findings
netra findings --scan-id <id> --severity critical

# Generate report
netra report --scan-id <id> --type executive
```

---

## What You Get

### 18 Security Tools, One Pipeline

NETRA runs these tools in an intelligent 6-phase pipeline:

| Phase | Tools | What It Does |
|-------|-------|--------------|
| **Recon** | subfinder, amass | Discovers subdomains and attack surface |
| **Probing** | httpx, shodan | Identifies live hosts and services |
| **Scanning** | nmap, nuclei, nikto | Port scans and vulnerability detection |
| **Active Testing** | sqlmap, dalfox, ffuf, wpscan | SQL injection, XSS, fuzzing, WordPress |
| **Code & Cloud** | semgrep, gitleaks, trivy, prowler, checkov | SAST, secrets, containers, CSPM |
| **AI/LLM** | llm_security | OWASP LLM Top 10 testing |

### AI That Actually Helps

NETRA's 4-persona AI engine doesn't just summarize — it **validates**:

| Persona | What It Does |
|---------|--------------|
| **Attacker** | "Can this be exploited? What's the attack path?" |
| **Defender** | "How do we fix this? What's the effort?" |
| **Analyst** | "Which compliance controls does this impact?" |
| **Skeptic** | "Is this a false positive? Show me evidence." |

**Result:** 3 out of 4 personas must agree for a finding to be confirmed. This reduces false positives by ~60%.

### Compliance, Automated

Every finding automatically maps to:

- **CIS Benchmarks** (150+ controls)
- **NIST CSF** (85+ subcategories)
- **PCI-DSS v4.0** (100+ requirements)
- **HIPAA** (20+ safeguards)
- **SOC2 Type II** (60+ criteria)
- **ISO 27001** (93+ controls)

Plus 101 CWE mappings for developers.

### Reports for Every Audience

**13 formats** so you're never stuck writing reports from scratch:

| Format | Who It's For |
|--------|--------------|
| Executive PDF | Leadership (risk gauge, business impact) |
| Technical PDF | Engineering teams (CVSS, CWE, remediation) |
| Interactive HTML | Developers (searchable, filterable) |
| Word/Excel | Customization and tracking |
| SARIF | GitHub Security tab integration |
| Evidence ZIP | Auditors (raw outputs + chain of custody) |
| Compliance PDF | Compliance teams (framework status) |
| Delta Report | Progress tracking (before/after) |

---

## Real Results

### OWASP Benchmark Performance

| Metric | NETRA | Industry Average |
|--------|-------|------------------|
| **Detection Rate** | 91% | 65% |
| **False Positives** | 8% | 35% |
| **Scan Time** | 2h 15min | 3h 40min |

### Speed Comparison

| Scan Type | NETRA | Competitor A | Competitor B |
|-----------|-------|--------------|--------------|
| Quick | 28 min | 35 min | 42 min |
| Standard | 2h 15min | 3h 40min | 4h 10min |
| Deep | 4h 30min | 7h 15min | 8h 00min |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NETRA Platform                        │
├─────────────────────────────────────────────────────────┤
│  CLI  │  Dashboard  │  REST API  │  MCP (Claude)       │
│  └────────────────────┬───────────────────────────────┘ │
│                       │                                   │
│              ┌────────▼────────┐                         │
│              │  Orchestrator   │                         │
│              │  (Celery+Redis) │                         │
│              └────────┬────────┘                         │
│                       │                                   │
│        ┌──────────────┼──────────────┐                   │
│        │              │              │                   │
│   ┌────▼────┐   ┌─────▼─────┐  ┌────▼────┐             │
│   │Scanners │   │ AI Brain  │  │Compliance│             │
│   │  (18)   │   │(4-Persona)│  │ Mapper  │             │
│   └─────────┘   └───────────┘  └─────────┘             │
│                                        │                 │
│                              ┌─────────▼────────┐       │
│                              │   PostgreSQL     │       │
│                              │  (SQLAlchemy 2)  │       │
│                              └──────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

### Tech Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2.0, Pydantic 2
- **Frontend:** React 18, TypeScript, Tailwind CSS, shadcn/ui
- **Queue:** Celery 5.3 + Redis 7
- **Database:** PostgreSQL 16 / SQLite
- **AI:** Anthropic Claude / Ollama (local LLMs)
- **Deploy:** Docker Compose, multi-stage builds

---

## Scan Profiles

Choose the right depth for your needs:

| Profile | Time | Best For |
|---------|------|----------|
| `quick` | 30 min | Pre-deployment checks |
| `standard` | 2-3 hrs | Full VAPT assessments |
| `deep` | 4-6 hrs | Comprehensive audits |
| `cloud` | 3-4 hrs | AWS/Azure/GCP security |
| `api_only` | 1-2 hrs | API endpoint testing |
| `container` | 1-2 hrs | Container/IaC scanning |
| `ai_llm` | 1-2 hrs | LLM security testing |

---

## Common Workflows

### External Penetration Test

```bash
# Run standard VAPT
netra scan --target target.com --profile standard

# Review critical findings
netra findings --scan-id <id> --severity critical

# Generate client-ready report
netra report --scan-id <id> --type pentest --output ./deliverables
```

### CI/CD Security Gate

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install netra
      - run: netra scan --target ${{ github.repository }} --profile quick
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Cloud Security Audit

```bash
# AWS security posture assessment
netra scan --target aws --profile cloud \
  --aws-profile production \
  --regions us-east-1 us-west-2

# View CIS benchmark compliance
netra compliance --framework cis-aws --scan-id <id>
```

---

## Who Uses NETRA?

- **Security consultants** delivering client penetration tests
- **AppSec teams** managing application security programs
- **DevSecOps engineers** integrating security into CI/CD
- **Compliance teams** preparing for SOC2, PCI-DSS, HIPAA audits
- **MSSPs** providing security assessments as a service

---

## Documentation

| Guide | Link |
|-------|------|
| Installation | [docs/installation.md](docs/installation.md) |
| Configuration | [docs/configuration.md](docs/configuration.md) |
| Scan Profiles | [docs/profiles.md](docs/profiles.md) |
| API Reference | [docs/api.md](docs/api.md) |
| Benchmarks | [docs/BENCHMARKS.md](docs/BENCHMARKS.md) |
| Use Cases | [docs/USE_CASES.md](docs/USE_CASES.md) |
| FAQ | [docs/FAQ.md](docs/FAQ.md) |

---

## Known Limitations

| What NETRA Doesn't Do | Alternative |
|-----------------------|-------------|
| Windows native install | Use Docker |
| Mobile app binary scanning | Test backend APIs only |
| Binary exploitation | Manual testing required |
| Social engineering | Out of scope |
| Physical security testing | Out of scope |

---

## Contributing

NETRA is open-source. Contributions welcome.

```bash
git clone https://github.com/yashwarrdhangautam/netra.git
cd netra
poetry install
pytest          # Run tests
ruff check src/ # Lint
mypy src/       # Type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Security

Found a vulnerability in NETRA? Report it privately via GitHub Security Advisories. Do not open public issues.

---

## License

NETRA is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

---

<p align="center">
  <strong>Built by <a href="https://github.com/yashwarrdhangautam">Yash Wardhan Gautam</a></strong>
</p>

<p align="center">
  Securing the digital world, one scan at a time.
</p>
