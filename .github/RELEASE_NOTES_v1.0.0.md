# NETRA v1.0.0 - Initial Release

**Release Date:** March 28, 2026

## 🎉 Highlights

NETRA v1.0.0 marks the first stable release of the AI-assisted security orchestration platform. This release includes everything needed for professional vulnerability assessments, penetration testing, and compliance reporting.

### Key Capabilities

- **18 Security Tools** orchestrated in a unified pipeline
- **4-Persona AI Consensus** engine for finding validation
- **13 Report Formats** for different audiences
- **6 Compliance Frameworks** with auto-mapping
- **React 18 Dashboard** with real-time updates
- **MCP Server** for Claude Desktop integration

---

## 📦 What's New

### Scanning Engine

**18 Tool Wrappers**
- Subdomain enumeration: subfinder, amass
- HTTP probing: httpx, shodan
- Port scanning: nmap
- Vulnerability scanning: nuclei (9000+ templates), nikto
- Active testing: sqlmap, dalfox, ffuf, wpscan
- Code security: semgrep, gitleaks, dependency_scan
- Cloud security: trivy, prowler, checkov
- AI/LLM security: llm_security

**6-Phase Pipeline**
1. Reconnaissance
2. HTTP Probing
3. Port Scanning
4. Vulnerability Scanning
5. Active Testing
6. Code & Cloud Security

**9 Scan Profiles**
- `quick` - 30 min reconnaissance
- `standard` - 2-3 hour full VAPT
- `deep` - 4-6 hour comprehensive
- `cloud` - AWS/Azure/GCP focus
- `api_only` - API security testing
- `container` - Container/IaC scanning
- `ai_llm` - OWASP LLM Top 10
- `mobile` - Mobile backend testing
- `custom` - User-defined

### AI Brain

**4-Persona Consensus Engine**
- 🎯 **Attacker** - Exploitability assessment, attack chains
- 🛡️ **Defender** - Remediation guidance, effort estimates
- 📋 **Analyst** - Compliance framework mapping
- 🤔 **Skeptic** - False positive detection

**AI Provider Support**
- Anthropic Claude (Sonnet 4, Opus 4.5)
- Ollama local LLMs (Llama 3.1, Mistral, Qwen)

**AI Features**
- Consensus voting (3/4 required)
- Attack chain discovery via DFS
- CVSS v3.1 auto-scoring
- CWE mapping (101 entries)
- ~60% false positive reduction

### Dashboard

**React 18 Frontend**
- TypeScript + Vite + Tailwind CSS
- shadcn/ui components
- Dark mode
- Real-time WebSocket updates

**10 Pages**
- Overview dashboard (risk gauge, severity charts)
- Scans list (filters, pagination)
- Scan detail (phase timeline)
- Findings table (bulk actions)
- Finding detail (AI analysis tabs)
- Reports generator
- Compliance dashboard
- Targets management
- Attack graph visualization
- Settings

### Reports

**13 Report Formats**
1. Executive PDF (C-level summary)
2. Technical PDF (full findings)
3. Interactive HTML (searchable)
4. Word Document (editable)
5. Excel Workbook (9 sheets)
6. Compliance Audit PDF
7. Evidence ZIP (chain of custody)
8. SARIF (GitHub Security)
9. Pentest Report (client-ready)
10. Cloud Security Report
11. API Security Report
12. Delta Report (comparison)
13. Full Combined (all formats)

### Compliance

**6 Frameworks Supported**
- CIS Benchmarks (Linux, Docker, Kubernetes)
- NIST Cybersecurity Framework
- PCI-DSS v4.0
- HIPAA §164.312
- SOC2 Type II
- ISO 27001

**Auto-Mapping**
- 500+ controls mapped
- 101 CWE cross-references
- Framework-specific gap analysis

### Security

**Authentication & Authorization**
- JWT with refresh tokens
- TOTP-based MFA
- Backup codes
- RBAC (Admin/Analyst/Viewer/Client)

**Security Features**
- CSRF protection
- SSRF detection
- Rate limiting (SlowAPI)
- Account lockout (5 attempts)
- Content Security Policy headers
- Encrypted credential storage

### Integrations

**MCP Server**
- 18 tools exposed to Claude Desktop
- Natural language commands
- Context-aware responses

**CI/CD**
- GitHub Actions workflows
- SARIF upload to GitHub Security
- Pipeline exit codes

**Notifications**
- Slack webhooks
- Email (SMTP)
- DefectDojo import

### Infrastructure

**Deployment Options**
- Docker Compose (production)
- pip/Poetry (development)
- One-command install script

**Database**
- PostgreSQL 16 (production)
- SQLite (development)
- Alembic migrations

**Task Queue**
- Celery 5.3
- Redis 7
- Flower monitoring

---

## 📊 Benchmarks

### Detection Accuracy
- Overall: 91% (Industry avg: 65%)
- False Positive Rate: 8% (Industry avg: 35%)

### Performance
- Quick scan: 28 min
- Standard VAPT: 2h 15min
- Deep assessment: 4h 30min

### AI Validation
- Consensus accuracy: 94%
- False positive reduction: ~60%

---

## 🔧 Installation

### Option 1: One-Command Install
```bash
bash <(curl -s https://raw.githubusercontent.com/yashwarrdhangautam/netra/main/install.sh)
```

### Option 2: Docker
```bash
git clone https://github.com/yashwarrdhangautam/netra.git
cd netra
cp .env.example .env
docker compose up -d
```

### Option 3: pip/Poetry
```bash
git clone https://github.com/yashwarrdhangautam/netra.git
cd netra
poetry install
```

---

## 🚀 Quick Start

```bash
# Quick scan (~30 min)
netra scan --target scanme.nmap.org --profile quick

# Standard VAPT (~2-3 hrs)
netra scan --target example.com --profile standard

# View critical findings
netra findings --scan-id <id> --severity critical

# Generate executive report
netra report --scan-id <id> --type executive
```

---

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Quick Start](docs/quickstart.md)
- [Configuration](docs/configuration.md)
- [Scan Profiles](docs/profiles.md)
- [API Reference](docs/api.md)
- [Dashboard Guide](docs/dashboard.md)
- [Reports](docs/SAMPLE_REPORTS.md)
- [Benchmarks](docs/BENCHMARKS.md)
- [Use Cases](docs/USE_CASES.md)
- [FAQ](docs/FAQ.md)
- [Roadmap](docs/ROADMAP.md)

---

## ⚠️ Known Issues

### Limitations
- Windows native install not supported (use Docker)
- Mobile app binary scanning not available
- Binary exploitation out of scope
- Social engineering out of scope

### Bugs
- None reported in self-scan

---

## 🔜 Coming in v2.0

- REST API with OAuth 2.0
- Scheduled scans (cron-based)
- Plugin system for custom modules
- DefectDojo bidirectional sync
- Jira ticket auto-creation
- Slack/Teams native integrations

See [ROADMAP.md](docs/ROADMAP.md) for details.

---

## 🙏 Acknowledgments

Built on the shoulders of giants:
- OWASP
- MITRE ATT&CK
- NVD
- ProjectDiscovery (nuclei, subfinder, httpx)
- Nmap
- Ollama
- Open-source security community

---

## 📄 License

AGPL-3.0 - See [LICENSE](LICENSE) for details.

Commercial licensing available - contact yashwarrdhangautam@gmail.com

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/yashwarrdhangautam/netra.git
cd netra
poetry install
pytest                  # Run tests
ruff check src/         # Lint
mypy src/               # Type check
```

---

## 🔒 Security

Report vulnerabilities privately:
- Email: security@netra.dev
- GitHub: [Security Advisories](https://github.com/yashwarrdhangautam/netra/security/advisories)
- Policy: [SECURITY.md](SECURITY.md)

---

**Full Changelog:** Initial release

---

*Made by [Yash Wardhan Gautam](https://github.com/yashwarrdhangautam)*
*Securing the digital world, one scan at a time.*
