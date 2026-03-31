# NETRA FAQ

Frequently asked questions about NETRA, covering installation, usage, features, troubleshooting, and more.

---

## Table of Contents

- [General](#general)
- [Installation](#installation)
- [Scanning](#scanning)
- [AI Features](#ai-features)
- [Reports](#reports)
- [Compliance](#compliance)
- [Dashboard](#dashboard)
- [Integrations](#integrations)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Licensing](#licensing)

---

## General

### What is NETRA?

NETRA is an AI-assisted security orchestration platform that combines reconnaissance, vulnerability scanning, AI-powered validation, compliance mapping, and executive-ready reporting in a single automated workflow.

The name "NETRA" (नेत्र) means "eye" or "third eye" in Sanskrit, reflecting its purpose as the third eye of security.

### Who is NETRA for?

NETRA is designed for:
- **Security engineers** conducting penetration tests
- **AppSec teams** managing application security programs
- **Security consultants** delivering client assessments
- **DevSecOps engineers** integrating security into CI/CD
- **MSSPs** providing security services to clients
- **Compliance teams** preparing for audits

### Is NETRA free?

Yes, NETRA is open-source under the AGPL-3.0 license. You can:
- Use it for personal and commercial projects
- Modify and distribute the code
- Contribute improvements back

**Commercial licensing** is available for organizations that cannot comply with AGPL requirements. Contact yashwarrdhangautam@gmail.com for details.

### How does NETRA compare to [X]?

| Competitor | NETRA Advantage |
|------------|-----------------|
| **Burp Suite** | NETRA orchestrates 18+ tools, validates with AI, maps to compliance, generates 13 report formats |
| **Nuclei** | NETRA includes nuclei but adds orchestration, AI validation, dashboards, and reporting |
| **Metasploit** | NETRA focuses on vulnerability discovery and validation, not exploitation |
| **DefectDojo** | NETRA generates findings; DefectDojo tracks them. They complement each other. |
| **Commercial DAST** | NETRA is open-source, AI-enhanced, and includes compliance mapping out of the box |

### What's the difference between NETRA and Shannon?

Both are AI-powered security tools, but:
- **Shannon** focuses on autonomous white-box pentesting with exploit generation
- **NETRA** focuses on security orchestration, AI validation, compliance mapping, and reporting

They can be complementary in a security program.

---

## Installation

### What are the system requirements?

**Minimum:**
- Python 3.12+
- 8 GB RAM
- 10 GB disk space
- Linux or macOS (Windows via Docker)

**Recommended:**
- Python 3.12
- 16 GB RAM (for local AI models)
- 50 GB disk space
- Ubuntu 22.04 or later
- Docker 24+ (for containerized deployment)

### How do I install NETRA?

**Option 1: One-command install (recommended)**
```bash
bash <(curl -s https://raw.githubusercontent.com/yashwarrdhangautam/netra/main/install.sh)
```

**Option 2: Docker**
```bash
docker compose up -d
```

**Option 3: pip/Poetry**
```bash
git clone https://github.com/yashwarrdhangautam/netra.git
cd netra
poetry install
```

See [docs/installation.md](docs/installation.md) for detailed instructions.

### Does NETRA work on Windows?

NETRA works best on Linux/macOS. For Windows:
- **Recommended:** Use Docker Desktop
- **Alternative:** Use WSL2 with Ubuntu

Native Windows support is planned for v2.0.

### Do I need to install security tools separately?

The `install.sh` script automatically installs most required tools. Docker includes all tools pre-installed.

Tools include: nmap, nuclei, sqlmap, subfinder, amass, httpx, nikto, dalfox, ffuf, semgrep, gitleaks, trivy, prowler, checkov, wpscan, shodan.

### Can I use NETRA without AI features?

Yes. Set `NETRA_AI_PROVIDER=none` in your `.env` file. NETRA will still:
- Run all security scans
- Generate reports
- Map to compliance frameworks

AI validation will be skipped.

---

## Scanning

### How long does a scan take?

| Profile | Duration |
|---------|----------|
| `quick` | ~30 minutes |
| `standard` | 2-3 hours |
| `deep` | 4-6 hours |
| `cloud` | 3-4 hours |
| `api_only` | 1-2 hours |

Actual duration depends on target size, network speed, and tool configuration.

### Can I pause and resume scans?

Yes. NETRA uses checkpoint-based resumption. If a scan is interrupted:
```bash
netra scan --resume --scan-id <interrupted-scan-id>
```

The scan resumes from the last completed phase.

### What targets can I scan?

NETRA can scan:
- **Web applications** (domains, URLs)
- **APIs** (REST, GraphQL endpoints)
- **Networks** (IP ranges, CIDR blocks)
- **Cloud accounts** (AWS, Azure, GCP)
- **Containers** (Docker images)
- **Source code** (repositories, directories)

### Is scanning legal?

**Only scan targets you own or have explicit written authorization to test.**

Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- Similar laws in other jurisdictions

NETRA is a professional security tool. Use it responsibly and legally.

### Can I scan multiple targets at once?

Yes. NETRA supports concurrent scans:
```bash
# Run multiple scans in parallel
netra scan --target example1.com --profile quick &
netra scan --target example2.com --profile quick &
netra scan --target example3.com --profile quick &
```

**Recommended limit:** 3 concurrent scans for optimal performance.

### How do I authenticate to targets?

For authenticated scanning:
```bash
netra scan --target example.com \
  --profile standard \
  --credentials "username:password" \
  --auth-header "Authorization: Bearer <token>"
```

Credentials are encrypted at rest and only used during the scan.

---

## AI Features

### Do I need an API key for AI features?

**Option 1: Anthropic Claude (API key required)**
```bash
NETRA_AI_PROVIDER=anthropic
NETRA_ANTHROPIC_API_KEY=your-key
```

**Option 2: Ollama local LLMs (no API key)**
```bash
NETRA_AI_PROVIDER=ollama
NETRA_OLLAMA_BASE_URL=http://localhost:11434
NETRA_OLLAMA_MODEL=llama3.1:8b
```

**Option 3: No AI**
```bash
NETRA_AI_PROVIDER=none
```

### Which AI models does NETRA support?

**Cloud (API-based):**
- Claude Sonnet 4 (recommended)
- Claude Opus 4.5 (maximum accuracy)

**Local (via Ollama):**
- Llama 3.1 8B
- Mistral 7B
- Qwen 2.5 14B
- Any Ollama-compatible model

### How does the 4-persona consensus work?

Each finding is analyzed by 4 AI personas:

| Persona | Role |
|---------|------|
| 🎯 Attacker | Assesses exploitability and attack chains |
| 🛡️ Defender | Proposes remediation with effort estimates |
| 📋 Analyst | Maps to compliance frameworks |
| 🤔 Skeptic | Challenges evidence quality, flags false positives |

**Consensus requires 3/4 agreement** to confirm a finding. The Skeptic persona alone reduces false positives by ~40%.

### How much does AI analysis cost?

**Claude Sonnet 4:** ~$0.45 per standard scan
**Claude Opus 4.5:** ~$1.20 per standard scan
**Ollama (local):** Free (uses your compute)

Costs vary based on target size and findings count.

### Can AI analysis be wrong?

Yes. AI models can:
- Miss subtle vulnerabilities (false negatives)
- Incorrectly validate false positives
- Provide incomplete remediation guidance

**Always review AI analysis critically.** NETRA's Skeptic persona helps catch errors, but human expertise is essential.

---

## Reports

### What report formats does NETRA generate?

NETRA generates 13 report formats:

| Format | Best For |
|--------|----------|
| Executive PDF | C-level leadership |
| Technical PDF | Engineering teams |
| Interactive HTML | Self-serve developers |
| Word Document | Customization |
| Excel Workbook | Tracking, assignment |
| Compliance Audit PDF | Auditors |
| Evidence ZIP | Verification, archives |
| SARIF | GitHub Security, CI/CD |
| Pentest Report | Client deliverables |
| Cloud Security Report | Cloud teams |
| API Security Report | API developers |
| Delta Report | Before/after comparison |
| Full Combined | Complete archive |

See [docs/SAMPLE_REPORTS.md](docs/SAMPLE_REPORTS.md) for examples.

### Can I customize report branding?

Yes. Create a branding configuration file:
```yaml
# client-branding.yaml
client_name: "Acme Corporation"
logo_path: "./assets/client-logo.png"
color_scheme:
  primary: "#1E40AF"
  secondary: "#3B82F6"
```

Generate branded reports:
```bash
netra report --scan-id <id> \
  --type pentest \
  --branding-config ./client-branding.yaml
```

### How do I compare two scans?

Use the delta report:
```bash
netra report --scan-id <current-id> \
  --type delta \
  --compare-with <previous-id>
```

This shows new findings, resolved findings, and risk score changes.

### Can I automate report generation?

Yes. Reports can be generated via:
- **CLI:** `netra report --scan-id <id> --type all`
- **API:** `POST /api/v1/reports/generate`
- **Dashboard:** One-click generation
- **CI/CD:** Automated in GitHub Actions

---

## Compliance

### Which compliance frameworks does NETRA support?

NETRA maps findings to 6 major frameworks:

| Framework | Controls Mapped |
|-----------|-----------------|
| CIS Benchmarks | 150+ |
| NIST CSF | 85+ subcategories |
| PCI-DSS v4.0 | 100+ requirements |
| HIPAA §164.312 | 20+ safeguards |
| SOC2 Type II | 60+ criteria |
| ISO 27001 | 93+ Annex A controls |

Plus 101 CWE cross-reference mappings.

### Can I add custom compliance frameworks?

Custom framework support is planned for v2.5. Currently, you can:
- Export findings to Excel
- Manually map to custom controls
- Use the Compliance Audit PDF as a template

### Is NETRA compliance mapping audit-ready?

NETRA provides **automated initial mapping** that significantly reduces manual effort. However:
- Final validation should be done by compliance professionals
- Some controls require evidence beyond automated scanning
- NETRA complements but doesn't replace formal compliance audits

---

## Dashboard

### How do I access the dashboard?

**Docker deployment:**
```
http://localhost:5173
```

**Self-hosted:**
```bash
cd frontend && npm run dev
```

Default credentials (change immediately):
- Username: `admin`
- Password: (set via `.env`)

### Can multiple users access the dashboard?

Yes. NETRA supports RBAC with 4 roles:

| Role | Permissions |
|------|-------------|
| Admin | Full access, user management |
| Analyst | Create scans, view findings, generate reports |
| Viewer | Read-only access |
| Client | Limited to assigned scans/reports |

### Does the dashboard update in real-time?

Yes. The dashboard uses WebSocket connections to show:
- Scan progress updates
- New findings as they're discovered
- AI analysis completion
- Report generation status

---

## Integrations

### How do I integrate with GitHub Actions?

Add a workflow file:
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
```

### Can NETRA integrate with Jira?

Jira integration is planned for v2.0. Currently, you can:
- Export findings to JSON/Excel
- Manually create Jira tickets
- Use the Excel workbook for assignment tracking

### How do I set up Slack notifications?

Add to `.env`:
```bash
NETRA_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
NETRA_SLACK_CHANNEL=#security-alerts
```

NETRA will notify on:
- Scan completion
- Critical findings
- Report generation

### What is the MCP server integration?

NETRA exposes 18 security tools as MCP (Model Context Protocol) tools for Claude Desktop.

Configure in Claude Desktop:
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

Then ask Claude: *"Run a nuclei scan on example.com"* or *"What are the critical findings from the last scan?"*

---

## Security

### Is NETRA itself secure?

NETRA follows security best practices:
- Regular self-scanning (zero critical findings in latest scan)
- Dependency audits (clean)
- Secret scanning (clean)
- Security headers enabled
- Rate limiting
- Input validation

Report NETRA vulnerabilities via [SECURITY.md](SECURITY.md).

### How are credentials stored?

Credentials are:
- Encrypted at rest using AES-256
- Stored in the database with encryption keys derived from `NETRA_JWT_SECRET_KEY`
- Never logged or included in reports
- Only decrypted during scan execution

### Can NETRA be used in air-gapped environments?

Yes, with limitations:
- Use Ollama for local AI (no API calls)
- Download tool signatures offline
- Manual report export required
- No automatic updates

Air-gapped deployment guide: [docs/airgap.md](docs/airgap.md) *(coming in v2.0)*

---

## Troubleshooting

### Scan fails with "tool not found"

Ensure tools are installed:
```bash
# Check tool installation
netra tools --check

# Install missing tools
netra tools --install
```

Or use Docker (all tools pre-installed).

### AI analysis is slow

**If using Ollama:**
- Ensure Ollama is running: `ollama serve`
- Pull the model: `ollama pull llama3.1:8b`
- Consider a smaller model for faster responses

**If using Claude:**
- Check API key: `echo $NETRA_ANTHROPIC_API_KEY`
- Verify network connectivity to Anthropic API
- Consider rate limiting on your account

### Dashboard won't load

**Check:**
1. Frontend is running: `docker compose ps`
2. Port 5173 is not in use by another service
3. Browser console for errors

**Fix:**
```bash
docker compose restart frontend
```

### Database errors

**SQLite (development):**
```bash
# Reset database
rm netra.db
alembic upgrade head
```

**PostgreSQL (production):**
```bash
# Check connection
docker compose exec db psql -U netra -c "SELECT 1"

# Run migrations
alembic upgrade head
```

### High memory usage

**Reduce concurrent scans:**
```bash
NETRA_MAX_CONCURRENT_SCANS=2
```

**Use cloud AI instead of local:**
```bash
NETRA_AI_PROVIDER=anthropic
```

**Limit scan scope:**
- Use `--profile quick` for faster scans
- Exclude large IP ranges
- Schedule scans during off-peak hours

---

## Contributing

### How do I contribute to NETRA?

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development environment setup
- Coding standards
- PR submission process
- Issue reporting guidelines

### Can I add new security tools?

Yes! NETRA has a plugin architecture for tool wrappers.

**Steps:**
1. Create tool wrapper in `src/netra/scanner/tools/`
2. Add configuration in `config.yaml`
3. Write tests in `tests/scanner/test_new_tool.py`
4. Submit a PR

See [docs/contributing-tools.md](docs/contributing-tools.md) for detailed guide.

### Can I add new report formats?

Yes! Report generators are modular.

**Steps:**
1. Create generator in `src/netra/reports/`
2. Implement the `ReportGenerator` interface
3. Register in `reports/__init__.py`
4. Submit a PR

---

## Licensing

### What license is NETRA under?

NETRA is licensed under **AGPL-3.0** (GNU Affero General Public License v3.0).

**You can:**
- Use NETRA for personal and commercial projects
- Modify and distribute the code
- Contribute improvements

**You must:**
- Make source code available if you distribute NETRA
- Disclose modifications
- Use the same license for derivatives

### Do I need a commercial license?

You may need a commercial license if:
- You cannot comply with AGPL requirements
- You want to embed NETRA in a proprietary product
- You need indemnification

Contact yashwarrdhangautam@gmail.com for commercial licensing.

### Can I use NETRA for client work?

Yes. AGPL-3.0 allows commercial use. You can:
- Use NETRA for client penetration tests
- Generate and deliver reports to clients
- Charge for your services

**Note:** If you modify NETRA and distribute it to clients, you must make source code available under AGPL.

---

## Still Have Questions?

| Need Help? | Where to Go |
|------------|-------------|
| 📖 Documentation | [docs/](docs/) folder |
| 🐛 Bug Reports | [GitHub Issues](https://github.com/yashwarrdhangautam/netra/issues) |
| 💡 Feature Requests | [GitHub Issues](https://github.com/yashwarrdhangautam/netra/issues) |
| ❓ Questions | [GitHub Discussions](https://github.com/yashwarrdhangautam/netra/discussions) |
| 🔒 Security Issues | [security@netra.dev](mailto:security@netra.dev) |
| 💬 Community | Discord (coming soon) |

---

*Last updated: March 2026 | NETRA v1.0.0*
