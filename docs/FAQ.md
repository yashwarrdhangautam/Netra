# Frequently Asked Questions

Quick answers to common questions about NETRA.

---

## What is NETRA?

NETRA is an AI-assisted security orchestration platform. It runs 18 security tools in an automated pipeline, validates findings with a 4-persona AI engine, maps to compliance frameworks, and generates 13 report formats.

## Who is it for?

- Security engineers conducting penetration tests
- AppSec teams managing security programs
- Security consultants delivering client assessments
- DevSecOps engineers integrating security into CI/CD
- Compliance teams preparing for audits

## Is NETRA free?

Yes. NETRA is open-source under AGPL-3.0. Free for personal and commercial use.

## How do I install NETRA?

**One-command install:**
```bash
bash <(curl -s https://raw.githubusercontent.com/yashwarrdhangautam/netra/main/install.sh)
```

**Docker:**
```bash
docker compose up -d
```

See [docs/installation.md](docs/installation.md) for details.

## What tools does NETRA run?

18 security tools including:
- Recon: subfinder, amass
- Scanning: nmap, nuclei, nikto
- Active testing: sqlmap, dalfox, ffuf, wpscan
- Code security: semgrep, gitleaks
- Cloud: trivy, prowler, checkov
- AI/LLM: llm_security

## How long does a scan take?

| Profile | Duration |
|---------|----------|
| Quick | 30 min |
| Standard | 2-3 hours |
| Deep | 4-6 hours |
| Cloud | 3-4 hours |

## Do I need API keys for AI features?

No. NETRA works with local Ollama models (free). Anthropic Claude is optional.

```bash
# Local AI (no API key)
NETRA_AI_PROVIDER=ollama

# Or skip AI entirely
NETRA_AI_PROVIDER=none
```

## How does AI validation work?

Four AI personas (Attacker, Defender, Analyst, Skeptic) analyze each finding. Three out of four must agree for a finding to be confirmed. This reduces false positives by ~60%.

## What reports does NETRA generate?

13 formats:
- Executive PDF (C-level summary)
- Technical PDF (engineering details)
- Interactive HTML (searchable)
- Word/Excel (editable)
- SARIF (GitHub Security)
- Evidence ZIP (raw outputs)
- Compliance PDF (framework status)
- Delta Report (before/after)
- And 5 more specialized formats

## Which compliance frameworks are supported?

- CIS Benchmarks
- NIST Cybersecurity Framework
- PCI-DSS v4.0
- HIPAA
- SOC2 Type II
- ISO 27001

## Can I use NETRA in CI/CD?

Yes. NETRA integrates with GitHub Actions, GitLab CI, and Jenkins. Outputs SARIF for GitHub Security tab.

Example:
```yaml
- run: netra scan --target ${{ github.repository }} --profile quick
- uses: github/codeql-action/upload-sarif@v3
```

## Does NETRA work on Windows?

Use Docker for best experience. Native Windows support is planned for v2.0.

## Is scanning legal?

Only scan targets you own or have written authorization to test. NETRA is for authorized security testing only.

## Can NETRA replace my pentester?

No. NETRA augments security professionals by automating repetitive tasks. Human expertise is still essential for complex testing and business context.

## What's the difference between NETRA and Burp Suite?

Burp Suite is a manual testing proxy. NETRA orchestrates 18+ tools, validates with AI, maps to compliance, and generates reports automatically. They complement each other.

## How do I contribute?

```bash
git clone https://github.com/yashwarrdhangautam/netra.git
cd netra
poetry install
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Where can I get help?

- **Documentation:** [docs/](docs/) folder
- **Bug reports:** [GitHub Issues](https://github.com/yashwarrdhangautam/netra/issues)
- **Questions:** [GitHub Discussions](https://github.com/yashwarrdhangautam/netra/discussions)
- **Security issues:** GitHub Security Advisories

---

*Last updated: March 2026 | NETRA v1.0.0*
