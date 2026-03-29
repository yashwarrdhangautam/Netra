# NETRA नेत्र

> The Third Eye of Security

NETRA is an open-source, AI-augmented unified cybersecurity platform that combines penetration testing, vulnerability management, cloud security posture management (CSPM), compliance automation, and AI-powered security testing.

## Quick Start

### Install with pip

```bash
pip install netra
netra --help
```

### Run with Docker

```bash
docker compose up -d
# Dashboard: http://localhost:5173
# API: http://localhost:8000/docs
```

## Features

- **14 Security Tools** orchestrated by AI
- **200+ Vulnerability Checks** via Nuclei templates
- **6 Compliance Frameworks** (ISO 27001, PCI DSS, SOC 2, HIPAA, NIST CSF, CIS)
- **11 Report Types** (PDF, Word, Excel, HTML, Evidence ZIP)
- **Autonomous Pentest Agent** with human-in-the-loop
- **CI/CD Integration** with GitHub Actions and SARIF output

## Scan Profiles

| Profile | Description | Duration |
|---------|-------------|----------|
| `quick` | Fast pre-release check | 30 min |
| `standard` | Balanced full scan | 3 hours |
| `deep` | Comprehensive assessment | 12 hours |
| `api_only` | API-focused testing | 2 hours |
| `cloud` | Cloud security posture | 6 hours |
| `container` | Container image scanning | 2 hours |
| `ai_llm` | OWASP LLM Top 10 testing | 1 hour |

## Example Usage

```bash
# Quick scan
netra scan --target example.com --profile quick

# Deep scan with source code analysis
netra scan --target example.com --profile deep --source /path/to/repo

# Cloud security audit
netra scan --target aws --profile cloud

# Generate executive report
netra report --type executive --scan-id <ID>

# Compliance gap analysis
netra compliance --framework pci --scan-id <ID>
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      NETRA Platform                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐ │
│  │  CLI    │  │Dashboard│  │   API   │  │  MCP Server     │ │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────────┬────────┘ │
│       │            │            │                 │          │
│       └────────────┴────────────┴─────────────────┘          │
│                            │                                  │
│                    ┌───────▼───────┐                         │
│                    │  Orchestrator │                         │
│                    └───────┬───────┘                         │
│                            │                                  │
│       ┌────────────────────┼────────────────────┐            │
│       │                    │                    │            │
│  ┌────▼────┐        ┌─────▼─────┐       ┌──────▼──────┐     │
│  │  Tools  │        │ AI Brain  │       │  Compliance │     │
│  │ (14+)   │        │ (4 personas)│      │  Engine     │     │
│  └─────────┘        └───────────┘       └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Documentation

- [Installation Guide](installation.md)
- [Configuration](configuration.md)
- [Scan Profiles](profiles.md)
- [API Reference](api.md)
- [Autonomous Agent](agent.md)

## License

AGPL-3.0 — Open Source
