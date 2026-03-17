<div align="center">

# NETRA नेत्र
### The Third Eye of Security

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-AGPL%203.0-green)](LICENSE)
[![CI](https://github.com/netra-security/netra/actions/workflows/ci.yml/badge.svg)](https://github.com/netra-security/netra/actions)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20%2B%20Qwen-orange)](https://ollama.ai)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

**Open-source AI-augmented VAPT platform. No API keys. No cloud. 100% local.**

[Quick Start](#-quick-start) • [Features](#-features) • [Docker](#-docker) • [AI Brain](#-ai-brain) • [Compliance](#-compliance) • [Contributing](#-contributing)

</div>

---

## What is NETRA?

NETRA is a unified security testing platform that combines automated VAPT scanning (nmap, nuclei, subfinder, and 12 more tools) with a **local AI brain powered by Ollama + Qwen** — no API keys, no cloud, fully offline. It discovers vulnerabilities, chains them into attack paths, maps them to compliance standards (CIS, NIST, PCI, HIPAA, SOC2), and generates professional reports in 6 formats.

```
Scan → Recon → VAPT → AI Analysis → Attack Chains → Compliance Audit → Reports
       (auto)  (auto) (local LLM)   (graph DFS)     (CIS/NIST/PCI)    (6 formats)
```

---

## 📋 Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | Core runtime |
| Go | 1.22+ | For Go-based tools (subfinder, nuclei, httpx…) — `install.sh` handles this |
| Ollama | latest | Local LLM backend — `install.sh` handles this |
| Qwen 14B | `qwen:14b` | Default AI model (~8GB) — swappable in `config.yaml` |
| OS | Linux / macOS | Windows via Docker |

> **RAM:** 16GB minimum recommended (8GB usable for Qwen 14B + tools). For <16GB use `OLLAMA_MODEL=qwen:7b`.

---

## ⚡ Quick Start

### Option 1: One-command install (recommended)

```bash
git clone https://github.com/netra-security/netra.git
cd netra
bash install.sh
```

`install.sh` handles everything: Python deps, Go tools, Ollama, Qwen model.

### Option 2: Manual install

```bash
# 1. Clone
git clone https://github.com/netra-security/netra.git && cd netra

# 2. Python dependencies
pip3 install -r requirements.txt --break-system-packages

# 3. Install Ollama + pull Qwen
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen:14b && ollama serve &

# 4. Install security tools
python3 netra.py --install-deps

# 5. Run your first scan
python3 netra.py -t example.com --profile fast
```

### Option 3: Docker

```bash
docker-compose up -d           # Start NETRA + Ollama
docker-compose exec netra python3 netra.py -t example.com --profile balanced
```

---

## ✨ Features

| Category | What NETRA Does |
|----------|-----------------|
| **Recon** | OSINT, subdomain enumeration (subfinder, amass, assetfinder), DNS resolution, live host discovery |
| **Scanning** | Port scan (nmap, naabu), vulnerability scan (nuclei), web crawl (katana, gau) |
| **Pentest** | SQL injection, XSS, SSRF, auth bypass, API testing, WAF evasion, cloud misconfig |
| **Screenshots** | Playwright headless browser captures every live URL, thumbnails in HTML report |
| **Cloud** | Auto-detect AWS/Azure/GCP, S3 bucket enum, CSPM prompt if cloud found |
| **AI Brain** | 4-persona consensus (Qwen), CVSS scoring, attack chain discovery, MITRE mapping |
| **Compliance** | CIS, NIST, PCI-DSS, HIPAA, SOC2 — findings auto-mapped to controls |
| **Reports** | Interactive HTML, PDF, Word, Excel (9 sheets), Compliance PDF, Evidence ZIP |
| **Resume** | Phase-aware checkpoints — resume any interrupted scan |
| **Database** | SQLite findings DB with full history, deduplication, attack chains |

---

## 🗂 Directory Layout

```
netra/                          ← Repository root
├── netra/                      ← Python package
│   ├── core/                   (config, database, deps, utils, notify, checkpoint)
│   ├── modules/vapt/           (15 scan modules + screenshots + cloud detect)
│   ├── ai_brain/               (personas, consensus, narrative, analyzer, audit)
│   ├── reports/                (word, pdf, html, excel, compliance, evidence_zip)
│   ├── mcp/                    (Claude Desktop — v2)
│   └── tui/                    (terminal UI — v2)
├── netra.py                    ← CLI entry point
├── install.sh                  ← One-command setup
├── Dockerfile                  ← Docker image
├── docker-compose.yml          ← NETRA + Ollama
├── requirements.txt
├── pyproject.toml
└── config.yaml                 ← Config template
```

After first run, data lives here:

```
~/.netra/
├── tools/bin/                  ← All Go tools (no sudo needed)
├── tools/templates/            ← Nuclei templates
├── data/
│   ├── findings.db             ← Master SQLite database
│   └── scans/
│       └── scan_20260317_example.com/
│           ├── reports/        ← HTML, PDF, Word, Excel, ZIP
│           ├── screenshots/    ← Web page screenshots
│           ├── raw/            ← nmap.xml, nuclei.json
│           ├── logs/           ← Per-tool logs
│           └── checkpoint.json
└── logs/                       ← Global logs
```

---

## 🧠 AI Brain

NETRA uses a **multi-persona consensus system** — no API keys needed:

```
Finding → 4 Personas run in parallel (Ollama + Qwen 14B)
           ├── Bug Bounty Hunter  → Is it exploitable? Chain potential?
           ├── Code Auditor       → Root cause? CWE? Systemic risk?
           ├── Pentester          → Business impact? MITRE techniques?
           └── Skeptic            → Is this a false positive?
                    ↓
           3/4 confirm → VALIDATED
           Skeptic 80%+ confident FP → REJECTED
```

**Result**: ~60% fewer false positives vs. single-model analysis.

**Supported models** (swap in config.yaml):

| Model | Size | Speed | Best for |
|-------|------|-------|----------|
| `qwen:14b` | 8GB | Fast | **Default — best balance** |
| `llama2` | 4GB | Faster | Low-RAM systems |
| `mistral` | 4GB | Fastest | Quick triage |
| `neural-chat` | 4GB | Fast | Narrative quality |

---

## 📊 Compliance

After scanning, NETRA auto-maps findings to controls:

```bash
python3 netra.py -t example.com --profile deep
# → generates compliance.pdf with control status tables
```

| Standard | Controls Checked |
|----------|-----------------|
| CIS Benchmarks | Linux, Docker, Kubernetes hardening |
| NIST CSF | PR.AC, PR.DS, DE.AE, RS.AN controls |
| PCI-DSS v4.0 | Network segmentation, encryption, scanning |
| HIPAA §164.312 | Workforce security, access management, PHI |
| SOC2 Type II | Change management, system monitoring |

---

## 🐳 Docker

```bash
# Pull and start
git clone https://github.com/netra-security/netra.git && cd netra
docker-compose up -d

# First run: pull Qwen model into Ollama container
docker-compose exec ollama ollama pull qwen:14b

# Scan
docker-compose exec netra python3 netra.py -t example.com --profile balanced

# View reports
ls ./netra-data/data/scans/
```

---

## 🛠 Tools Bundled in NETRA

NETRA automatically installs all tools to `~/.netra/tools/bin/` — no sudo, no conflicts.

| Tool | Category | What it does |
|------|----------|-------------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Recon | Passive subdomain enumeration via 40+ sources (VirusTotal, Shodan, etc.) |
| [amass](https://github.com/owasp-amass/amass) | Recon | Deep subdomain discovery — DNS brute-force + scraping |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Recon | Fast subdomain finder via cert transparency + APIs |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Recon | DNS resolver — verifies which subdomains are live |
| [httpx](https://github.com/projectdiscovery/httpx) | Recon | HTTP probe — checks live web servers, grabs titles + status codes |
| [gau](https://github.com/lc/gau) | Recon | Fetch all known URLs from Wayback Machine, OTX, URLScan |
| [katana](https://github.com/projectdiscovery/katana) | Recon | Web crawler — finds endpoints, forms, JS files |
| [nmap](https://nmap.org) | Scanning | Port scanner + service/version detection (the industry standard) |
| [naabu](https://github.com/projectdiscovery/naabu) | Scanning | Fast port scanner — complements nmap for speed |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Scanning | Template-based vulnerability scanner (9000+ CVE/misconfig templates) |
| [nikto](https://cirt.net/Nikto2) | Scanning | Web server scanner — checks for dangerous files, outdated software |
| [sqlmap](https://sqlmap.org) | Pentest | Automated SQL injection detection and exploitation |
| [ffuf](https://github.com/ffuf/ffuf) | Pentest | Fast web fuzzer — directory/file brute-force, API endpoint discovery |
| [gobuster](https://github.com/OJ/gobuster) | Pentest | Directory/DNS/S3 brute-forcer |
| [gowitness](https://github.com/sensepost/gowitness) | Screenshots | Headless browser screenshots of web services |
| [subzy](https://github.com/LukaSikic/subzy) | Pentest | Subdomain takeover detection |

**Check tool status:**
```bash
python3 netra.py --check-deps      # shows a status table for every tool
python3 netra.py --install-deps    # installs any missing tools automatically
```

---

## 🔧 Scan Profiles

```bash
python3 netra.py -t example.com --profile fast        # 30 min, recon only
python3 netra.py -t example.com --profile balanced    # 2-3 hrs, full VAPT
python3 netra.py -t example.com --profile deep        # 4-6 hrs, everything
python3 netra.py -t example.com --profile healthcare  # HIPAA focused
python3 netra.py -t example.com --profile saas        # API + auth focus
```

Other flags:

```bash
python3 netra.py --resume              # Resume last scan
python3 netra.py --status              # DB summary table
python3 netra.py --check-deps          # Tool status table
python3 netra.py --install-deps        # Install all tools
python3 netra.py -f targets.txt        # Multi-target from file
python3 netra.py -x assets.xlsx        # Targets from Excel
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

```bash
git checkout -b feature/your-feature
# make changes, add tests
git push origin feature/your-feature
# open a Pull Request
```

---

## 🗺 Roadmap

| Version | Features |
|---------|---------|
| **v1.0** ✅ | VAPT scanning, AI brain (Ollama), compliance audit, 6 report types, screenshots, cloud detect, Docker |
| **v2.0** 🔄 | MCP server (Claude Desktop), REST API, plugin system, DefectDojo integration, scan scheduling |

---

## 📄 License

AGPL-3.0 — Free and open-source.
Commercial licensing: [yashwarrdhangautam@gmail.com](mailto:yashwarrdhangautam@gmail.com)

**Author**: [Yash Wardhan Gautam](https://github.com/yashwardhan-gautam)
