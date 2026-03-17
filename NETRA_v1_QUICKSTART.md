# NETRA नेत्र v1 — Open-Source Security Platform

> **No API keys. No cloud lockdown. Just pure open-source security.**

NETRA v1 is a unified security testing platform powered by **local LLMs** (Ollama) and automated analysis. Full VAPT + compliance auditing + multi-agent AI brain, 100% offline.

---

## 🚀 Quick Start (5 minutes)

### 1. Install Ollama + Qwen Model

```bash
# macOS/Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Or download from: https://ollama.ai/download

# Pull the Qwen model (lightweight, fast, great reasoning)
ollama pull qwen:14b

# Start Ollama in background
ollama serve &
```

**Other models** (optional):
```bash
ollama pull llama2       # General-purpose
ollama pull mistral      # Fast, lightweight
ollama pull neural-chat  # Optimized for chat
```

### 2. Install NETRA

```bash
git clone https://github.com/netra-security/netra.git
cd netra

# Install dependencies
pip3 install -r requirements.txt --break-system-packages

# Check external tools
python3 netra.py --check-deps
python3 netra.py --install-deps  # Auto-install nmap, nuclei, etc.
```

### 3. Run Your First Scan

```bash
# Scan a target (fast recon + analysis)
python3 netra.py -t example.com --profile fast

# Full scan (all phases)
python3 netra.py -t example.com --profile balanced --client "Acme Corp"

# Run with custom Ollama model
python3 netra.py -t example.com --profile deep --ai-model mistral
```

### 4. View Results

```bash
# Find the generated reports
ls ~/netra_output/scan_*.html
ls ~/netra_output/findings.db

# Open in browser
open ~/netra_output/scan_XXXX.html  # macOS
firefox ~/netra_output/scan_XXXX.html  # Linux
```

---

## 📋 What's Included

| Component | Details |
|-----------|---------|
| **Recon** | OSINT, subdomain enum, port scanning, web discovery |
| **VAPT** | SQL injection, XSS, SSRF, auth bypass, cloud misconfig |
| **AI Brain** | 4-persona consensus, false positive filtering |
| **Analysis** | CVSS v3.1, attack chain discovery, MITRE mapping |
| **Reports** | HTML, JSON, Word, PDF, Excel, Compliance, Evidence ZIP |
| **Compliance** | CIS, NIST, PCI, HIPAA, SOC2 audit mappings |
| **Database** | SQLite + checkpoint system for resume capability |

---

## ⚙️ Configuration

Edit `~/.netra.conf.yaml` or use CLI flags:

```bash
# Select standards to audit against
python3 netra.py -t example.com \
  --profile balanced \
  --compliance-standards CIS,NIST,PCI \
  --client "Your Company" \
  --engagement "Security Assessment"
```

**Config file** (`config.yaml`):
```yaml
ai:
  ollama_url: "http://localhost:11434"
  ollama_model: "qwen:14b"        # or llama2, mistral, neural-chat
  
compliance:
  standards: ["CIS", "NIST", "PCI", "HIPAA", "SOC2"]
  auto_audit: true
```

---

## 🧠 AI Brain Explained

NETRA uses a **multi-persona consensus system**:

1. **Bug Bounty Hunter** — Focuses on exploitability and chaining
2. **Code Auditor** — Root cause analysis and systemic risk
3. **Pentester** — Business impact and attack narrative
4. **Skeptic** — False positive filter (vetos at 80% confidence)

**Consensus rule**: 3/4 personas must agree to confirm a finding.

**Result**: ~60% fewer false positives than single-model analysis.

---

## 📊 Compliance Auditing

After scanning, NETRA maps findings to compliance controls:

```bash
# Run with compliance auditing enabled
python3 netra.py -t example.com --profile deep --auto-audit

# View audit results in report
open ~/netra_output/scan_XXXX_compliance.pdf
```

**Supported standards**:
- ✅ CIS Benchmarks (Linux, Docker, Kubernetes)
- ✅ NIST Cybersecurity Framework (CSF)
- ✅ PCI-DSS v4.0 (Payment Card Industry)
- ✅ HIPAA §164.312 (Health data protection)
- ✅ SOC2 Type II (Service organization controls)

---

## 🔧 Scanning Modes

```bash
# Fast recon only (30 min)
python3 netra.py -t example.com --only-recon --profile fast

# Pentest only (requires prior recon)
python3 netra.py -t example.com --only-pentest --profile deep

# Resume interrupted scan
python3 netra.py --resume

# Skip AI analysis (faster, no Ollama needed)
python3 netra.py -t example.com --skip-ai

# View database summary
python3 netra.py --status
```

---

## 🛠️ External Tools Used

NETRA calls these tools via subprocess (all optional):

```bash
# Installed via --install-deps
nmap          # Port scanning
nuclei        # Vulnerability scanning
subfinder     # Subdomain enumeration
httpx         # HTTP probing
ffuf          # Fuzzing
amass         # OSINT
gobuster      # Directory brute-force
sqlmap        # SQL injection testing
nikto         # Web server scanning
```

---

## 📝 API Reference (Python)

```python
from netra.core.database import FindingsDB
from netra.ai_brain.consensus import run_consensus_analysis
from netra.ai_brain.config_audit import audit_config

# Load findings DB
db = FindingsDB(db_path="~/netra_output/findings.db")
findings = db.get_findings(scan_id="scan_XXXXX", severity="critical,high")

# Run AI consensus on findings
results = run_consensus_analysis(scan_id="scan_XXXXX", db=db)

# Audit against standard
audit = audit_config("PCI", findings=findings)
```

---

## 🐛 Troubleshooting

### Ollama not responding
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama if stopped
ollama serve &
```

### Model not found
```bash
# Pull the model
ollama pull qwen:14b

# List available models
ollama list
```

### External tools missing
```bash
# Auto-install all tools
python3 netra.py --install-deps

# Or manually install key tools
sudo apt-get install nmap
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Scan hangs on a phase
```bash
# Resume from last checkpoint
python3 netra.py --resume

# Check progress
python3 netra.py --status
```

---

## 📄 License

AGPL-3.0 — Free and open-source.  
Commercial support / licensing available.

---

## 🤝 Contributing

We welcome pull requests!

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📚 Documentation

- **Architecture**: See `_archive/ENGINEERING_SPEC.md`
- **API Docs**: Run `python3 -c "from netra import *; help(netra)"`
- **Compliance mappings**: Check `netra/ai_brain/config_audit.py`

---

## 🔐 Security & Privacy

- ✅ No data sent to cloud
- ✅ No API keys required for core features
- ✅ Local Ollama models (fully offline)
- ✅ SQLite database (audit trail available)
- ✅ AGPL-3.0: Derivative works must be open-source

---

## 💬 Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Security**: Report to security@netra.security

---

**Built with ❤️ for the open-source security community.**

