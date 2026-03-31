# Use Cases

Real-world workflows for NETRA.

---

## External Attack Surface Assessment

**Goal:** Discover and test all internet-facing assets.

```bash
# Run standard external scan
netra scan --target example.com --profile standard

# Review critical findings with AI analysis
netra findings --scan-id <id> --severity critical --include-ai-analysis

# Generate executive and technical reports
netra report --scan-id <id> --type executive,technical,sarif
```

**Duration:** 2-3 hours  
**Output:** Executive PDF, Technical PDF, SARIF

---

## Client VAPT Deliverables

**Goal:** Generate professional, branded penetration test reports.

```bash
# Run scan with client branding
netra scan --target client.com --profile standard

# Generate branded pentest report
netra report --scan-id <id> --type pentest \
  --branding-config ./client-branding.yaml \
  --output ./client-deliverables
```

**Duration:** 2-3 hours + report customization  
**Output:** Branded Pentest PDF, Evidence ZIP

---

## CI/CD Security Gate

**Goal:** Automated security checks in pull requests.

```yaml
# .github/workflows/security.yml
name: Security Gate
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install netra
      - run: netra scan --target ${{ github.repository }} \
                         --profile quick \
                         --output sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

**Duration:** 30 minutes  
**Output:** SARIF for GitHub Security tab

---

## Cloud Security Posture

**Goal:** Assess AWS/Azure/GCP security configuration.

```bash
# AWS security assessment
netra scan --target aws --profile cloud \
  --aws-profile production \
  --regions us-east-1 us-west-2

# View CIS benchmark status
netra compliance --framework cis-aws --scan-id <id>
```

**Duration:** 3-4 hours  
**Output:** Cloud Security Report, CIS Benchmark Status

---

## Compliance Evidence Mapping

**Goal:** Auto-map findings to SOC2, PCI-DSS, HIPAA controls.

```bash
# Run cloud-focused scan
netra scan --target aws --profile cloud

# Generate compliance gap analysis
netra compliance --scan-id <id> \
  --framework soc2,nist,pci \
  --output compliance-report.pdf
```

**Duration:** 3-4 hours  
**Output:** Compliance Gap Report, Control Mapping Excel

---

## AI-Assisted Triage

**Goal:** Use AI to reduce false positives and prioritize.

```bash
# Run scan with AI validation
netra scan --target example.com \
  --profile standard \
  --ai-provider ollama \
  --ai-model llama3.1:8b

# View only AI-validated findings
netra findings --scan-id <id> --ai-validated --consensus-threshold 3
```

**Duration:** 2-3 hours  
**Output:** AI-validated findings (60% fewer false positives)

---

## Before/After Comparison

**Goal:** Track remediation progress between scans.

```bash
# Run new scan
netra scan --target example.com --profile standard

# Compare with previous scan
netra report --scan-id <new-id> \
  --type delta \
  --compare-with <old-id>
```

**Duration:** 2-3 hours + comparison  
**Output:** Delta Report showing resolved/new findings

---

## Need a Different Workflow?

See [docs/USE_CASES.md](docs/USE_CASES.md) for detailed guides on each use case.
