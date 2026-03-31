# Use Cases

NETRA fits multiple security workflows. This document provides detailed guidance for common use cases.

---

## Table of Contents

- [External Attack Surface Assessment](#external-attack-surface-assessment)
- [Internal Security Validation](#internal-security-validation)
- [Client-Facing VAPT Reports](#client-facing-vapt-reports)
- [Compliance Evidence Mapping](#compliance-evidence-mapping)
- [DevSecOps CI/CD Integration](#devsecops-cicd-integration)
- [AI-Assisted Vulnerability Triage](#ai-assisted-vulnerability-triage)
- [Cloud Security Posture Assessment](#cloud-security-posture-assessment)
- [API Security Testing](#api-security-testing)

---

## External Attack Surface Assessment

**Goal:** Discover and test all internet-facing assets to identify exploitable vulnerabilities.

### When to Use

- Quarterly external penetration tests
- Pre-acquisition security due diligence
- New product launch security review
- Post-incident external exposure check

### Recommended Profile

```bash
netra scan --target example.com --profile standard
```

### Expected Duration

- **Quick:** 30 minutes (reconnaissance only)
- **Standard:** 2-3 hours (full external VAPT)
- **Deep:** 4-6 hours (includes fuzzing and SAST)

### Workflow

```bash
# 1. Run standard external scan
netra scan --target example.com \
  --profile standard \
  --exclude-ports 80,443 \
  --rate-limit 100

# 2. Monitor progress
netra status --scan-id <scan-id> --watch

# 3. Review critical findings with AI analysis
netra findings --scan-id <scan-id> \
  --severity critical \
  --include-ai-analysis

# 4. Generate executive and technical reports
netra report --scan-id <scan-id> \
  --type executive,technical,sarif \
  --output ./reports/external-assessment
```

### Expected Outputs

| Output | Purpose |
|--------|---------|
| Executive PDF | C-level summary for leadership |
| Technical PDF | Detailed findings for engineering |
| SARIF | Upload to GitHub Security tab |
| Evidence ZIP | Raw tool outputs for verification |

### Key Metrics

- Subdomains discovered
- Live hosts identified
- Open ports found
- Vulnerabilities by severity
- False positives filtered by AI
- Compliance controls impacted

---

## Internal Security Validation

**Goal:** Test internal network, applications, and systems for security gaps.

### When to Use

- Internal network segmentation testing
- Pre-production environment validation
- Employee workstation security checks
- Post-remediation verification

### Recommended Profile

```bash
netra scan --target internal-network \
  --profile deep \
  --source ./src \
  --credentials "domain\\user:password"
```

### Expected Duration

- **Standard:** 3-4 hours (internal network)
- **Deep:** 6-8 hours (includes SAST and fuzzing)

### Workflow

```bash
# 1. Run deep internal scan with credentials
netra scan --target 10.0.0.0/24 \
  --profile deep \
  --source /path/to/codebase \
  --credentials "admin:SecurePass123" \
  --internal-mode

# 2. Compare with previous scan
netra report --scan-id <new-scan-id> \
  --type delta \
  --compare-with <previous-scan-id>

# 3. Export findings for ticketing
netra findings --scan-id <scan-id> \
  --format json \
  --output findings.json

# 4. Create Jira tickets for critical items
netra integrate jira \
  --findings findings.json \
  --project SEC \
  --severity-filter critical,high
```

### Expected Outputs

| Output | Purpose |
|--------|---------|
| Delta Report | Before/after comparison |
| JSON Export | Import to ticketing system |
| Technical PDF | Engineering remediation guide |
| Excel Workbook | Tracking and assignment |

---

## Client-Facing VAPT Reports

**Goal:** Generate professional, branded penetration test reports for clients.

### When to Use

- Consultant delivering pentest engagement
- MSSP providing security assessments
- Internal team reporting to business units
- Compliance audit deliverables

### Recommended Profile

```bash
netra scan --target client-domain.com --profile standard
```

### Workflow

```bash
# 1. Run scan with client branding
netra scan --target client.example.com \
  --profile standard \
  --branding-config ./client-branding.yaml

# 2. Generate branded reports
netra report --scan-id <scan-id> \
  --type pentest,executive,evidence \
  --output ./client-deliverables \
  --brand client-name

# 3. Create evidence package
netra report --scan-id <scan-id> \
  --type evidence_zip \
  --include-chain-of-custody
```

### Branding Configuration

Create `client-branding.yaml`:

```yaml
client_name: "Acme Corporation"
report_title: "Penetration Test Report"
prepared_for: "Acme Corporation Security Team"
prepared_by: "Your Company Name"
date_format: "DD MMMM YYYY"
logo_path: "./assets/client-logo.png"
color_scheme:
  primary: "#1E40AF"
  secondary: "#3B82F6"
disclaimer: |
  This report is confidential and intended solely for...
```

### Expected Outputs

| Output | Purpose |
|--------|---------|
| Branded Pentest PDF | Client deliverable |
| Executive Summary | Leadership briefing |
| Evidence ZIP | Raw findings with SHA-256 manifest |
| Certificate | Completion certificate (custom) |

---

## Compliance Evidence Mapping

**Goal:** Automatically map security findings to compliance framework controls.

### When to Use

- SOC 2 Type II audit preparation
- PCI-DSS annual assessment
- HIPAA security rule compliance
- ISO 27001 certification
- NIST CSF maturity assessment

### Recommended Profile

```bash
netra scan --target environment --profile cloud
```

### Workflow

```bash
# 1. Run cloud-focused scan
netra scan --target aws \
  --profile cloud \
  --aws-profile production \
  --regions us-east-1 us-west-2

# 2. Generate compliance gap analysis
netra compliance --scan-id <scan-id> \
  --framework soc2,nist,pci \
  --output compliance-report.pdf

# 3. Export control mapping
netra compliance --scan-id <scan-id> \
  --framework cis-aws \
  --format excel \
  --output control-mapping.xlsx

# 4. Generate evidence package
netra report --scan-id <scan-id> \
  --type compliance_audit \
  --frameworks soc2,pci \
  --output audit-evidence/
```

### Supported Frameworks

| Framework | Controls Mapped | Output Format |
|-----------|-----------------|---------------|
| CIS Benchmarks | 150+ | Excel, PDF |
| NIST CSF | 85+ subcategories | Excel, PDF |
| PCI-DSS v4.0 | 100+ requirements | Excel, PDF |
| HIPAA §164.312 | 20+ safeguards | Excel, PDF |
| SOC2 Type II | 60+ criteria | Excel, PDF |
| ISO 27001 | 93+ Annex A controls | Excel, PDF |

### Expected Outputs

| Output | Purpose |
|--------|---------|
| Compliance Gap Report | Identify control deficiencies |
| Control Mapping Excel | Auditor evidence tracker |
| Framework PDF | Per-framework compliance status |
| Evidence ZIP | Raw findings linked to controls |

---

## DevSecOps CI/CD Integration

**Goal:** Automate security scanning in CI/CD pipelines with gated deployments.

### When to Use

- Pull request security checks
- Pre-deployment security gates
- Nightly security regression tests
- Release candidate validation

### Recommended Profile

```bash
netra scan --target application --profile quick
```

### GitHub Actions Example

```yaml
# .github/workflows/security-gate.yml
name: Security Gate

on:
  pull_request:
    paths: ['src/**', 'package.json', 'requirements.txt']
  push:
    branches: [main, develop]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install NETRA
        run: pip install netra
      
      - name: Run security scan
        run: |
          netra scan --target ${{ github.server_url }}/${{ github.repository }} \
            --profile quick \
            --output sarif > results.sarif
        env:
          NETRA_AI_PROVIDER: none  # Skip AI for speed
      
      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      
      - name: Check for critical findings
        run: |
          CRITICAL=$(jq '.runs[].results[] | select(.level == "error")' results.sarif | wc -l)
          if [ $CRITICAL -gt 0 ]; then
            echo "❌ $CRITICAL critical findings detected"
            exit 1
          fi
          echo "✅ No critical findings"
```

### GitLab CI Example

```yaml
# .gitlab-ci.yml
security-scan:
  stage: test
  image: python:3.12
  script:
    - pip install netra
    - netra scan --target $CI_PROJECT_URL --profile quick
    - netra report --scan-id $(netra scan latest) --type sarif
  artifacts:
    reports:
      sast: netra-results.sarif
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### Expected Outputs

| Output | Purpose |
|--------|---------|
| SARIF | GitHub/GitLab Security tab |
| Exit Code | Pipeline pass/fail gate |
| JSON Report | Custom integrations |
| Slack Notification | Team alert on failures |

---

## AI-Assisted Vulnerability Triage

**Goal:** Use AI consensus to reduce false positives and prioritize remediation.

### When to Use

- Large scan results requiring prioritization
- Consultant reviewing automated scanner output
- Security team overwhelmed with findings
- Pre-report validation of findings

### Recommended Profile

```bash
netra scan --target application --profile standard --ai-provider ollama
```

### Workflow

```bash
# 1. Run scan with AI analysis enabled
netra scan --target example.com \
  --profile standard \
  --ai-provider ollama \
  --ai-model llama3.1:8b

# 2. View AI-validated findings only
netra findings --scan-id <scan-id> \
  --ai-validated \
  --consensus-threshold 3

# 3. Review persona breakdown for specific finding
netra findings --scan-id <scan-id> \
  --finding-id <finding-id> \
  --show-ai-analysis

# 4. Export AI summary for leadership
netra report --scan-id <scan-id> \
  --type executive \
  --include-ai-summary
```

### AI Persona Breakdown

| Persona | Vote Weight | Focus Area |
|---------|-------------|------------|
| Attacker | 25% | Exploitability, attack chains |
| Defender | 25% | Remediation effort, mitigations |
| Analyst | 25% | Compliance impact, risk scoring |
| Skeptic | 25% | False positive detection, evidence quality |

### Expected Outcomes

| Metric | Without AI | With AI |
|--------|------------|---------|
| False Positives | ~35% | ~8% |
| Triage Time | 4-6 hours | 30-60 min |
| Priority Clarity | Manual | AI-scored |
| Attack Chain Context | None | DFS-mapped |

---

## Cloud Security Posture Assessment

**Goal:** Identify misconfigurations and compliance gaps in cloud infrastructure.

### When to Use

- AWS/Azure/GCP security audits
- Pre-migration security review
- Cloud compliance assessments
- Infrastructure-as-Code validation

### Recommended Profile

```bash
netra scan --target aws --profile cloud
```

### AWS Example

```bash
# 1. Run cloud security assessment
netra scan --target aws \
  --profile cloud \
  --aws-profile production \
  --regions us-east-1 us-west-2 eu-west-1 \
  --services ec2,s3,iam,lambda,rds

# 2. View CIS AWS benchmark status
netra compliance --scan-id <scan-id> \
  --framework cis-aws \
  --format dashboard

# 3. Generate cloud security report
netra report --scan-id <scan-id> \
  --type cloud_security \
  --output cloud-assessment.pdf
```

### Azure Example

```bash
netra scan --target azure \
  --profile cloud \
  --azure-subscription <subscription-id> \
  --services vm,storage,sql,keyvault
```

### GCP Example

```bash
netra scan --target gcp \
  --profile cloud \
  --gcp-project <project-id> \
  --services compute,storage,bigquery,iam
```

### Expected Outputs

| Output | Purpose |
|--------|---------|
| Cloud Security Report | CSPM findings summary |
| CIS Benchmark Status | Per-control pass/fail |
| Misconfiguration List | Prioritized remediation |
| IaC Scan Results | Terraform/CloudFormation issues |

---

## API Security Testing

**Goal:** Test REST, GraphQL, and gRPC APIs for security vulnerabilities.

### When to Use

- API endpoint security validation
- OAuth/OIDC implementation testing
- Rate limiting and authentication checks
- Schema validation testing

### Recommended Profile

```bash
netra scan --target api.example.com --profile api_only
```

### Workflow

```bash
# 1. Run API-focused scan
netra scan --target https://api.example.com \
  --profile api_only \
  --api-spec ./openapi.yaml \
  --auth-bearer "$API_TOKEN"

# 2. Test authentication flows
netra scan --target https://api.example.com \
  --profile api_only \
  --test-auth-flows \
  --oauth-config ./oauth-config.yaml

# 3. Generate API security report
netra report --scan-id <scan-id> \
  --type api_security \
  --output api-assessment.pdf
```

### Expected Outputs

| Output | Purpose |
|--------|---------|
| API Security Report | OWASP API Top 10 coverage |
| Auth Flow Analysis | OAuth/OIDC validation results |
| Schema Validation | OpenAPI/GraphQL schema issues |
| Rate Limit Test | DoS protection validation |

---

## Choosing the Right Use Case

| Your Need | Recommended Profile | Key Output |
|-----------|--------------------|------------|
| External pentest | `standard` | Executive + Technical PDF |
| Internal validation | `deep` | Delta report + JSON export |
| Client deliverable | `standard` | Branded Pentest PDF |
| Compliance audit | `cloud` | Compliance gap analysis |
| CI/CD gate | `quick` | SARIF + exit code |
| Reduce false positives | Any + AI | AI-validated findings |
| Cloud security | `cloud` | CSPM report |
| API testing | `api_only` | API security report |

---

## Need Help?

- 📖 **Documentation:** See [docs/](docs/) for detailed guides
- 💡 **Examples:** Check [docs/samples/](docs/samples/) for sample outputs
- ❓ **Questions:** Open a discussion on [GitHub](https://github.com/yashwarrdhangautam/netra/discussions)
- 🐛 **Issues:** Report bugs on [GitHub Issues](https://github.com/yashwarrdhangautam/netra/issues)
