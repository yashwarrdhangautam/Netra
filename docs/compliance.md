# Compliance

NETRA maps findings to 6 major compliance frameworks automatically.

## Supported Frameworks

### ISO 27001:2022

**Coverage:** 93 controls in Annex A

**Key Controls:**
- A.8.24 — Use of cryptography
- A.8.25 — Secure development life cycle
- A.8.28 — Secure coding
- A.5.17 — Authentication information

### PCI DSS v4.0

**Coverage:** 12 requirements with sub-requirements

**Key Requirements:**
- 6.5.1 — Injection flaws
- 6.5.7 — Cross-site scripting
- 8.2 — Strong authentication
- 3.4 — Protect stored cardholder data

### SOC 2

**Coverage:** Trust Services Criteria (CC series)

**Key Criteria:**
- CC6.1 — Logical and Physical Access Controls
- CC6.2 — System Credentials
- CC7.1 — System Monitoring

### HIPAA Security Rule

**Coverage:** Administrative, Physical, Technical safeguards

**Key Safeguards:**
- 164.312(a)(1) — Access Control
- 164.312(c)(1) — Transmission Security
- 164.312(d) — Person or Entity Authentication

### NIST CSF 2.0

**Coverage:** 6 functions (GV, ID, PR, DE, RS, RC)

**Key Categories:**
- PR.AC-01 — Identity and access management
- PR.DS-01 — Data-at-rest protection
- DE.CM-01 — Continuous monitoring

### CIS Controls v8

**Coverage:** 18 control groups

**Key Controls:**
- 16.1 — Secure application development
- 7.1 — Vulnerability management
- 8.1 — Audit log management

## CWE Mappings

NETRA includes 100+ CWE-to-control mappings:

| CWE | Description | Frameworks Mapped |
|-----|-------------|-------------------|
| CWE-89 | SQL Injection | All 6 |
| CWE-79 | XSS | All 6 |
| CWE-287 | Improper Authentication | All 6 |
| CWE-798 | Hardcoded Credentials | All 6 |
| CWE-311 | Missing Encryption | All 6 |
| CWE-200 | Information Exposure | All 6 |

## Usage

### Get Compliance Score

```bash
# PCI DSS score
netra compliance --framework pci_dss --scan-id abc123

# Output:
# Framework: PCI DSS v4.0
# Score: 72.5%
# Status: FAIL
# Failed Controls: 8
```

### Gap Analysis

```bash
# HIPAA gap analysis
netra compliance --framework hipaa --scan-id abc123 --gap-analysis

# Output:
# Total Gaps: 12
# Critical: 2
# High: 4
# Medium: 6
```

### Generate Compliance Report

```bash
# ISO 27001 report
netra report --type compliance --scan-id abc123 --framework iso27001
```

## API Usage

```bash
# Get score
curl "http://localhost:8000/api/v1/compliance/abc123/score/pci_dss"

# Get gap analysis
curl "http://localhost:8000/api/v1/compliance/abc123/gap-analysis/hipaa"

# Map findings to frameworks
curl -X POST "http://localhost:8000/api/v1/compliance/map" \
  -d '{"scan_id": "abc123", "frameworks": ["iso27001", "pci_dss"]}'
```

## Compliance Heatmap

The Dashboard shows a heatmap:

| Framework | Score | Status |
|-----------|-------|--------|
| ISO 27001 | 85% | ✅ Pass |
| PCI DSS | 72% | ❌ Fail |
| SOC 2 | 90% | ✅ Pass |
| HIPAA | 68% | ❌ Fail |
| NIST CSF | 78% | ⚠️ Partial |
| CIS | 82% | ✅ Pass |

## Next Steps

- [Reports](reports.md) — Generate compliance reports
- [Agent](agent.md) — Autonomous compliance testing
