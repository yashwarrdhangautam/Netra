# Reports

NETRA generates 11 types of professional security reports.

## Report Types

### 1. Executive (PDF)

**Audience:** Leadership, CISO, non-technical stakeholders

**Contents:**
- Risk grade (A-F)
- Severity distribution chart
- Top 5 critical findings
- Key metrics
- Business impact summary

```bash
netra report --type executive --scan-id abc123
```

### 2. Technical (Word .docx)

**Audience:** Security engineers, developers

**Contents:**
- Cover page with metadata
- Table of contents
- Methodology section
- Detailed findings with evidence
- AI remediation guidance
- Code examples

```bash
netra report --type technical --scan-id abc123
```

### 3. Pentest (PDF)

**Audience:** External clients, compliance auditors

**Contents:**
- Executive summary with risk gauge
- Scope and methodology
- Attack chain narratives
- Detailed findings grouped by severity
- Remediation roadmap
- Appendix with evidence

```bash
netra report --type pentest --scan-id abc123
```

### 4. HTML (Interactive Dashboard)

**Audience:** Internal teams, real-time collaboration

**Features:**
- Self-contained single file
- Sortable/filterable findings table
- Risk score gauge
- Severity distribution chart
- Search functionality
- Dark theme

```bash
netra report --type html --scan-id abc123
```

### 5. Excel (9-Sheet Workbook)

**Audience:** Analysts, data teams

**Sheets:**
1. Summary — Overview and risk score
2. Findings — All findings data
3. Compliance — Framework mappings
4. Assets — Discovered assets
5. Timeline — Scan phases
6. Risk Matrix — Impact/likelihood heatmap
7. Remediation — Prioritized action items
8. Evidence Log — Evidence references
9. Config — Scan configuration

```bash
netra report --type excel --scan-id abc123
```

### 6. Evidence ZIP

**Audience:** Legal, compliance, auditors

**Contents:**
- `manifest.json` — SHA256 hashes of all files
- `chain_of_custody.txt` — Timestamped audit log
- `findings.json` — Complete findings data
- `screenshots/` — Visual evidence
- `tool_outputs/` — Raw tool outputs
- `scan_config.json` — Exact scan configuration

```bash
netra report --type evidence --scan-id abc123
```

### 7. Delta/Diff (PDF)

**Audience:** Teams tracking remediation progress

**Contents:**
- New findings (since last scan)
- Resolved findings
- Changed findings (severity changes)
- Compliance posture change
- Net risk change

```bash
netra report --type delta --scan-a abc123 --scan-b def456
```

### 8. API Security (PDF)

**Audience:** API developers, security teams

**Focus:**
- OWASP API Top 10 coverage
- Endpoint inventory
- Authentication issues
- Injection points
- Rate limiting gaps

```bash
netra report --type api --scan-id abc123
```

### 9. Cloud Security (PDF)

**Audience:** Cloud teams, DevOps

**Focus:**
- CIS benchmark results
- Resource inventory
- IAM findings
- Encryption status
- Network exposure

```bash
netra report --type cloud --scan-id abc123
```

### 10. Compliance Gap (PDF)

**Audience:** Compliance officers, auditors

**Frameworks:**
- ISO 27001
- PCI DSS
- SOC 2
- HIPAA
- NIST CSF
- CIS Controls

**Contents:**
- Control-by-control assessment
- Failed controls with linked findings
- Remediation priority
- Evidence requirements

```bash
netra report --type compliance --scan-id abc123 --framework pci_dss
```

### 11. Full Comprehensive (PDF)

**Audience:** All stakeholders

**Contents:**
- Everything combined
- 100+ pages for large scans
- All findings, all frameworks, all evidence

```bash
netra report --type full --scan-id abc123
```

## Report Location

Reports are saved to `~/.netra/reports/`:

```
~/.netra/reports/
├── executive_abc123.pdf
├── technical_abc123.docx
├── pentest_abc123.pdf
├── report_abc123.html
├── report_abc123.xlsx
├── evidence_abc123.zip
└── ...
```

## API Usage

```bash
# Generate via API
curl -X POST "http://localhost:8000/api/v1/reports/abc123/generate?report_type=executive"

# Download report
curl -O "http://localhost:8000/api/v1/reports/report-id/download"
```

## Next Steps

- [Compliance](compliance.md) — Framework mappings
- [Dashboard](dashboard.md) — Web interface
