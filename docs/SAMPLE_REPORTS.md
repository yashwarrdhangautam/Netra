# Sample Reports

NETRA generates 13 report formats. Here's what each includes.

---

## Executive PDF

**For:** C-level leadership, board members

**Includes:**
- Overall risk score (0-10 gauge)
- Severity distribution chart
- Top 5 critical findings with business impact
- 30/60/90 day remediation plan
- Compliance status summary

**Pages:** 8-12  
**Size:** ~2 MB

---

## Technical PDF

**For:** Engineering teams, security engineers

**Includes:**
- Complete findings list
- CVSS v3.1 scores and vectors
- CWE mappings
- Step-by-step reproduction
- Code-level remediation
- AI persona analysis per finding
- Raw tool output excerpts

**Pages:** 40-80  
**Size:** ~8 MB

---

## Interactive HTML

**For:** Developers, self-serve review

**Features:**
- Searchable findings table
- Filter by severity, tool, status
- Click-through CWE/CVE links
- Interactive attack chain graph
- Export to CSV/JSON
- Dark/light mode

**Size:** ~1 MB

---

## Excel Workbook

**For:** Project managers, tracking

**9 Sheets:**
1. Summary (risk score, severity distribution)
2. Findings (complete list)
3. Risk Scorecard
4. MITRE ATT&CK Map
5. Compliance Status
6. CWE Summary
7. Tool Results
8. Remediation Tracker
9. Trends

**Size:** ~3 MB

---

## SARIF

**For:** GitHub Security tab, CI/CD

**Compatible with:**
- GitHub Security tab
- GitLab SAST
- DefectDojo
- Any SARIF 2.1.0 parser

**Size:** ~500 KB

---

## Evidence ZIP

**For:** Auditors, verification, archives

**Includes:**
- SHA-256 manifest
- Chain of custody document
- Raw tool outputs
- Screenshots
- AI analysis JSON files
- All generated reports

**Size:** ~45 MB

---

## Compliance Audit PDF

**For:** Compliance teams, auditors

**Includes:**
- Per-framework compliance status
- Control-by-control pass/fail
- Evidence references
- Gap analysis
- Remediation roadmap

**Frameworks:** CIS, NIST, PCI-DSS, HIPAA, SOC2, ISO 27001

**Pages:** 50-90  
**Size:** ~7 MB

---

## Pentest Report

**For:** Client deliverables

**Includes:**
- Executive summary
- Technical findings
- Methodology description
- Scope definition
- Disclaimer and legal notices
- Custom branding (optional)

**Pages:** 60-100  
**Size:** ~12 MB

---

## Cloud Security Report

**For:** Cloud teams, DevOps

**Includes:**
- AWS/Azure/GCP specific findings
- CIS Cloud Benchmark status
- Misconfiguration details
- IaC scanning results
- Identity and access analysis

**Pages:** 45-75  
**Size:** ~7 MB

---

## API Security Report

**For:** API developers, backend teams

**Includes:**
- OWASP API Top 10 coverage
- Authentication/authorization testing
- Rate limiting validation
- Schema validation results
- Fuzzing outcomes

**Pages:** 30-50  
**Size:** ~5 MB

---

## Delta Report

**For:** Tracking remediation progress

**Includes:**
- Side-by-side scan comparison
- New findings since last scan
- Resolved findings
- Regressions detected
- Risk score change

**Pages:** 35-60  
**Size:** ~5 MB

---

## Word Document

**For:** Customization, editing

**Same content as Technical PDF in editable .docx format.**

**Pages:** 35-70  
**Size:** ~6 MB

---

## Generate Reports

```bash
# All formats
netra report --scan-id <id> --type all --output ./reports

# Specific formats
netra report --scan-id <id> \
  --type executive,technical,sarif \
  --output ./reports

# With custom branding
netra report --scan-id <id> \
  --type pentest \
  --branding-config ./client-branding.yaml
```

---

*Last updated: March 2026 | NETRA v1.0.0*
