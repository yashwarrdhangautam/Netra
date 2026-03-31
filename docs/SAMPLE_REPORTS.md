# Sample Reports

NETRA generates 13 different report formats for different audiences. This page provides previews and sample downloads for each format.

---

## Quick Reference

| Report Type | Best For | Pages | Format |
|-------------|----------|-------|--------|
| [Executive PDF](#executive-pdf) | C-level, leadership | 8-12 | PDF |
| [Technical PDF](#technical-pdf) | Engineering teams | 40-80 | PDF |
| [Interactive HTML](#interactive-html) | Developers, self-serve | N/A | HTML |
| [Word Document](#word-document) | Customization, editing | 35-70 | DOCX |
| [Excel Workbook](#excel-workbook) | Tracking, assignment | 9 sheets | XLSX |
| [Compliance Audit PDF](#compliance-audit-pdf) | Auditors, compliance | 50-90 | PDF |
| [Evidence ZIP](#evidence-zip) | Verification, archives | N/A | ZIP |
| [SARIF](#sarif) | GitHub Security, CI/CD | N/A | JSON |
| [Pentest Report](#pentest-report) | Client deliverables | 60-100 | PDF |
| [Cloud Security Report](#cloud-security-report) | Cloud teams | 45-75 | PDF |
| [API Security Report](#api-security-report) | API developers | 30-50 | PDF |
| [Delta Report](#delta-report) | Before/after comparison | 35-60 | PDF |
| [Full Combined](#full-combined) | Complete archive | 200-400 | ZIP |

---

## Executive PDF

**Audience:** C-level executives, board members, non-technical leadership

**Content:**
- Risk gauge visualization (overall security posture)
- Severity distribution chart
- Top 5 critical findings with business impact
- Priority remediation actions (30/60/90 day plan)
- Compliance status summary
- Trend comparison (if previous scans exist)

**Preview:**

```
┌─────────────────────────────────────────────────────────────┐
│                    NETRA Security Report                     │
│                    Executive Summary                         │
│                                                              │
│  Target: example.com                                         │
│  Date: 28 March 2026                                         │
│  Profile: Standard VAPT                                      │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              OVERALL RISK SCORE                      │    │
│  │                                                       │    │
│  │                    ╭─────╮                           │    │
│  │                  ╱         ╲                         │    │
│  │                ╱    HIGH    ╲                        │    │
│  │               │      7.2     │                       │    │
│  │                ╲             ╱                        │    │
│  │                  ╲         ╱                          │    │
│  │                    ╰─────╯                            │    │
│  │                                                       │    │
│  │  Scale: Low (0-3) | Medium (4-6) | High (7-10)       │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  FINDINGS SUMMARY                                            │
│  ┌──────────┬────────┬──────────┬──────────┬──────────┐    │
│  │ Critical │  High  │  Medium  │   Low    │   Info   │    │
│  ├──────────┼────────┼──────────┼──────────┼──────────┤    │
│  │    2     │   8    │    6     │    2     │    5     │    │
│  └──────────┴────────┴──────────┴──────────┴──────────┘    │
│                                                              │
│  TOP CRITICAL FINDINGS                                       │
│  ─────────────────────                                       │
│  1. SQL Injection in /api/login (CVSS 9.8)                  │
│     Business Impact: Complete database compromise possible  │
│                                                              │
│  2. Authentication Bypass in Admin Panel (CVSS 9.1)         │
│     Business Impact: Unauthorized admin access              │
│                                                              │
│  PRIORITY ACTIONS (30/60/90 Days)                           │
│  ──────────────────────────────                              │
│  30 Days: Patch critical SQL injection, rotate credentials  │
│  60 Days: Implement WAF rules, code review all endpoints    │
│  90 Days: Security training, penetration test remediation   │
│                                                              │
│  COMPLIANCE STATUS                                           │
│  ┌─────────────┬──────────┬──────────┬──────────┐          │
│  │ Framework   │  Pass    │  Fail    │  N/A     │          │
│  ├─────────────┼──────────┼──────────┼──────────┤          │
│  │ CIS         │   89%    │   11%    │    -     │          │
│  │ NIST CSF    │   94%    │    6%    │    -     │          │
│  │ PCI-DSS     │   87%    │   13%    │   25%    │          │
│  └─────────────┴──────────┴──────────┴──────────┘          │
└─────────────────────────────────────────────────────────────┘
```

**Download:** [executive-sample.pdf](samples/executive-sample.pdf) *(2.1 MB)*

---

## Technical PDF

**Audience:** Engineering teams, security engineers, developers

**Content:**
- Complete findings list with full details
- CVSS v3.1 scores and vectors
- CWE mappings with descriptions
- Step-by-step reproduction instructions
- Code-level remediation recommendations
- AI persona analysis for each finding
- Attack chain visualizations
- Raw tool output excerpts

**Preview:**

```
┌─────────────────────────────────────────────────────────────┐
│                    NETRA Technical Report                    │
│                                                              │
│  FINDING #1: SQL Injection in /api/login                    │
│  ─────────────────────────────────────────────────────────  │
│                                                              │
│  SEVERITY: Critical (CVSS 9.8)                              │
│  CWE: CWE-89 (SQL Injection)                                │
│  LOCATION: POST /api/login, parameter: username             │
│  TOOL: sqlmap, nuclei                                       │
│                                                              │
│  CVSS VECTOR:                                               │
│  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H                        │
│  ┌────────┬────────┬────────┬────────┬────────┬────────┐   │
│  │   AV   │   AC   │   PR   │   UI   │   S    │  CIA   │   │
│  ├────────┼────────┼────────┼────────┼────────┼────────┤   │
│  │Network │  Low   │  None  │  None  │Unchanged│  High  │   │
│  └────────┴────────┴────────┴────────┴────────┴────────┘   │
│                                                              │
│  DESCRIPTION:                                               │
│  The /api/login endpoint is vulnerable to SQL injection     │
│  attacks via the 'username' parameter. Attackers can        │
│  execute arbitrary SQL commands to extract, modify, or      │
│  delete database contents.                                  │
│                                                              │
│  REPRODUCTION:                                              │
│  1. Send POST request to /api/login                         │
│  2. Set username parameter to: admin' OR '1'='1           │
│  3. Observe successful login without valid credentials      │
│                                                             │
│  Proof of Concept:                                          │
│  POST /api/login HTTP/1.1                                   │
│  Host: example.com                                          │
│  Content-Type: application/x-www-form-urlencoded            │
│                                                             │
│  username=admin'%20OR%20'1'='1&password=anything            │
│                                                             │
│  AI ANALYSIS (4-Persona Consensus):                         │
│  ─────────────────────────────────────────────────────────  │
│  🎯 Attacker: "Highly exploitable. No auth required.       │
│     Full database access possible. Priority target."        │
│                                                             │
│  🛡️ Defender: "Use parameterized queries. Implement        │
│     input validation. WAF rule as temporary mitigation."    │
│                                                             │
│  📋 Analyst: "Maps to PCI-DSS 6.5.1, OWASP A03:2021.       │
│     Compliance impact: High."                               │
│                                                             │
│  🤔 Skeptic: "Confirmed by sqlmap + nuclei. Evidence       │
│     quality: High. Not a false positive."                   │
│                                                             │
│  CONSENSUS: 4/4 personas agree - VALID FINDING             │
│                                                             │
│  REMEDIATION:                                               │
│  ────────────                                               │
│  1. Replace string concatenation with parameterized queries│
│                                                             │
│     Vulnerable:                                             │
│     query = f"SELECT * FROM users WHERE username='{user}'" │
│                                                             │
│     Fixed:                                                  │
│     cursor.execute("SELECT * FROM users WHERE username=?",  │
│                      (user,))                               │
│                                                             │
│  2. Implement input validation on all user inputs          │
│  3. Apply principle of least privilege to database accounts│
│  4. Consider ORM frameworks (SQLAlchemy, Hibernate)        │
│                                                             │
│  EFFORT ESTIMATE: 2-4 hours                                 │
│  PRIORITY: P0 - Immediate                                   │
│                                                             │
│  COMPLIANCE MAPPINGS:                                       │
│  ┌─────────────┬─────────────────────────────────────────┐ │
│  │ Framework   │ Control                                  │ │
│  ├─────────────┼─────────────────────────────────────────┤ │
│  │ PCI-DSS     │ 6.5.1 - Injection flaws                  │ │
│  │ NIST CSF    │ PR.DS-6 - Data integrity                 │ │
│  │ CIS         │ 5.1.3 - Input validation                 │ │
│  │ OWASP       │ A03:2021 - Injection                     │ │
│  └─────────────┴─────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Download:** [technical-sample.pdf](samples/technical-sample.pdf) *(8.4 MB)*

---

## Interactive HTML

**Audience:** Developers, self-serve teams, interactive review

**Content:**
- Searchable, filterable findings table
- Collapsible AI analysis sections
- Click-through CWE and CVE links
- Interactive attack chain graph
- Export to CSV/JSON buttons
- Dark/light mode toggle

**Features:**
- 🔍 Search findings by keyword
- 🎚️ Filter by severity, tool, status
- 📊 Sort by CVSS, date, tool
- 🔗 Direct links to CWE, CVE, NVD
- 📋 Copy finding details to clipboard
- 📤 Export filtered results

**Preview:**

```
┌─────────────────────────────────────────────────────────────┐
│  NETRA Security Report - Interactive Dashboard              │
│  example.com | 28 March 2026 | Standard VAPT               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [Search findings...]  [Severity ▼] [Tool ▼] [Status ▼]    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 23 FINDINGS                                         │   │
│  ├──────┬───────────────┬─────────┬────────┬──────────┤   │
│  │ ☐    │ Finding       │ CVSS    │ Tool   │ Status   │   │
│  ├──────┼───────────────┼─────────┼────────┼──────────┤   │
│  │ ☐    │ SQL Injection │ 9.8     │ sqlmap │ NEW      │   │
│  │      │ in /api/login │         │ nuclei │          │   │
│  ├──────┼───────────────┼─────────┼────────┼──────────┤   │
│  │ ☐    │ Auth Bypass   │ 9.1     │ nuclei │ REVIEW   │   │
│  │      │ in Admin      │         │        │          │   │
│  ├──────┼───────────────┼─────────┼────────┼──────────┤   │
│  │ ☐    │ XSS in search │ 7.2     │ dalfox │ VERIFIED │   │
│  │      │ field         │         │        │          │   │
│  ├──────┼───────────────┼─────────┼────────┼──────────┤   │
│  │ ☐    │ Open S3       │ 6.5     │ prowler│ NEW      │   │
│  │      │ bucket        │         │        │          │   │
│  └──────┴───────────────┴─────────┴────────┴──────────┘   │
│                                                             │
│  [Export CSV] [Export JSON] [Print] [Share]                │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│  ATTACK CHAIN VISUALIZATION                                 │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│     [Recon] → [Initial Access] → [Privilege Escalation]    │
│        │              │                    │                │
│        ▼              ▼                    ▼                │
│   subfinder       SQL Injection      Admin Bypass          │
│   amass           (CVSS 9.8)         (CVSS 9.1)            │
│                                                             │
│  [Interactive graph - click nodes for details]              │
└─────────────────────────────────────────────────────────────┘
```

**Live Demo:** [View Demo](https://netra.dev/demo-report) *(coming soon)*

**Download:** [sample-report.html](samples/sample-report.html) *(1.2 MB)*

---

## Word Document

**Audience:** Teams needing customization, client report editing

**Content:**
- Same content as Technical PDF
- Fully editable format
- Styles for easy rebranding
- Track changes support
- Comment capability

**Use Cases:**
- Client branding customization
- Internal review and comments
- Legal/compliance review
- Translation workflows

**Download:** [technical-sample.docx](samples/technical-sample.docx) *(5.6 MB)*

---

## Excel Workbook

**Audience:** Project managers, tracking, bulk operations

**Content (9 Sheets):**

| Sheet | Content |
|-------|---------|
| Summary | Risk score, severity distribution |
| Findings | Complete list with all details |
| Risk Scorecard | Per-finding risk calculation |
| MITRE Map | ATT&CK technique mappings |
| Compliance | Framework control status |
| CWE Summary | CWE category breakdown |
| Tool Results | Per-tool finding counts |
| Remediation | Effort estimates, assignments |
| Trends | Comparison with previous scans |

**Preview:**

```
┌─────────────────────────────────────────────────────────────┐
│  NETRA Security Report - Excel Workbook                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Sheet: Findings                                            │
│  ┌────┬───────────┬─────────┬────────┬──────────┬────────┐ │
│  │ #  │ Finding   │ CVSS    │ CWE    │ Tool     │ Status │ │
│  ├────┼───────────┼─────────┼────────┼──────────┼────────┤ │
│  │ 1  │ SQL Inj.  │ 9.8     │ CWE-89 │ sqlmap   │ NEW    │ │
│  │ 2  │ Auth Byp. │ 9.1     │ CWE-287│ nuclei   │ REVIEW │ │
│  │ 3  │ XSS       │ 7.2     │ CWE-79 │ dalfox   │ VERIF. │ │
│  │ 4  │ S3 Open   │ 6.5     │ CWE-284│ prowler  │ NEW    │ │
│  └────┴───────────┴─────────┴────────┴──────────┴────────┘ │
│                                                             │
│  Sheet: Compliance                                          │
│  ┌─────────────┬──────────┬──────────┬──────────┐          │
│  │ Control     │ Status   │ Finding  │ Evidence │          │
│  ├─────────────┼──────────┼──────────┼──────────┤          │
│  │ PCI 6.5.1   │ ❌ Fail  │ SQL Inj. │ #1, #5   │          │
│  │ CIS 5.1.3   │ ⚠️ Partial│ XSS     │ #3       │          │
│  │ NIST PR.DS-6│ ✅ Pass  │ -        │ -        │          │
│  └─────────────┴──────────┴──────────┴──────────┘          │
└─────────────────────────────────────────────────────────────┘
```

**Download:** [sample-workbook.xlsx](samples/sample-workbook.xlsx) *(3.2 MB)*

---

## Compliance Audit PDF

**Audience:** Auditors, compliance teams, regulators

**Content:**
- Per-framework compliance status
- Control-by-control pass/fail
- Evidence references
- Gap analysis
- Remediation roadmap

**Frameworks Included:**
- CIS Benchmarks
- NIST Cybersecurity Framework
- PCI-DSS v4.0
- HIPAA §164.312
- SOC2 Type II
- ISO 27001

**Download:** [compliance-sample.pdf](samples/compliance-sample.pdf) *(6.8 MB)*

---

## Evidence ZIP

**Audience:** Verification, legal, archives

**Content:**
```
evidence-scan-7f3a2b1c.zip
├── MANIFEST.txt           # SHA-256 checksums
├── chain-of-custody.pdf   # Evidence handling log
├── raw-output/
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── nmap.xml
│   ├── nuclei.json
│   ├── sqlmap.log
│   └── ...
├── screenshots/
│   ├── homepage.png
│   ├── login-page.png
│   └── admin-panel.png
├── ai-analysis/
│   ├── finding-1-analysis.json
│   ├── finding-2-analysis.json
│   └── ...
└── reports/
    ├── executive.pdf
    ├── technical.pdf
    └── compliance.pdf
```

**Download:** [evidence-sample.zip](samples/evidence-sample.zip) *(45 MB)*

---

## SARIF

**Audience:** GitHub Security tab, CI/CD pipelines, DevSecOps

**Content:**
- Standard SARIF 2.1.0 format
- GitHub Security tab compatible
- GitLab SAST compatible
- DefectDojo import ready

**Preview:**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "NETRA",
          "version": "1.0.0",
          "informationUri": "https://github.com/yashwarrdhangautam/netra"
        }
      },
      "results": [
        {
          "ruleId": "SQL-INJECTION",
          "level": "error",
          "message": {
            "text": "SQL Injection vulnerability in /api/login endpoint"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "POST /api/login"
                }
              }
            }
          ],
          "properties": {
            "cvss": 9.8,
            "cwe": "CWE-89",
            "severity": "critical"
          }
        }
      ]
    }
  ]
}
```

**Download:** [results.sarif](samples/results.sarif) *(450 KB)*

---

## Pentest Report

**Audience:** Client deliverables, formal engagements

**Content:**
- Executive summary
- Technical findings
- Methodology description
- Scope definition
- Rules of engagement reference
- Disclaimer and legal notices
- About the tester section
- Glossary of terms

**Customization:**
- Client branding (logo, colors)
- Custom disclaimer text
- Engagement-specific methodology
- Tester credentials section

**Download:** [pentest-sample.pdf](samples/pentest-sample.pdf) *(12 MB)*

---

## Cloud Security Report

**Audience:** Cloud teams, DevOps, platform engineers

**Content:**
- AWS/Azure/GCP specific findings
- CIS Cloud Benchmark status
- Misconfiguration details
- IaC scanning results
- Identity and access analysis
- Network security review

**Download:** [cloud-security-sample.pdf](samples/cloud-security-sample.pdf) *(7.2 MB)*

---

## API Security Report

**Audience:** API developers, backend teams

**Content:**
- OWASP API Top 10 coverage
- Authentication/authorization testing
- Rate limiting validation
- Schema validation results
- Fuzzing outcomes
- Business logic testing

**Download:** [api-security-sample.pdf](samples/api-security-sample.pdf) *(4.8 MB)*

---

## Delta Report

**Audience:** Teams tracking remediation progress

**Content:**
- Side-by-side scan comparison
- New findings since last scan
- Resolved findings
- Regressions detected
- Trend analysis
- Risk score change

**Preview:**

```
┌─────────────────────────────────────────────────────────────┐
│                    Delta Report                              │
│              Scan Comparison Summary                         │
│                                                              │
│  Previous Scan: scan-abc123 (15 March 2026)                 │
│  Current Scan:  scan-def456 (28 March 2026)                 │
│                                                              │
│  RISK SCORE TREND                                            │
│  ────────────────────                                        │
│  Previous: 8.1 (High) ──────→ Current: 7.2 (High)           │
│  Improvement: -11%                                           │
│                                                              │
│  FINDINGS CHANGE                                             │
│  ┌──────────┬─────────┬─────────┬──────────┐               │
│  │ Severity │ Previous│ Current │ Change   │               │
│  ├──────────┼─────────┼─────────┼──────────┤               │
│  │ Critical │    4    │    2    │  -2 ✅   │               │
│  │ High     │   12    │    8    │  -4 ✅   │               │
│  │ Medium   │   10    │    6    │  -4 ✅   │               │
│  │ Low      │    5    │    2    │  -3 ✅   │               │
│  └──────────┴─────────┴─────────┴──────────┘               │
│                                                              │
│  NEW FINDINGS (3)                                            │
│  ─────────────────                                           │
│  + XSS in /search (CVSS 6.1)                                │
│  + Missing HSTS header (CVSS 4.3)                           │
│  + Verbose error messages (CVSS 3.7)                        │
│                                                              │
│  RESOLVED FINDINGS (7)                                       │
│  ────────────────────                                        │
│  ✓ SQL Injection patched                                    │
│  ✓ Auth bypass fixed                                        │
│  ✓ S3 bucket secured                                        │
│  ...                                                         │
└─────────────────────────────────────────────────────────────┘
```

**Download:** [delta-sample.pdf](samples/delta-sample.pdf) *(5.4 MB)*

---

## Full Combined

**Audience:** Complete archive, compliance submissions

**Content:**
- All 12 report formats above
- Organized folder structure
- Comprehensive evidence package
- Suitable for regulatory submission

**Download:** [full-combined-sample.zip](samples/full-combined-sample.zip) *(125 MB)*

---

## Generating Reports

### CLI Commands

```bash
# Generate all report formats
netra report --scan-id <id> --type all --output ./reports

# Generate specific formats
netra report --scan-id <id> \
  --type executive,technical,sarif \
  --output ./reports

# Generate with custom branding
netra report --scan-id <id> \
  --type pentest \
  --branding-config ./client-branding.yaml \
  --output ./client-deliverables

# Generate delta report
netra report --scan-id <current-id> \
  --type delta \
  --compare-with <previous-id> \
  --output ./delta-report
```

### API Endpoint

```bash
POST /api/v1/reports/generate
{
  "scan_id": "scan-7f3a2b1c",
  "types": ["executive", "technical", "sarif"],
  "output_dir": "./reports"
}
```

---

## Need Custom Formats?

For enterprise customers, we offer custom report format development:

- 📧 Email: reports@netra.dev
- 📝 Issue: [GitHub](https://github.com/yashwarrdhangautam/netra/issues)

---

*Last updated: March 2026 | NETRA v1.0.0*
