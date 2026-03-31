# Sample Reports Directory

This directory contains sample report outputs for demonstration purposes.

## Sample Files to Generate

Run NETRA scans and export these sample reports:

### Executive PDF
- [ ] `executive-sample.pdf` - C-level summary report
- Target: scanme.nmap.org
- Profile: quick
- Pages: 8-12

### Technical PDF
- [ ] `technical-sample.pdf` - Full technical findings
- Target: scanme.nmap.org
- Profile: standard
- Pages: 40-60

### Interactive HTML
- [ ] `sample-report.html` - Self-contained HTML report
- Target: scanme.nmap.org
- Profile: quick

### Excel Workbook
- [ ] `sample-workbook.xlsx` - 9-sheet workbook
- Target: scanme.nmap.org
- Profile: standard

### SARIF
- [ ] `results.sarif` - GitHub Security compatible
- Target: scanme.nmap.org
- Profile: quick

### Evidence ZIP
- [ ] `evidence-sample.zip` - Complete evidence package
- Target: scanme.nmap.org
- Profile: quick
- Include: chain-of-custody.pdf

### Compliance PDF
- [ ] `compliance-sample.pdf` - Multi-framework report
- Target: scanme.nmap.org
- Profile: standard
- Frameworks: CIS, NIST, PCI-DSS

### Pentest Report
- [ ] `pentest-sample.pdf` - Client-ready report
- Target: scanme.nmap.org
- Profile: standard
- With branding

### Cloud Security Report
- [ ] `cloud-security-sample.pdf` - CSPM findings
- Target: AWS (demo account)
- Profile: cloud

### API Security Report
- [ ] `api-security-sample.pdf` - API testing results
- Target: OWASP CRAPI
- Profile: api_only

### Delta Report
- [ ] `delta-sample.pdf` - Before/after comparison
- Compare: Two scans of same target
- Profile: standard

### Word Document
- [ ] `technical-sample.docx` - Editable format
- Same content as technical PDF

### Full Combined
- [ ] `full-combined-sample.zip` - All formats
- Complete archive

## How to Generate Samples

```bash
# Run a scan for sample generation
netra scan --target scanme.nmap.org --profile standard

# Generate all report formats
netra report --scan-id <scan-id> --type all --output docs/samples

# Rename files to match naming convention
mv docs/samples/executive.pdf docs/samples/executive-sample.pdf
# ... repeat for all formats
```

## Redaction Guidelines

Before committing sample reports:
- [ ] Remove real IP addresses (use 192.0.2.x)
- [ ] Remove real domain names (use example.com)
- [ ] Remove API keys and credentials
- [ ] Remove timestamps that reveal scan dates
- [ ] Check for any PII in findings

## File Size Guidelines

| Report Type | Max Size |
|-------------|----------|
| Executive PDF | 3 MB |
| Technical PDF | 10 MB |
| HTML | 2 MB |
| Excel | 5 MB |
| Evidence ZIP | 50 MB |
| Full Combined | 150 MB |

Compress files if they exceed these limits.

---

*Last updated: March 2026*
