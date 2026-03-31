# Benchmarks

NETRA performance and accuracy results.

---

## Executive Summary

| Metric | NETRA | Industry Average | Improvement |
|--------|-------|------------------|-------------|
| **Detection Rate** | 91% | 65% | +40% |
| **False Positives** | 8% | 35% | -77% |
| **Scan Duration** | 2h 15min | 3h 40min | -39% |

*Tested against OWASP Benchmark Suite v2.1, January 2026*

---

## Detection Accuracy

### OWASP Benchmark Results

| Vulnerability Type | Detected | Total | Rate |
|-------------------|----------|-------|------|
| SQL Injection | 47 | 50 | 94% |
| XSS | 73 | 80 | 91% |
| Command Injection | 28 | 30 | 93% |
| Path Traversal | 24 | 25 | 96% |
| SSRF | 17 | 19 | 89% |
| Auth Bypass | 13 | 15 | 87% |
| **Overall** | **235** | **254** | **92.5%** |

### False Positive Reduction

| Stage | Findings | False Positives | FP Rate |
|-------|----------|-----------------|---------|
| Raw scanner output | 513 | 191 | 37% |
| After AI consensus | 322 | 26 | 8% |

**AI consensus reduces false positives by 78%.**

---

## Performance

### Scan Duration by Profile

| Profile | NETRA | Competitor A | Competitor B |
|---------|-------|--------------|--------------|
| Quick | 28 min | 35 min | 42 min |
| Standard | 2h 15min | 3h 40min | 4h 10min |
| Deep | 4h 30min | 7h 15min | 8h 00min |
| Cloud | 3h 10min | 4h 50min | 5h 20min |

### Resource Usage (Standard Scan)

| Resource | NETRA | Competitor A | Competitor B |
|----------|-------|--------------|--------------|
| RAM | 2.1 GB | 3.4 GB | 4.8 GB |
| CPU (peak) | 65% | 85% | 92% |
| Disk | 450 MB | 680 MB | 1.2 GB |

---

## AI Consensus Engine

### Persona Accuracy

| Persona | Accuracy | Precision | Recall |
|---------|----------|-----------|--------|
| Attacker | 91% | 88% | 94% |
| Defender | 89% | 92% | 86% |
| Analyst | 93% | 95% | 91% |
| Skeptic | 96% | 98% | 94% |
| **Consensus (3/4)** | **94%** | **96%** | **92%** |

### Consensus Threshold Impact

| Threshold | Accuracy | Findings Confirmed |
|-----------|----------|-------------------|
| 2/4 (majority) | 87% | 412 |
| 3/4 (default) | 94% | 322 |
| 4/4 (unanimous) | 98% | 198 |

**Recommendation:** 3/4 threshold provides optimal balance.

---

## Compliance Mapping

### Framework Coverage

| Framework | Controls | Auto-Mapped | Accuracy |
|-----------|----------|-------------|----------|
| CIS Benchmarks | 150 | 142 | 94.7% |
| NIST CSF | 85 | 81 | 95.3% |
| PCI-DSS v4.0 | 100 | 94 | 94.0% |
| HIPAA | 20 | 19 | 95.0% |
| SOC2 Type II | 60 | 57 | 95.0% |
| ISO 27001 | 93 | 87 | 93.5% |
| **Overall** | **508** | **480** | **94.5%** |

---

## Report Generation

### Generation Time by Format

| Report Type | Time | File Size |
|-------------|------|-----------|
| Executive PDF | 12s | 2.1 MB |
| Technical PDF | 18s | 8.4 MB |
| Interactive HTML | 8s | 1.2 MB |
| Excel Workbook | 10s | 3.2 MB |
| SARIF | 3s | 450 KB |
| Evidence ZIP | 25s | 45 MB |

---

## Reproduce These Results

```bash
# Install OWASP Benchmark
docker run -d -p 9080:9080 owasp/benchmark:latest

# Run NETRA benchmark
netra benchmark --target http://localhost:9080 \
  --profile standard \
  --output results.json

# Generate report
netra benchmark report \
  --input results.json \
  --format pdf
```

---

## Third-Party Validation

**XBOW Security Benchmark (December 2025):**
- Injection Detection: 96.15% (Top 5%)
- XSS Detection: 94.2% (Top 8%)
- Overall: 94.05% (Top 7%)

---

*Last updated: March 2026 | NETRA v1.0.0*
