# Scan Profiles

NETRA provides pre-configured scan profiles for different use cases.

## Built-in Profiles

### `quick` — Fast Pre-release Check

**Use case:** CI/CD pipeline, quick validation

| Setting | Value |
|---------|-------|
| Severity Filter | critical, high |
| Max Targets | 20 |
| Rate Limit | 300 req/s |
| Port Range | top-100 |
| Active Testing | No |
| Estimated Duration | 30 minutes |

```bash
netra scan --target example.com --profile quick
```

### `standard` — Balanced Full Scan

**Use case:** Regular security assessments

| Setting | Value |
|---------|-------|
| Severity Filter | critical, high, medium |
| Max Targets | 50 |
| Rate Limit | 150 req/s |
| Port Range | top-1000 |
| Active Testing | Yes (SQLi, XSS) |
| Estimated Duration | 3 hours |

```bash
netra scan --target example.com --profile standard
```

### `deep` — Comprehensive Assessment

**Use case:** Full penetration test, compliance audits

| Setting | Value |
|---------|-------|
| Severity Filter | critical, high, medium, low, info |
| Max Targets | 200 |
| Rate Limit | 50 req/s |
| Port Range | 1-65535 |
| Active Testing | Yes (extensive) |
| SAST | Yes |
| Secrets Scan | Yes |
| Estimated Duration | 12 hours |

```bash
netra scan --target example.com --profile deep
```

### `api_only` — API Security Testing

**Use case:** REST/GraphQL API audits

| Setting | Value |
|---------|-------|
| Severity Filter | critical, high, medium |
| Max Targets | 30 |
| Focus | OWASP API Top 10 |
| Estimated Duration | 2 hours |

```bash
netra scan --target https://api.example.com --profile api_only
```

### `cloud` — Cloud Security Posture

**Use case:** AWS/Azure/GCP configuration audits

| Tool | Purpose |
|------|---------|
| Prowler | CIS benchmark checks |
| Trivy | Container scanning |
| Checkov | IaC scanning |

```bash
netra scan --target aws --profile cloud
```

### `container` — Container Image Scanning

**Use case:** Docker image vulnerability assessment

```bash
netra scan --target nginx:latest --profile container
```

### `ai_llm` — OWASP LLM Top 10 Testing

**Use case:** AI/LLM application security

| Test Category | Description |
|---------------|-------------|
| Prompt Injection | Direct and indirect injection |
| Jailbreak | DAN mode, unrestricted mode |
| Data Exfiltration | Context extraction |
| Excessive Agency | Unauthorized actions |

```bash
netra scan --target https://chat.example.com/api/chat --profile ai_llm
```

### `sast` — Static Application Security Testing

**Use case:** Source code security analysis

| Tool | Purpose |
|------|---------|
| Semgrep | SAST with rulesets |
| Gitleaks | Secret detection |
| pip-audit | Dependency scanning |

```bash
netra scan --target /path/to/repo --profile sast
```

### `iac` — Infrastructure as Code Scanning

**Use case:** Terraform, CloudFormation, Kubernetes configs

```bash
netra scan --target /path/to/terraform --profile iac
```

## Custom Profiles

Create custom profiles in `~/.netra/profiles/custom.yaml`:

```yaml
name: custom
description: My custom profile
severity_filter: critical,high
max_targets: 100
rate_limit: 200
port_range: top-500
use_nikto: true
test_sqli: true
test_xss: false
timeout_minutes: 120
```

Use with:
```bash
netra scan --target example.com --profile custom
```

## Profile Comparison

| Profile | Speed | Coverage | Noise |
|---------|-------|----------|-------|
| quick | ⚡⚡⚡ | ⚪⚪⚪⚪⚪ | Low |
| standard | ⚡⚡ | ⚪⚪⚪⚪⚪ | Medium |
| deep | ⚡ | ⚪⚪⚪⚪⚪ | High |

## Next Steps

- [Reports](reports.md) — Generate findings reports
- [Compliance](compliance.md) — Map findings to frameworks
