# NETRA नेत्र

> The Third Eye of Security

AI-assisted security orchestration that finds vulnerabilities, validates them with AI, maps to compliance, and generates reports — all in one automated workflow.

## Quick Start

```bash
# Install
bash <(curl -s https://raw.githubusercontent.com/yashwarrdhangautam/netra/main/install.sh)

# Or use Docker
docker compose up -d
```

## What You Get

- **18 Security Tools** orchestrated in one pipeline
- **4-Persona AI** validation (60% fewer false positives)
- **6 Compliance Frameworks** auto-mapped
- **13 Report Formats** ready in minutes

## Scan Profiles

| Profile | Duration | Best For |
|---------|----------|----------|
| `quick` | 30 min | Pre-deployment checks |
| `standard` | 2-3 hrs | Full VAPT |
| `deep` | 4-6 hrs | Comprehensive audit |
| `cloud` | 3-4 hrs | AWS/Azure/GCP |
| `api_only` | 1-2 hrs | API testing |

## Example

```bash
# Quick scan
netra scan --target example.com --profile quick

# View findings
netra findings --scan-id <id> --severity critical

# Generate report
netra report --scan-id <id> --type executive
```

## Documentation

- [Installation](installation.md)
- [Configuration](configuration.md)
- [Profiles](profiles.md)
- [API](api.md)
- [Benchmarks](BENCHMARKS.md)
- [Use Cases](USE_CASES.md)
- [FAQ](FAQ.md)

## License

AGPL-3.0
