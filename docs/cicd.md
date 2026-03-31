# CI/CD Integration

NETRA integrates with GitHub Actions, GitLab CI, and any CI/CD system via SARIF output.

## GitHub Actions

### Basic Workflow

Create `.github/workflows/netra-scan.yml`:

```yaml
name: NETRA Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 0'  # Weekly on Sundays

jobs:
  netra:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - name: Install NETRA
        run: pip install netra

      - name: Install tools
        run: |
          go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          echo "$(go env GOPATH)/bin" >> $GITHUB_PATH

      - name: Run scan
        env:
          NETRA_ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          netra scan \
            --target "${{ github.event.repository.html_url }}" \
            --profile quick \
            --output-sarif results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Reusable Workflow

Use NETRA's reusable workflow:

```yaml
name: Security Scan

on: [push]

jobs:
  scan:
    uses: yashwarrdhangautam/netra/.github/workflows/netra-reusable.yml@main
    with:
      target: ${{ github.event.repository.html_url }}
      profile: quick
      fail_on_severity: high
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## GitLab CI

Create `.gitlab-ci.yml`:

```yaml
stages:
  - security

netra-scan:
  stage: security
  image: python:3.12
  script:
    - pip install netra
    - go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    - export PATH=$PATH:$(go env GOPATH)/bin
    - netra scan --target $CI_PROJECT_URL --profile quick --output-sarif results.sarif
  artifacts:
    reports:
      container_scanning: results.sarif
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## SARIF Output

Generate SARIF for GitHub Security tab:

```bash
netra scan --target example.com --output-sarif results.sarif
```

SARIF includes:
- Rule IDs (CWE or tool-based)
- Severity levels (error, warning, note)
- Locations (URLs, file paths)
- Properties (confidence, tool source)

## Exit Codes

NETRA returns exit codes for CI/CD:

| Code | Meaning |
|------|---------|
| 0 | Success, no findings above threshold |
| 1 | Findings above threshold found |
| 2 | Scan error/failure |

Use `--fail-on` to set threshold:

```bash
# Fail on high or critical
netra scan --target example.com --fail-on high

# Fail only on critical
netra scan --target example.com --fail-on critical

# Never fail (always exit 0)
netra scan --target example.com --fail-on none
```

## Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('NETRA Scan') {
            steps {
                sh 'pip install netra'
                sh 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
                sh '''
                    netra scan \\
                        --target ${BUILD_URL} \\
                        --profile quick \\
                        --output-sarif results.sarif \\
                        --fail-on high || true
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.sarif'
                }
            }
        }
    }
}
```

## Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: pip install netra
    displayName: 'Install NETRA'

  - script: |
      go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
      export PATH=$PATH:$(go env GOPATH)/bin
    displayName: 'Install security tools'

  - script: |
      netra scan \
        --target $(Build.Repository.Uri) \
        --profile quick \
        --output-sarif results.sarif
    env:
      NETRA_ANTHROPIC_API_KEY: $(ANTHROPIC_API_KEY)
    displayName: 'Run NETRA scan'

  - task: PublishSecurityAnalysisLogs@3
    inputs:
      ToolType: 'SARIF'
      SARIFFile: 'results.sarif'
```

## Next Steps

- [MCP](mcp.md) — MCP integration for Claude
- [Architecture](architecture.md) — System design
