# Quick Start

## 1. Run Your First Scan

```bash
# Quick scan on a test target
netra scan --target scanme.nmap.org --profile quick
```

Expected output:
```
[INFO] Starting scan: abc123
[INFO] Phase 1: Subdomain enumeration...
[INFO] Phase 2: Live host discovery...
[INFO] Phase 3: Port scanning...
[INFO] Phase 4: Vulnerability scanning...
[INFO] Scan completed: 26 findings
┌────────────┬───────────┬────────────┐
│ Severity   │ Count     │ Percentage │
├────────────┼───────────┼────────────┤
│ Critical   │ 0         │ 0%         │
│ High       │ 2         │ 8%         │
│ Medium     │ 5         │ 19%        │
│ Low        │ 8         │ 31%        │
│ Info       │ 11        │ 42%        │
└────────────┴───────────┴────────────┘
```

## 2. View Findings

```bash
# List all findings
netra findings --scan-id abc123

# Filter by severity
netra findings --scan-id abc123 --severity high
```

## 3. Generate Report

```bash
# Executive PDF report
netra report --type executive --scan-id abc123

# HTML interactive report
netra report --type html --scan-id abc123

# Reports saved to ~/.netra/reports/
```

## 4. Check Compliance

```bash
# PCI DSS compliance score
netra compliance --framework pci_dss --scan-id abc123

# Output:
# Framework: PCI DSS v4.0
# Compliance Score: 72.5%
# Failed Controls: 8
# - 6.5.1: Injection flaws
# - 6.5.7: Cross-site scripting
```

## Using the Dashboard

1. Open http://localhost:5173
2. Navigate to **Scans** → **New Scan**
3. Enter target and select profile
4. Watch real-time progress
5. View findings and generate reports

## Using MCP with Claude

Configure in Claude Desktop config:

```json
{
  "mcpServers": {
    "netra": {
      "command": "python",
      "args": ["-m", "netra.mcp.server"]
    }
  }
}
```

Then ask Claude:
> "Run a quick security scan on example.com using NETRA"

## Next Steps

- [Scan Profiles](profiles.md) — Understand different scan types
- [Reports](reports.md) — Generate professional deliverables
- [Autonomous Agent](agent.md) — Let AI run pentests for you
