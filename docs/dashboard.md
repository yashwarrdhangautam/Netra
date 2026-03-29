# Dashboard

The NETRA Dashboard is a React-based web interface for managing scans and viewing findings.

## Access

```bash
# Start Docker Compose
docker compose up -d

# Open dashboard
open http://localhost:5173
```

## Pages

### 1. Dashboard (Home)

**Features:**
- Risk score gauge (A-F grade)
- Severity distribution pie chart
- Stats cards (Critical, High, Medium counts)
- Recent scans table
- Activity timeline

### 2. Scans

**Features:**
- List all scans with pagination
- Filter by status, profile
- Sort by name, date, findings
- Actions: View, Resume, Delete, Compare

### 3. Scan Detail

**Features:**
- Phase timeline visualization
- Real-time finding stream (WebSocket)
- Scan statistics
- Actions: Pause, Cancel, Generate Report

### 4. Findings

**Features:**
- Paginated findings table
- Filters: severity, status, CWE, tool, scan
- Bulk actions: Mark FP, Assign, Tag
- Inline AI preview on hover

### 5. Finding Detail

**Features:**
- Full finding information
- Tabs: Evidence | AI Analysis | Remediation | Compliance | History
- AI persona responses (Attacker, Defender, Analyst, Skeptic)
- Status workflow buttons

### 6. Reports

**Features:**
- 11 report type selector
- Scan selector
- Generate button with progress
- Report history with download links

### 7. Compliance

**Features:**
- Framework tabs (ISO 27001, PCI DSS, etc.)
- Compliance score gauge per framework
- Control heatmap
- Gap list with linked findings

### 8. Targets

**Features:**
- Target list with finding counts
- Add target (single or bulk import)
- Scope rules configuration
- Scan history per target

### 9. Attack Graph

**Features:**
- Interactive force-directed graph
- Nodes: findings (colored by severity)
- Edges: attack chains from AI
- Click to see finding detail panel

### 10. Settings

**Features:**
- API keys management (Anthropic, Shodan)
- Notification configuration
- Scan defaults
- User management (admin only)

## Real-time Updates

The dashboard uses WebSocket for live updates:

- Scan progress updates
- New findings as discovered
- Agent conversation stream

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `N` | New Scan |
| `/` | Search |
| `?` | Show shortcuts |

## Browser Support

- Chrome 120+
- Firefox 120+
- Safari 17+
- Edge 120+

## Next Steps

- [Agent](agent.md) — Autonomous pentesting
- [API Reference](api.md) — REST API documentation
