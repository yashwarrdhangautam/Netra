# Autonomous Agent

NETRA's autonomous pentest agent uses Claude to orchestrate security testing with human-in-the-loop controls.

## How It Works

1. **Reconnaissance** — Passive subdomain enumeration, OSINT
2. **Discovery** — Live host detection, technology fingerprinting
3. **Vulnerability Scanning** — Targeted Nuclei scans
4. **Active Testing** — SQLi, XSS testing (requires approval)
5. **Analysis** — Attack chain discovery
6. **Reporting** — Narrative with evidence

## Safety Limits

| Limit | Value |
|-------|-------|
| Max Tool Calls | 50 |
| Max Duration | 30 minutes |
| Max Cost | $5 USD |

## Tools Requiring Approval

These tools require human approval before execution:

- `sqlmap_test` — SQL injection testing
- `dalfox_xss` — XSS testing
- `ffuf_fuzz` — Directory fuzzing (aggressive)

## Usage

### Start Agent Session

```bash
# Via CLI
netra agent start --target example.com --profile standard

# Via API
curl -X POST "http://localhost:8000/api/v1/agent/start?target=example.com"
```

### Check Status

```bash
# Via CLI
netra agent status --session-id abc123

# Via API
curl "http://localhost:8000/api/v1/agent/abc123/status"
```

### Approve/Reject Action

When agent finds a potential SQL injection point:

```bash
# Approve exploitation
netra agent approve --session-id abc123

# Reject with reason
netra agent reject --session-id abc123 --reason "Out of scope"
```

### WebSocket Stream

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/agent/abc123');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Agent update:', data);
};
```

## Agent Response Format

```json
{
  "status": "awaiting_approval",
  "session_id": "abc123",
  "pending_action": {
    "tool": "sqlmap_test",
    "args": {
      "url": "https://example.com/search?q=test",
      "safe_mode": true
    }
  },
  "decisions": [
    {
      "timestamp": "2026-03-28T10:30:00Z",
      "type": "reasoning",
      "data": "Found search parameter, testing for SQLi..."
    }
  ],
  "tool_calls": 12,
  "elapsed_minutes": 8
}
```

## Audit Trail

All agent decisions are logged:

```bash
# View audit log
netra agent audit-log --session-id abc123

# Export to JSON
netra agent audit-log --session-id abc123 --export audit.json
```

## Best Practices

1. **Start with quick profile** — Test agent behavior
2. **Review reasoning** — Agent explains before each action
3. **Set clear scope** — Define what's in/out of scope
4. **Monitor cost** — Check token usage

## Next Steps

- [CI/CD](cicd.md) — Integrate with GitHub Actions
- [MCP](mcp.md) — Use agent via Claude Desktop
