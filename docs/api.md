# API Reference

NETRA provides a REST API at `/api/v1/`.

## Authentication

Most endpoints require JWT authentication:

```bash
# Login to get token
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "password"}'

# Use token in requests
curl "http://localhost:8000/api/v1/scans" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Scans

### List Scans

```http
GET /api/v1/scans?page=1&per_page=20&status=completed
```

### Create Scan

```http
POST /api/v1/scans/
Content-Type: application/json

{
  "target_id": "uuid",
  "name": "My Scan",
  "profile": "standard"
}
```

### Get Scan

```http
GET /api/v1/scans/{scan_id}
```

### Update Scan

```http
PATCH /api/v1/scans/{scan_id}
Content-Type: application/json

{
  "status": "paused"
}
```

### Delete Scan

```http
DELETE /api/v1/scans/{scan_id}
```

### Get Scan Phases

```http
GET /api/v1/scans/{scan_id}/phases
```

### Resume Scan

```http
POST /api/v1/scans/{scan_id}/resume
```

### Compare Scans

```http
POST /api/v1/scans/diff
Content-Type: application/json

{
  "scan_a_id": "uuid",
  "scan_b_id": "uuid"
}
```

## Findings

### List Findings

```http
GET /api/v1/findings?page=1&per_page=20&severity=high&status=new
```

### Get Finding

```http
GET /api/v1/findings/{finding_id}
```

### Create Finding

```http
POST /api/v1/findings/
Content-Type: application/json

{
  "scan_id": "uuid",
  "title": "SQL Injection",
  "description": "...",
  "severity": "critical",
  "tool_source": "sqlmap"
}
```

### Update Finding

```http
PATCH /api/v1/findings/{finding_id}
Content-Type: application/json

{
  "status": "confirmed"
}
```

### Mark as False Positive

```http
POST /api/v1/findings/{finding_id}/mark-false-positive
```

### Bulk Update

```http
POST /api/v1/findings/bulk-update
Content-Type: application/json

{
  "finding_ids": ["uuid1", "uuid2"],
  "status": "resolved"
}
```

## Reports

### Generate Report

```http
POST /api/v1/reports/{scan_id}/generate?report_type=executive
```

### Get Report

```http
GET /api/v1/reports/{report_id}
```

### List Reports for Scan

```http
GET /api/v1/reports/scan/{scan_id}
```

### Delete Report

```http
DELETE /api/v1/reports/{report_id}
```

## Compliance

### Get Compliance Score

```http
GET /api/v1/compliance/{scan_id}/score/{framework}
```

### Get Framework Status

```http
GET /api/v1/compliance/{scan_id}/framework/{framework}
```

### Get Gap Analysis

```http
GET /api/v1/compliance/{scan_id}/gap-analysis/{framework}
```

### Map Findings

```http
POST /api/v1/compliance/map
Content-Type: application/json

{
  "scan_id": "uuid",
  "frameworks": ["iso27001", "pci_dss"]
}
```

## Targets

### List Targets

```http
GET /api/v1/targets?page=1&per_page=20
```

### Create Target

```http
POST /api/v1/targets/
Content-Type: application/json

{
  "name": "Example.com",
  "target_type": "domain",
  "value": "example.com"
}
```

### Import Targets

```http
POST /api/v1/targets/import
Content-Type: multipart/form-data

file: targets.txt
```

## Agent

### Start Agent

```http
POST /api/v1/agent/start?target=example.com&profile=standard
```

### Get Agent Status

```http
GET /api/v1/agent/{session_id}/status
```

### Approve Action

```http
POST /api/v1/agent/{session_id}/approve
```

### Reject Action

```http
POST /api/v1/agent/{session_id}/reject?reason=Out+of+scope
```

## Health

### Health Check

```http
GET /api/health
```

Response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "connected"
}
```

## WebSocket

### Scan Progress

```
WS /ws/scans/{scan_id}
```

### Finding Stream

```
WS /ws/findings
```

### Agent Conversation

```
WS /ws/agent/{session_id}
```

## Rate Limiting

Default: 100 requests per minute per IP.

Configure with `NETRA_API_RATE_LIMIT`:

```bash
NETRA_API_RATE_LIMIT=200/minute
```

## OpenAPI Documentation

Interactive API docs available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
