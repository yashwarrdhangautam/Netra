# Configuration

## Environment Variables

All configuration is done via environment variables with `NETRA_` prefix.

### Application

| Variable | Default | Description |
|----------|---------|-------------|
| `NETRA_ENVIRONMENT` | `development` | `development`, `staging`, `production` |
| `NETRA_DEBUG` | `true` | Enable debug logging |
| `NETRA_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `NETRA_LOG_FORMAT` | `json` | `json` or `text` |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `NETRA_DATABASE_URL` | `sqlite+aiosqlite:///./netra.db` | Database connection string |
| `NETRA_DB_ECHO` | `false` | Log SQL queries |

Examples:
```bash
# SQLite (default, for CLI)
NETRA_DATABASE_URL=sqlite+aiosqlite:///./netra.db

# PostgreSQL (for Docker/production)
NETRA_DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/netra
```

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `NETRA_JWT_SECRET_KEY` | (auto-generated) | JWT signing key |
| `NETRA_JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `NETRA_JWT_EXPIRE_MINUTES` | `60` | Token expiration |

### AI Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NETRA_AI_PROVIDER` | `none` | `anthropic`, `ollama`, `none` |
| `NETRA_ANTHROPIC_API_KEY` | | Anthropic API key |
| `NETRA_ANTHROPIC_MODEL` | `claude-sonnet-4-20250514` | Claude model |
| `NETRA_OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama endpoint |
| `NETRA_OLLAMA_MODEL` | `llama3.1:8b` | Ollama model |

### Tool API Keys

| Variable | Default | Description |
|----------|---------|-------------|
| `NETRA_SHODAN_API_KEY` | | Shodan API key |
| `NETRA_WPSCAN_API_TOKEN` | | WPScan API token |

### Notifications

| Variable | Default | Description |
|----------|---------|-------------|
| `NETRA_SLACK_WEBHOOK_URL` | | Slack webhook for alerts |
| `NETRA_SMTP_HOST` | | SMTP server |
| `NETRA_SMTP_PORT` | `587` | SMTP port |
| `NETRA_SMTP_USER` | | SMTP username |
| `NETRA_NOTIFICATION_EMAIL_TO` | | Recipient emails (comma-separated) |

### Scanning

| Variable | Default | Description |
|----------|---------|-------------|
| `NETRA_DEFAULT_SCAN_PROFILE` | `standard` | Default scan profile |
| `NETRA_MAX_CONCURRENT_SCANS` | `3` | Max parallel scans |
| `NETRA_SCAN_TIMEOUT_HOURS` | `12` | Max scan duration |

## Configuration File

NETRA also supports YAML configuration:

```yaml
# config.yaml
app:
  environment: production
  log_level: WARNING

database:
  url: postgresql+asyncpg://user:pass@localhost:5432/netra

ai:
  provider: anthropic
  model: claude-sonnet-4-20250514

scanning:
  default_profile: standard
  max_concurrent: 5
```

Load with:
```bash
netra server --config config.yaml
```

## Secrets Management

**Never commit secrets!** Use one of:

1. **Environment variables** (recommended for Docker)
2. **.env file** (add to .gitignore)
3. **Secrets manager** (AWS Secrets Manager, HashiCorp Vault)

Example `.env` (add to `.gitignore`):
```bash
NETRA_ANTHROPIC_API_KEY=sk-ant-xxx
NETRA_SHODAN_API_KEY=xxx
NETRA_JWT_SECRET_KEY=$(openssl rand -hex 32)
```
