# Installation

## Prerequisites

- Python 3.12+
- pip or Poetry
- (Optional) Docker and Docker Compose

## Method 1: pip Install

```bash
# Install NETRA
pip install netra

# Verify installation
netra --version
```

## Method 2: Install Security Tools

NETRA requires external security tools for scanning. Install them individually:

```bash
# Nuclei (vulnerability scanning)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Subfinder (subdomain enumeration)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Httpx (HTTP probing)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nmap (port scanning)
# Ubuntu/Debian
sudo apt-get install nmap
# macOS
brew install nmap

# SQLMap (SQL injection testing)
git clone https://github.com/sqlmapproject/sqlmap.git
export PATH=$PATH:$(pwd)/sqlmap

# Ffuf (directory fuzzing)
go install github.com/ffuf/ffuf@latest

# Dalfox (XSS testing)
go install github.com/hahwul/dalfox/v2@latest

# Nikto (web server scanning)
# Ubuntu/Debian
sudo apt-get install nikto
```

Or use the convenience command:

```bash
netra --install-deps
```

## Method 3: Docker Compose (Recommended for Production)

```bash
# Clone repository
git clone https://github.com/yashwg/netra.git
cd netra

# Start all services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f api
```

Services available:
- **API**: http://localhost:8000
- **Dashboard**: http://localhost:5173
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## Configuration

Create a `.env` file in your project root:

```bash
# AI Configuration
NETRA_AI_PROVIDER=anthropic
NETRA_ANTHROPIC_API_KEY=your-api-key-here

# Tool API Keys
NETRA_SHODAN_API_KEY=your-shodan-key

# Database (auto-configured in Docker)
NETRA_DATABASE_URL=postgresql+asyncpg://netra:netra@localhost:5432/netra
```

## Verify Installation

```bash
# Check CLI
netra --help

# Start API server
netra server

# Run health check
curl http://localhost:8000/api/health
```

## Next Steps

- [Quick Start](quickstart.md) — Run your first scan
- [Configuration](configuration.md) — Detailed configuration options

## First Run: Create the Administrator Account

The GUI requires sign-in. Create the first admin once, after the database migrations have finished:

```bash
# Docker Compose stack
docker compose exec -it api python -m netra.cli.create_admin

# Local development (from the repository root)
uv run python -m netra.cli.create_admin
```

You are prompted for an email, an optional name, and a password. The password must be at least 12 characters and mix upper- and lower-case letters with at least one digit. Then open the GUI at `http://localhost:5173/login`.

Notes:
- `NETRA_JWT_SECRET_KEY` must be set in `.env` before the stack starts. Docker Compose refuses to start without it.
- If port 8000 is already in use on your machine, change the host port of the `api` service in `docker-compose.yml`. The GUI proxies to the API inside the Docker network, so it does not need changing.
- Scanner binaries such as subfinder, amass, ffuf and nuclei must be installed in the API and worker images before scans and hunts can produce results. See Method 2 above.
