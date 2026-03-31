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
git clone https://github.com/yashwarrdhangautam/netra.git
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
