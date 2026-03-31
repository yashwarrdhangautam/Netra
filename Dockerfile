# ─────────────────────────────────────────────────────────────────────────────
# NETRA नेत्र — Dockerfile
# Multi-stage build: Python + Go tools + Playwright
# Optimized for production with minimal layers and caching
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Go tool builder ──────────────────────────────────────────────────
FROM golang:1.22-alpine AS go-builder

RUN apk add --no-cache git ca-certificates

ENV GOBIN=/go-tools/bin

# Install Go-based security tools (pinned versions for reproducibility)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7 && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.4.2            && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.7       && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.2.2         && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.2              && \
    go install -v github.com/ffuf/ffuf/v2@v2.1.0                                && \
    go install -v github.com/tomnomnom/assetfinder@latest                       && \
    go install -v github.com/sensepost/gowitness@v2.5.2                         && \
    go install -v github.com/lc/gau/v2/cmd/gau@v2.2.2

# ── Stage 2: Final image ──────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="Yash Wardhan Gautam <yash@netra.security>"
LABEL org.opencontainers.image.title="NETRA नेत्र"
LABEL org.opencontainers.image.description="The Third Eye of Security"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/netra-security/netra"

# Install system dependencies in single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap            \
    nikto           \
    sqlmap          \
    git             \
    curl            \
    dnsutils        \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Go binaries from builder stage
COPY --from=go-builder /go-tools/bin/ /usr/local/bin/

# Set up NETRA home
ENV NETRA_HOME=/root/.netra
RUN mkdir -p $NETRA_HOME/data/scans \
             $NETRA_HOME/tools/bin  \
             $NETRA_HOME/tools/templates \
             $NETRA_HOME/logs       \
             $NETRA_HOME/cache

# Copy only requirements first for better layer caching
WORKDIR /netra
COPY pyproject.toml poetry.lock* requirements.txt ./

# Install Python dependencies with no cache to reduce image size
RUN pip install --no-cache-dir -r requirements.txt --break-system-packages

# Install Playwright (for screenshots)
RUN pip install --no-cache-dir playwright --break-system-packages && \
    playwright install chromium --with-deps && \
    playwright install-deps chromium || true

# Copy application code last (changes most frequently)
COPY . .

# Install NETRA as a package
RUN pip install --no-cache-dir -e . --break-system-packages

# Update nuclei templates
RUN nuclei -update-templates -templates-directory $NETRA_HOME/tools/templates || true

# Create non-root user for security
RUN useradd -m -u 1000 netra && \
    chown -R netra:netra $NETRA_HOME /netra
USER netra

# Volumes for persistent data
VOLUME ["/root/.netra"]

ENTRYPOINT ["netra"]
CMD ["--help"]
