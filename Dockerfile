# ─────────────────────────────────────────────────────────────────────────────
# NETRA नेत्र — Dockerfile
# Multi-stage build: Python + Go tools + Playwright
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Go tool builder ──────────────────────────────────────────────────
FROM golang:1.22-alpine AS go-builder

RUN apk add --no-cache git ca-certificates

ENV GOBIN=/go-tools/bin

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest            && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest       && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest         && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest              && \
    go install -v github.com/ffuf/ffuf/v2@latest                                && \
    go install -v github.com/tomnomnom/assetfinder@latest                       && \
    go install -v github.com/sensepost/gowitness@latest                         && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest

# ── Stage 2: Final image ──────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="Yash Wardhan Gautam <yash@netra.security>"
LABEL org.opencontainers.image.title="NETRA नेत्र"
LABEL org.opencontainers.image.description="The Third Eye of Security"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/netra-security/netra"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap            \
    nikto           \
    sqlmap          \
    git             \
    curl            \
    dnsutils        \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder stage
COPY --from=go-builder /go-tools/bin/ /usr/local/bin/

# Set up NETRA home
ENV NETRA_HOME=/root/.netra
RUN mkdir -p $NETRA_HOME/data/scans \
             $NETRA_HOME/tools/bin  \
             $NETRA_HOME/tools/templates \
             $NETRA_HOME/logs       \
             $NETRA_HOME/cache

# Copy NETRA source
WORKDIR /netra
COPY pyproject.toml poetry.lock* requirements.txt ./

# Install pip dependencies (poetry not required at runtime)
RUN pip install --no-cache-dir -r requirements.txt --break-system-packages

# Install Playwright (for screenshots)
RUN pip install playwright --break-system-packages && \
    playwright install chromium --with-deps || true

COPY . .

# Install NETRA as a package
RUN pip install --no-cache-dir -e . --break-system-packages

# Update nuclei templates
RUN nuclei -update-templates -templates-directory $NETRA_HOME/tools/templates || true

# Volumes for persistent data
VOLUME ["/root/.netra"]

ENTRYPOINT ["netra"]
CMD ["--help"]
