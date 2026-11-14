# Scanner binaries are built from source in a Go stage, so the image does not depend on
# third-party release archives. Versions track @latest; pin them in a lock file for production.
FROM golang:1.23-bookworm AS gotools
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/PentestPad/subzy@latest && \
    go install github.com/zricethezav/gitleaks/v8@latest

FROM python:3.12-slim AS builder
WORKDIR /app
RUN pip install poetry==2.4.0
COPY pyproject.toml poetry.lock* ./
RUN poetry config virtualenvs.create false && \
    poetry install --only main --no-root --no-interaction --no-ansi

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONPATH=/app/src
RUN apt-get update && apt-get install -y --no-install-recommends curl nmap ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=gotools /go/bin/ /usr/local/bin/
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY verifier_allowlist.yaml ./
RUN useradd -m netra && mkdir -p /home/netra/.netra /home/netra/netra_output && chown -R netra:netra /app /home/netra
USER netra
EXPOSE 8000
CMD ["uvicorn", "netra.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
