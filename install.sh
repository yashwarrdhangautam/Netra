#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  NETRA नेत्र — One-Command Installer
#  Usage: curl -sSL https://raw.githubusercontent.com/your-org/netra/main/install.sh | bash
#  Or:    bash install.sh
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colors ─────────────────────────────────────────────────────────────────
RED='\033[91m'; ORANGE='\033[38;5;208m'; YELLOW='\033[93m'
GREEN='\033[92m'; TEAL='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'; DIM='\033[2m'

ok()   { echo -e "  ${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "  ${RED}[✗]${RESET} $*" >&2; }
info() { echo -e "  ${DIM}[·]${RESET} $*"; }
run()  { echo -e "  ${TEAL}[>]${RESET} $*"; }

# ── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${TEAL}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo -e "${TEAL}${BOLD}  NETRA नेत्र — The Third Eye of Security                      ${RESET}"
echo -e "${TEAL}${BOLD}  Installer v1.0.0                                             ${RESET}"
echo -e "${TEAL}──────────────────────────────────────────────────────────────${RESET}"
echo ""

# ── Detect OS ───────────────────────────────────────────────────────────────
OS="unknown"
PKG_MGR=""
if   [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if command -v apt-get &>/dev/null; then PKG_MGR="apt"
    elif command -v dnf &>/dev/null;    then PKG_MGR="dnf"
    elif command -v pacman &>/dev/null; then PKG_MGR="pacman"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    PKG_MGR="brew"
else
    err "Unsupported OS: $OSTYPE"
    exit 1
fi

info "Detected OS: $OS (pkg manager: ${PKG_MGR:-none})"
NETRA_HOME="${NETRA_HOME:-$HOME/.netra}"
info "NETRA_HOME: $NETRA_HOME"
echo ""

# ── Require: Python 3.11+ ───────────────────────────────────────────────────
echo -e "${TEAL}[1/6] Checking Python 3.11+${RESET}"
PY_BIN=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        VER=$("$candidate" -c "import sys; print(sys.version_info[:2])" 2>/dev/null || echo "")
        if [[ "$VER" == *"(3, 1"[1-9]* ]] || [[ "$VER" == *"(3, 1"[1-9][0-9]* ]]; then
            PY_BIN="$candidate"
            break
        fi
        # simpler version check
        if "$candidate" -c "import sys; assert sys.version_info >= (3,11)" 2>/dev/null; then
            PY_BIN="$candidate"
            break
        fi
    fi
done

if [[ -z "$PY_BIN" ]]; then
    err "Python 3.11+ not found."
    if [[ "$OS" == "linux" && "$PKG_MGR" == "apt" ]]; then
        warn "Try: sudo apt-get install -y python3.11 python3.11-pip python3.11-venv"
    elif [[ "$OS" == "macos" ]]; then
        warn "Try: brew install python@3.11"
    fi
    exit 1
fi
PY_VER=$("$PY_BIN" --version 2>&1)
ok "Found: $PY_VER ($PY_BIN)"

# ── Optional: Go 1.22+ ──────────────────────────────────────────────────────
echo ""
echo -e "${TEAL}[2/6] Checking Go 1.22+ (for Go-based tools)${RESET}"
GO_OK=false
if command -v go &>/dev/null; then
    GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
    # Check >= 1.22
    GO_MAJOR=$(echo "$GO_VER" | cut -d. -f1)
    GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)
    if [[ "$GO_MAJOR" -ge 1 && "$GO_MINOR" -ge 22 ]]; then
        ok "Found: go $GO_VER"
        GO_OK=true
    else
        warn "Go $GO_VER found but 1.22+ required for all tools. Attempting upgrade..."
    fi
fi

if [[ "$GO_OK" == "false" ]]; then
    warn "Go 1.22+ not found. Installing..."
    if [[ "$OS" == "linux" ]]; then
        GO_URL="https://go.dev/dl/go1.22.0.linux-amd64.tar.gz"
        if [[ "$(uname -m)" == "aarch64" ]]; then
            GO_URL="https://go.dev/dl/go1.22.0.linux-arm64.tar.gz"
        fi
        run "Downloading Go from $GO_URL"
        curl -sSL "$GO_URL" -o /tmp/go.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
        export PATH="$PATH:/usr/local/go/bin"
        echo 'export PATH="$PATH:/usr/local/go/bin"' >> "$HOME/.bashrc" 2>/dev/null || true
        echo 'export PATH="$PATH:/usr/local/go/bin"' >> "$HOME/.profile" 2>/dev/null || true
        ok "Go installed at /usr/local/go"
        GO_OK=true
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            run "brew install go"
            brew install go
            ok "Go installed via Homebrew"
            GO_OK=true
        else
            warn "Homebrew not found. Install Go manually from https://go.dev/dl/"
            warn "Go-based tools (subfinder, nuclei, httpx, etc.) will not be available."
        fi
    fi
fi

# Ensure GOBIN is in PATH for local tool installs
export GOPATH="${GOPATH:-$HOME/go}"
export GOBIN="${NETRA_HOME}/tools/bin"
mkdir -p "$GOBIN"

# ── Python Dependencies ─────────────────────────────────────────────────────
echo ""
echo -e "${TEAL}[3/6] Installing Python dependencies${RESET}"
NETRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$NETRA_DIR/requirements.txt" ]]; then
    # Being run via curl pipe — clone the repo first
    err "requirements.txt not found. Please clone the repo first:"
    echo "    git clone https://github.com/your-org/netra.git && cd netra && bash install.sh"
    exit 1
fi

run "pip install -r requirements.txt --break-system-packages -q"
"$PY_BIN" -m pip install -r "$NETRA_DIR/requirements.txt" \
    --break-system-packages \
    --quiet \
    --no-warn-script-location 2>&1 | grep -v "^$" | head -20 || true
ok "Python dependencies installed"

# Playwright browser for screenshots
run "Installing Playwright Chromium (for screenshots)"
"$PY_BIN" -m playwright install chromium --with-deps 2>&1 | tail -3 || \
    warn "Playwright install failed — screenshots will be skipped (optional)"

# ── Ollama ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${TEAL}[4/6] Installing Ollama + Qwen 14B${RESET}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen:14b}"

if command -v ollama &>/dev/null; then
    ok "Ollama already installed: $(ollama --version 2>&1 | head -1)"
else
    run "Installing Ollama..."
    if [[ "$OS" == "linux" ]]; then
        curl -fsSL https://ollama.com/install.sh | sh
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            brew install ollama
        else
            warn "Install Ollama manually from https://ollama.com/download"
            warn "AI analysis features will not be available until Ollama is running."
        fi
    fi
fi

# Start Ollama in background if not running
if command -v ollama &>/dev/null; then
    if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
        run "Starting Ollama service..."
        ollama serve &>/dev/null &
        OLLAMA_PID=$!
        sleep 3
        info "Ollama started (PID: $OLLAMA_PID)"
    else
        ok "Ollama already running"
    fi

    # Pull Qwen model
    run "Pulling $OLLAMA_MODEL (this may take a while on first run)..."
    info "Model size: ~8GB for qwen:14b. For a smaller model use: OLLAMA_MODEL=qwen:7b bash install.sh"
    if ollama pull "$OLLAMA_MODEL"; then
        ok "Model $OLLAMA_MODEL ready"
    else
        warn "Could not pull $OLLAMA_MODEL — AI features require manual: ollama pull $OLLAMA_MODEL"
    fi
fi

# ── NETRA Tool Dependencies ─────────────────────────────────────────────────
echo ""
echo -e "${TEAL}[5/6] Installing NETRA scan tools${RESET}"
if [[ "$GO_OK" == "true" ]]; then
    run "python3 netra.py --install-deps"
    cd "$NETRA_DIR"
    "$PY_BIN" netra.py --install-deps || warn "Some tools may have failed. Run --check-deps to see status."
    ok "Scan tools installation attempted"
else
    warn "Skipping Go tool install (Go not available)"
    warn "Install Go 1.22+, then run: python3 netra.py --install-deps"
fi

# ── Verify Installation ─────────────────────────────────────────────────────
echo ""
echo -e "${TEAL}[6/6] Verifying installation${RESET}"
cd "$NETRA_DIR"
if "$PY_BIN" netra.py --version &>/dev/null; then
    VER_OUTPUT=$("$PY_BIN" netra.py --version 2>&1 | head -1)
    ok "NETRA launches: $VER_OUTPUT"
else
    warn "NETRA --version failed. Check errors above."
fi

# ── Final Banner ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  NETRA नेत्र installed successfully!                          ${RESET}"
echo -e "${GREEN}──────────────────────────────────────────────────────────────${RESET}"
echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo -e "    python3 netra.py --check-deps          # verify tools"
echo -e "    python3 netra.py -t example.com        # run a scan"
echo -e "    python3 netra.py -t 10.0.0.0/24 --profile fast"
echo ""
echo -e "  ${BOLD}Config file:${RESET}  ${NETRA_HOME}/config.yaml"
echo -e "  ${BOLD}Scan data:${RESET}    ${NETRA_HOME}/data/scans/"
echo -e "  ${BOLD}Tools:${RESET}        ${NETRA_HOME}/tools/bin/"
echo ""
echo -e "  ${DIM}Docs: https://github.com/your-org/netra${RESET}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo ""
