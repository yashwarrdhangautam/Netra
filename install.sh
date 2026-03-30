#!/bin/bash
set -e

# NETRA नेत्र Installation Script
# Phase 4: Production Ready with Distributed Scanning, MFA, and Integrations
# Detects OS, installs dependencies, and sets up the NETRA platform
# Idempotent: safe to run multiple times

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

log_phase() {
    echo -e "${MAGENTA}[PHASE]${NC} $1"
}

# Detect OS and WSL
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if grep -qi microsoft /proc/version 2>/dev/null; then
            OS="wsl"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        log_error "Unsupported operating system: $OSTYPE"
    fi
    log_info "Detected OS: $OS"
}

# Check Python version
check_python() {
    log_info "Checking Python 3.11+"
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed. Please install Python 3.11 or later."
    fi

    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [[ $MAJOR -lt 3 ]] || [[ $MAJOR -eq 3 && $MINOR -lt 11 ]]; then
        log_error "Python 3.11+ required. Found: $PYTHON_VERSION"
    fi
    log_success "Python $PYTHON_VERSION found"
}

# Install Go 1.22+
install_go() {
    log_info "Checking Go 1.22+"
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        MAJOR=$(echo $GO_VERSION | cut -d. -f1)
        MINOR=$(echo $GO_VERSION | cut -d. -f2)
        if [[ $MAJOR -gt 1 ]] || [[ $MAJOR -eq 1 && $MINOR -ge 22 ]]; then
            log_success "Go $GO_VERSION already installed"
            return
        fi
    fi

    log_info "Installing Go 1.22+"
    GO_DOWNLOAD="https://go.dev/dl/go1.22.0.linux-amd64.tar.gz"
    if [[ "$OS" == "macos" ]]; then
        GO_DOWNLOAD="https://go.dev/dl/go1.22.0.darwin-arm64.tar.gz"
    fi

    cd /tmp
    wget -q $GO_DOWNLOAD -O go.tar.gz || log_error "Failed to download Go"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go.tar.gz
    rm go.tar.gz

    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc 2>/dev/null || true

    log_success "Go installed"
}

# Install Go security tools
install_go_tools() {
    log_info "Installing Go security tools"
    local TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
        "github.com/projectdiscovery/httpx/cmd/httpx"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
        "github.com/projectdiscovery/ffuf"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu"
        "github.com/projectdiscovery/dnsx/cmd/dnsx"
        "github.com/projectdiscovery/dalfox/v2/cmd/dalfox"
    )

    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

    for tool in "${TOOLS[@]}"; do
        TOOL_NAME=$(basename $(dirname "$tool"))
        if command -v $TOOL_NAME &> /dev/null; then
            log_success "$TOOL_NAME already installed"
        else
            log_info "Installing $TOOL_NAME"
            go install "${tool}@latest" || log_warn "Failed to install $TOOL_NAME"
        fi
    done

    mkdir -p ~/.netra/tools
    log_success "Go tools installation complete"
}

# Install system tools
install_system_tools() {
    log_info "Installing system security tools"

    if [[ "$OS" == "linux" ]] || [[ "$OS" == "wsl" ]]; then
        # Update package manager
        if command -v apt-get &> /dev/null; then
            log_info "Using apt-get"
            sudo apt-get update -qq
            sudo apt-get install -y nmap nikto sqlmap git wget curl 2>/dev/null || log_warn "Some tools failed to install"
        elif command -v yum &> /dev/null; then
            log_info "Using yum"
            sudo yum install -y nmap nikto git wget curl 2>/dev/null || log_warn "Some tools failed to install"
        fi
    elif [[ "$OS" == "macos" ]]; then
        if ! command -v brew &> /dev/null; then
            log_info "Installing Homebrew"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install nmap nikto sqlmap git 2>/dev/null || log_warn "Some tools failed to install"
    fi

    log_success "System tools installation complete"
}

# Install Ollama
install_ollama() {
    log_info "Checking Ollama"
    if command -v ollama &> /dev/null; then
        log_success "Ollama already installed"
        return
    fi

    log_info "Installing Ollama"
    if [[ "$OS" == "macos" ]]; then
        log_info "Download Ollama from https://ollama.ai/download"
        log_info "macOS requires manual installation"
    else
        curl -fsSL https://ollama.ai/install.sh | sh 2>/dev/null || log_warn "Ollama installation had issues"
    fi
}

# Pull Ollama model
pull_ollama_model() {
    log_info "Pulling qwen:14b model"
    if ! command -v ollama &> /dev/null; then
        log_warn "Ollama not found. Skipping model pull. Install Ollama and run: ollama pull qwen:14b"
        return
    fi

    # Start Ollama in background if not running
    if ! pgrep -x "ollama" > /dev/null; then
        log_info "Starting Ollama service"
        ollama serve > /dev/null 2>&1 &
        sleep 3
    fi

    log_info "This may take 10-15 minutes depending on connection speed"
    ollama pull qwen:14b 2>/dev/null || log_warn "Failed to pull model. Run manually: ollama pull qwen:14b"
    log_success "Model pulled"
}

# Install Redis (for Celery)
install_redis() {
    log_info "Checking Redis"
    if command -v redis-server &> /dev/null; then
        log_success "Redis already installed"
        return
    fi

    log_info "Installing Redis"
    if [[ "$OS" == "linux" ]] || [[ "$OS" == "wsl" ]]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y redis-server 2>/dev/null || log_warn "Redis installation failed"
        elif command -v yum &> /dev/null; then
            sudo yum install -y redis 2>/dev/null || log_warn "Redis installation failed"
        fi
    elif [[ "$OS" == "macos" ]]; then
        brew install redis 2>/dev/null || log_warn "Redis installation failed"
    fi

    log_success "Redis installation complete"
}

# Create directory structure
create_directory_structure() {
    log_info "Creating ~/.netra directory structure"
    mkdir -p ~/.netra/{scans,reports,evidence,config,tools,logs,certs,wordlists}
    log_success "Directory structure created"
}

# Install NETRA Python dependencies
install_netra() {
    log_info "Installing NETRA Python dependencies"

    # Get script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    # Check if requirements.txt exists
    if [[ ! -f "requirements.txt" ]]; then
        log_error "requirements.txt not found. Please ensure you're in the NETRA project root."
    fi

    # Install dependencies
    if command -v poetry &> /dev/null; then
        log_info "Using Poetry"
        poetry install --no-root
    else
        log_info "Using pip"
        python3 -m pip install --upgrade pip --quiet
        python3 -m pip install -r requirements.txt --quiet --break-system-packages 2>/dev/null || \
        python3 -m pip install -r requirements.txt --quiet 2>/dev/null || log_error "Failed to install dependencies"
    fi

    log_success "NETRA dependencies installed"
}

# Run database migrations
run_migrations() {
    log_info "Running database migrations"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    if [[ ! -f "alembic.ini" ]]; then
        log_warn "alembic.ini not found. Skipping migrations."
        return
    fi

    if command -v alembic &> /dev/null; then
        alembic upgrade head || log_warn "Migration had issues"
    elif python3 -m alembic --version &> /dev/null; then
        python3 -m alembic upgrade head || log_warn "Migration had issues"
    else
        log_warn "Alembic not found. Skipping migrations. Run manually: alembic upgrade head"
        return
    fi

    log_success "Migrations complete"
}

# Create .env file from example
setup_env() {
    log_info "Setting up environment file"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    if [[ -f ".env" ]]; then
        log_success ".env file already exists"
        return
    fi

    if [[ -f ".env.example" ]]; then
        cp .env.example .env
        log_success ".env file created from .env.example"
        log_info "Please edit .env and configure:"
        echo "  - NETRA_JWT_SECRET_KEY (generate a random 64-char string)"
        echo "  - NETRA_SLACK_WEBHOOK_URL (for Slack notifications)"
        echo "  - NETRA_SMTP_* (for email notifications)"
        echo "  - NETRA_DEFECTDOJO_* (for DefectDojo integration)"
        echo "  - NETRA_JIRA_* (for Jira integration)"
    else
        log_warn ".env.example not found"
    fi
}

# Print completion message
print_success_message() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       NETRA Installation Complete                          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo ""
    echo "1. Configure environment variables:"
    echo "   nano .env  # Edit .env file"
    echo ""
    echo "2. Start the NETRA API server:"
    echo "   netra server"
    echo "   # Or with Docker:"
    echo "   docker compose up -d"
    echo ""
    echo "3. Start Celery worker (for distributed scanning):"
    echo "   celery -A netra.worker.celery_app worker --loglevel=info"
    echo ""
    echo "4. Start Flower (Celery monitoring):"
    echo "   celery -A netra.worker.celery_app flower --port=5555"
    echo "   # Or with Docker:"
    echo "   docker compose --profile monitoring up flower"
    echo ""
    echo "5. Run CLI scans:"
    echo "   netra --help"
    echo "   netra -t example.com --profile deep"
    echo ""
    echo "6. Access the web dashboard:"
    echo "   http://localhost:5173"
    echo ""
    echo "7. Monitor Celery tasks:"
    echo "   http://localhost:5555"
    echo ""
    echo "8. Configure integrations:"
    echo "   - Slack: Set NETRA_SLACK_WEBHOOK_URL in .env"
    echo "   - Email: Set NETRA_SMTP_* in .env"
    echo "   - DefectDojo: Set NETRA_DEFECTDOJO_* in .env"
    echo "   - Jira: Set NETRA_JIRA_* in .env"
    echo ""
    echo -e "${CYAN}Documentation:${NC}"
    echo "   https://github.com/yashwg/netra#readme"
    echo ""
    echo -e "${CYAN}Report issues:${NC}"
    echo "   https://github.com/yashwg/netra/issues"
    echo ""
}

# Main installation flow
main() {
    log_info "=========================================="
    log_info "NETRA Installation (Phase 4)"
    log_info "=========================================="
    echo ""

    log_phase "Step 1/10: Detecting OS"
    detect_os
    
    log_phase "Step 2/10: Checking Python"
    check_python
    
    log_phase "Step 3/10: Installing Go"
    install_go
    
    log_phase "Step 4/10: Installing Go tools"
    install_go_tools
    
    log_phase "Step 5/10: Installing system tools"
    install_system_tools
    
    log_phase "Step 6/10: Installing Ollama"
    install_ollama
    
    log_phase "Step 7/10: Installing Redis"
    install_redis
    
    log_phase "Step 8/10: Creating directories"
    create_directory_structure
    
    log_phase "Step 9/10: Installing NETRA"
    install_netra
    
    log_phase "Step 10/10: Running migrations"
    run_migrations
    
    setup_env

    print_success_message
    log_success "All installations complete!"
}

# Run main installation
main "$@"
