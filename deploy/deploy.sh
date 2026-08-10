#!/bin/bash
# =============================================================================
# Email Forensic Analyzer - Deployment Script
# =============================================================================
# This script automates the deployment of the Email Forensic Analyzer
# on a Linux server (tested on Ubuntu/Debian, compatible with Proxmox)
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh [install|update|start|stop|restart|status]
# =============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/email-analyzer"
REPO_URL="https://github.com/CapePouvoir/email-analyzer.git"
SERVICE_NAME="email-analyzer"
PYTHON_VERSION="3.10"

# =============================================================================
# Functions
# =============================================================================

# Print colored messages
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root. Use: sudo ./deploy.sh"
    fi
}

# Check dependencies
check_dependencies() {
    info "Checking dependencies..."
    
    # Check git
    if ! command -v git &> /dev/null; then
        error "git is not installed. Install with: apt install git"
    fi
    
    # Check Python
    if ! command -v python${PYTHON_VERSION} &> /dev/null; then
        error "Python ${PYTHON_VERSION} is not installed. Install with: apt install python${PYTHON_VERSION} python${PYTHON_VERSION}-venv python${PYTHON_VERSION}-dev"
    fi
    
    # Check curl (for Ollama)
    if ! command -v curl &> /dev/null; then
        error "curl is not installed. Install with: apt install curl"
    fi
    
    success "All dependencies are installed"
}

# Clone or update repository
setup_repository() {
    info "Setting up repository..."
    
    if [ -d "$INSTALL_DIR" ]; then
        info "Directory exists. Pulling latest changes..."
        cd "$INSTALL_DIR"
        git pull origin main
    else
        info "Cloning repository..."
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
    
    success "Repository is ready at $INSTALL_DIR"
}

# Install Python dependencies
install_python_deps() {
    info "Installing Python dependencies..."
    
    cd "$INSTALL_DIR"
    
    # Create virtual environment
    if [ ! -d ".venv" ]; then
        info "Creating virtual environment..."
        python${PYTHON_VERSION} -m venv .venv
    fi
    
    # Install requirements
    info "Installing Python packages..."
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install -r backend/requirements.txt
    
    success "Python dependencies installed"
}

# Install Ollama
install_ollama() {
    info "Installing Ollama..."
    
    if command -v ollama &> /dev/null; then
        info "Ollama is already installed"
    else
        info "Downloading and installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        
        # Add to PATH for current session
        export PATH="$HOME/.local/bin:$PATH"
        
        success "Ollama installed successfully"
    fi
    
    # Pull default model (Mistral)
    info "Pulling Mistral model (this may take a few minutes)..."
    ollama pull mistral || warning "Failed to pull Mistral model. You can do it manually with: ollama pull mistral"
    
    success "Ollama is ready"
}

# Create data directories
create_directories() {
    info "Creating data directories..."
    
    cd "$INSTALL_DIR"
    
    # Create uploads directory
    mkdir -p data/uploads
    chmod 750 data/uploads
    
    # Create logs directory
    mkdir -p logs
    
    success "Directories created"
}

# Configure environment
configure_environment() {
    info "Configuring environment..."
    
    cd "$INSTALL_DIR"
    
    # Copy .env.example to .env if it doesn't exist
    if [ ! -f ".env" ]; then
        info "Creating .env file from template..."
        cp .env.example .env
        
        # Generate a random admin password
        ADMIN_PASSWORD=$(openssl rand -hex 16)
        sed -i "s/ADMIN_PASSWORD=changeme/ADMIN_PASSWORD=$ADMIN_PASSWORD/" .env
        
        warning "Generated random admin password: $ADMIN_PASSWORD"
        warning "Save it somewhere safe! You can change it later in the .env file."
    fi
    
    success "Environment configured"
}

# Setup systemd service
setup_service() {
    info "Setting up systemd service..."
    
    # Copy service file
    cp deploy/email-analyzer.service /etc/systemd/system/${SERVICE_NAME}.service
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    
    success "Service ${SERVICE_NAME} is enabled and started"
}

# Setup cleanup cron job
setup_cleanup() {
    info "Setting up automatic cleanup..."
    
    # Create cleanup script
    cat > /usr/local/bin/cleanup-uploads.sh << 'EOF'
#!/bin/bash
# Cleanup old uploads
INSTALL_DIR="/opt/email-analyzer"
CLEANUP_DAYS=7

cd "$INSTALL_DIR"
find data/uploads -type f -mtime +$CLEANUP_DAYS -delete 2>/dev/null
EOF
    
    chmod +x /usr/local/bin/cleanup-uploads.sh
    
    # Add cron job (runs daily at 3 AM)
    if ! crontab -l | grep -q "cleanup-uploads"; then
        (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/cleanup-uploads.sh") | crontab -
        info "Cron job added for daily cleanup at 3 AM"
    fi
    
    success "Automatic cleanup configured"
}

# Display status
show_status() {
    info "Checking service status..."
    
    systemctl status ${SERVICE_NAME} --no-pager
    
    info "Ollama status:"
    ollama list || echo "Ollama is not running or no models pulled"
    
    info "Application logs:"
    journalctl -u ${SERVICE_NAME} -n 20 --no-pager
}

# =============================================================================
# Main
# =============================================================================

# Parse arguments
ACTION=${1:-install}

case "$ACTION" in
    install)
        check_root
        check_dependencies
        setup_repository
        install_python_deps
        install_ollama
        create_directories
        configure_environment
        setup_service
        setup_cleanup
        
        echo ""
        success "=========================================="
        success "Email Forensic Analyzer deployed successfully!"
        success "=========================================="
        echo ""
        info "Access the application at: http://$(hostname -I | awk '{print $1}'):8000"
        info "Admin password is in: $INSTALL_DIR/.env"
        ;;
    update)
        check_root
        setup_repository
        install_python_deps
        systemctl restart ${SERVICE_NAME}
        success "Application updated"
        ;;
    start)
        check_root
        systemctl start ${SERVICE_NAME}
        success "Service started"
        ;;
    stop)
        check_root
        systemctl stop ${SERVICE_NAME}
        success "Service stopped"
        ;;
    restart)
        check_root
        systemctl restart ${SERVICE_NAME}
        success "Service restarted"
        ;;
    status)
        check_root
        show_status
        ;;
    *)
        echo "Usage: $0 [install|update|start|stop|restart|status]"
        echo ""
        echo "Commands:"
        echo "  install   - Full installation (default)"
        echo "  update    - Update the application"
        echo "  start     - Start the service"
        echo "  stop      - Stop the service"
        echo "  restart   - Restart the service"
        echo "  status    - Show service status"
        exit 1
        ;;
esac
