#!/usr/bin/env bash
################################################################################
#
#   VPS HARDENING SCRIPT - ENHANCED EDITION
#   Comprehensive Server Security Hardening Tool
#
#   Original Script + Full Enhancements Integrated
#   Compatible: Debian 10/11/12, Ubuntu 20.04/22.04/24.04
#
#   Features:
#     - Tier 0: Essential (SSH, UFW, Fail2ban, Kernel, Auto-Updates)
#     - Tier 1: High Impact (AppArmor, AIDE, auditd, /dev/shm, protocols)
#     - Tier 2: Advanced (Resource limits, DNS-over-TLS, Lynis, lockdown)
#     - Tier 3: Zero Trust (Tailscale, fwknop SPA)
#     - Bonus: Login security, user hardening, log forwarding, snapshots
#
#   Usage: sudo bash harden.sh
#
################################################################################

# ============================================================================
# STRICT ERROR HANDLING
# ============================================================================
set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# COLOR DEFINITIONS
# ============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;37m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly UNDERLINE='\033[4m'
readonly BLINK='\033[5m'
readonly NC='\033[0m' # No Color

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================
readonly SCRIPT_VERSION="2.0.0-enhanced"
readonly SCRIPT_NAME="VPS Hardening Script"
readonly SCRIPT_DATE="$(date +%Y-%m-%d)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

readonly LOG_FILE="/var/log/vps-hardening.log"
readonly BACKUP_DIR="/root/.vps-hardening-backups/${TIMESTAMP}"
readonly STATE_FILE="/var/lib/vps-hardening/state.conf"
readonly REPORT_FILE="/root/vps-hardening-report-${TIMESTAMP}.txt"

# Global operational variables (mutable)
SSH_PORT=""
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME="$(eval echo "~${TARGET_USER}")"
OS_ID=""
OS_VERSION=""
OS_NAME=""
OS_CODENAME=""
KERNEL_VERSION="$(uname -r)"
ARCH="$(uname -m)"

# Feature tracking
declare -A COMPLETED_TASKS
declare -A FAILED_TASKS

# Set noninteractive apt mode
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_MODE=a

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

init_logging() {
    # Create log directory if needed
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$STATE_FILE")"
    
    # Initialize log file
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    
    # Log script start
    {
        echo "================================================================"
        echo "  VPS Hardening Script - Session Started"
        echo "  Version: ${SCRIPT_VERSION}"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  User: ${TARGET_USER}"
        echo "  Host: $(hostname)"
        echo "================================================================"
    } >> "$LOG_FILE"
}

log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}" >> "$LOG_FILE"
}

log_info()    { log "INFO"    "$1"; }
log_warn()    { log "WARN"    "$1"; }
log_error()   { log "ERROR"   "$1"; }
log_success() { log "SUCCESS" "$1"; }
log_debug()   { log "DEBUG"   "$1"; }

# ============================================================================
# OUTPUT FORMATTING FUNCTIONS
# ============================================================================

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║          VPS HARDENING SCRIPT - ENHANCED EDITION v2.0            ║
    ║                                                                  ║
    ║              Comprehensive Server Security Toolkit               ║
    ║                                                                  ║
    ║   ┌────────────────────────────────────────────────────────┐   ║
    ║   │  Tier 0: Essential Hardening                           │   ║
    ║   │  Tier 1: High Impact Defenses                          │   ║
    ║   │  Tier 2: Advanced Security Controls                    │   ║
    ║   │  Tier 3: Zero Trust Networking                         │   ║
    ║   └────────────────────────────────────────────────────────┘   ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "  ${YELLOW}${BOLD}⚠  IMPORTANT NOTICES:${NC}"
    echo -e "  ${YELLOW}• This script must be run as root or with sudo${NC}"
    echo -e "  ${YELLOW}• All configurations are backed up before modification${NC}"
    echo -e "  ${YELLOW}• Test SSH access in a NEW terminal before disconnecting${NC}"
    echo -e "  ${YELLOW}• Review the log file: ${LOG_FILE}${NC}"
    echo ""
}

print_section() {
    local title="$1"
    local width=68
    local title_len=${#title}
    local padding=$(( (width - title_len - 2) / 2 ))
    
    echo ""
    echo -e "${BLUE}${BOLD}$(printf '━%.0s' $(seq 1 $width))${NC}"
    echo -e "${BLUE}${BOLD}$(printf ' %.0s' $(seq 1 $padding))${WHITE}${title}${BLUE}$(printf ' %.0s' $(seq 1 $padding))${NC}"
    echo -e "${BLUE}${BOLD}$(printf '━%.0s' $(seq 1 $width))${NC}"
    echo ""
}

print_subsection() {
    echo ""
    echo -e "  ${CYAN}${BOLD}▸ $1${NC}"
    echo -e "  ${DIM}$(printf '─%.0s' $(seq 1 60))${NC}"
}

print_status() {
    echo -e "  ${GREEN}${BOLD}[✔]${NC} $1"
    log_success "$1"
}

print_warning() {
    echo -e "  ${YELLOW}${BOLD}[⚠]${NC} $1"
    log_warn "$1"
}

print_error() {
    echo -e "  ${RED}${BOLD}[✘]${NC} $1"
    log_error "$1"
}

print_info() {
    echo -e "  ${CYAN}${BOLD}[ℹ]${NC} $1"
    log_info "$1"
}

print_step() {
    echo -e "  ${MAGENTA}${BOLD}[→]${NC} $1"
    log_info "STEP: $1"
}

print_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "  ${GRAY}${DIM}[DEBUG]${NC} $1"
    fi
    log_debug "$1"
}

print_separator() {
    echo -e "  ${DIM}$(printf '─%.0s' $(seq 1 66))${NC}"
}

# ============================================================================
# INTERACTIVE PROMPTS
# ============================================================================

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local response=""
    local hint=""
    
    if [[ "$default" == "y" ]]; then
        hint="[Y/n]"
    else
        hint="[y/N]"
    fi
    
    while true; do
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt} ${hint}: "
        read -r response
        response="${response:-$default}"
        
        case "${response,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *) print_warning "Please answer yes or no." ;;
        esac
    done
}

prompt_input() {
    local prompt="$1"
    local default="${2:-}"
    local variable_name="$3"
    local response=""
    
    if [[ -n "$default" ]]; then
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt} [default: ${default}]: "
    else
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt}: "
    fi
    
    read -r response
    response="${response:-$default}"
    
    # Set the variable using indirect reference
    printf -v "$variable_name" '%s' "$response"
}

prompt_password() {
    local prompt="$1"
    local variable_name="$2"
    local response=""
    
    echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt}: "
    read -rs response
    echo ""
    
    printf -v "$variable_name" '%s' "$response"
}

prompt_menu() {
    local prompt="$1"
    shift
    local options=("$@")
    local choice=""
    
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} ${prompt}"
    for i in "${!options[@]}"; do
        echo -e "      ${CYAN}$((i+1)))${NC} ${options[$i]}"
    done
    
    while true; do
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} Select option [1-${#options[@]}]: "
        read -r choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            echo "$((choice-1))"
            return 0
        else
            print_warning "Invalid selection. Please try again."
        fi
    done
}

pause() {
    echo ""
    echo -ne "  ${DIM}Press ${BOLD}Enter${NC}${DIM} to continue...${NC}"
    read -r
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "This script must be run as root."
        echo -e "  ${YELLOW}Please run with: ${BOLD}sudo bash $0${NC}"
        exit 1
    fi
}

check_internet() {
    print_step "Checking internet connectivity..."
    if ping -c 1 -W 3 8.8.8.8 &>/dev/null || ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
        print_status "Internet connection is active"
        return 0
    else
        print_error "No internet connection detected"
        print_warning "Some operations require internet access"
        if ! confirm "Continue anyway?"; then
            exit 1
        fi
    fi
}

detect_os() {
    print_step "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_NAME="${PRETTY_NAME:-unknown}"
        OS_CODENAME="${VERSION_CODENAME:-unknown}"
    else
        print_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    
    # Check for supported OS
    case "$OS_ID" in
        ubuntu|debian)
            print_status "Detected: ${OS_NAME}"
            print_info "Codename: ${OS_CODENAME} | Kernel: ${KERNEL_VERSION} | Arch: ${ARCH}"
            ;;
        *)
            print_warning "OS '${OS_ID}' is not officially tested."
            print_warning "This script is optimized for Debian/Ubuntu."
            if ! confirm "Continue anyway?"; then
                exit 1
            fi
            ;;
    esac
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra parts <<< "$ip"
        for part in "${parts[@]}"; do
            if [ "$part" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

validate_hostname() {
    local hostname="$1"
    if [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$ ]]; then
        return 0
    else
        return 1
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

service_exists() {
    systemctl list-unit-files "$1.service" &>/dev/null 2>&1
}

service_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

package_installed() {
    dpkg -l "$1" &>/dev/null 2>&1
}

# ============================================================================
# BACKUP & STATE MANAGEMENT
# ============================================================================

create_backup_dir() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"
        print_info "Backup directory: ${BACKUP_DIR}"
        log_info "Backup directory created: ${BACKUP_DIR}"
    fi
}

backup_file() {
    local file="$1"
    
    if [ -z "$file" ]; then
        return 1
    fi
    
    if [ -f "$file" ] || [ -d "$file" ]; then
        create_backup_dir
        local backup_path="${BACKUP_DIR}$(dirname "$file")"
        mkdir -p "$backup_path"
        cp -rp "$file" "$backup_path/" 2>/dev/null || true
        log_debug "Backed up: $file -> $backup_path/"
        return 0
    fi
    
    return 1
}

backup_directory() {
    local dir="$1"
    
    if [ -d "$dir" ]; then
        create_backup_dir
        local backup_path="${BACKUP_DIR}$(dirname "$dir")"
        mkdir -p "$backup_path"
        cp -rp "$dir" "$backup_path/" 2>/dev/null || true
        log_debug "Backed up directory: $dir"
        return 0
    fi
    
    return 1
}

save_state() {
    local key="$1"
    local value="$2"
    
    mkdir -p "$(dirname "$STATE_FILE")"
    touch "$STATE_FILE"
    
    # Remove existing entry if present
    sed -i "/^${key}=/d" "$STATE_FILE" 2>/dev/null || true
    
    # Add new entry
    echo "${key}=${value}" >> "$STATE_FILE"
    chmod 600 "$STATE_FILE"
}

load_state() {
    local key="$1"
    
    if [ -f "$STATE_FILE" ]; then
        grep "^${key}=" "$STATE_FILE" 2>/dev/null | cut -d'=' -f2- | tail -1
    fi
}

mark_completed() {
    local task="$1"
    COMPLETED_TASKS["$task"]="$(date '+%Y-%m-%d %H:%M:%S')"
    save_state "COMPLETED_${task}" "$(date '+%Y-%m-%d %H:%M:%S')"
}

mark_failed() {
    local task="$1"
    local reason="${2:-Unknown error}"
    FAILED_TASKS["$task"]="$reason"
    save_state "FAILED_${task}" "$reason"
}

is_completed() {
    local task="$1"
    [ -n "${COMPLETED_TASKS[$task]:-}" ] || [ -n "$(load_state "COMPLETED_${task}")" ]
}

# ============================================================================
# ERROR HANDLING & CLEANUP
# ============================================================================

cleanup_on_exit() {
    local exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        log_error "Script exited with code: $exit_code"
        echo ""
        print_error "Script exited unexpectedly (exit code: $exit_code)"
        print_info "Check the log file: ${LOG_FILE}"
        print_info "Backups are stored in: ${BACKUP_DIR}"
    fi
    
    # Reset terminal
    echo -e "${NC}"
}

trap cleanup_on_exit EXIT
trap 'log_error "Interrupted by user"; exit 130' INT
trap 'log_error "Terminated"; exit 143' TERM

# ============================================================================
# TIER 0: ESSENTIAL HARDENING FUNCTIONS
# ============================================================================

# ----------------------------------------------------------------------------
# Function: system_update
# Purpose: Update system packages and clean unnecessary files
# ----------------------------------------------------------------------------
system_update() {
    print_section "SYSTEM UPDATE & CLEANUP"
    
    print_step "Updating package repository lists..."
    if apt-get update -y >> "$LOG_FILE" 2>&1; then
        print_status "Package lists updated successfully"
    else
        print_error "Failed to update package lists"
        mark_failed "system_update" "apt-get update failed"
        return 1
    fi
    
    print_step "Upgrading installed packages (this may take a while)..."
    if apt-get -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                upgrade -y >> "$LOG_FILE" 2>&1; then
        print_status "System packages upgraded successfully"
    else
        print_error "Failed to upgrade packages"
        mark_failed "system_update" "apt-get upgrade failed"
        return 1
    fi
    
    if confirm "Perform full distribution upgrade (dist-upgrade)?" "n"; then
        print_step "Performing distribution upgrade..."
        if apt-get -o Dpkg::Options::="--force-confdef" \
                    -o Dpkg::Options::="--force-confold" \
                    dist-upgrade -y >> "$LOG_FILE" 2>&1; then
            print_status "Distribution upgrade completed"
        else
            print_warning "Distribution upgrade had issues (see log)"
        fi
    fi
    
    print_step "Removing unnecessary packages..."
    apt-get autoremove -y >> "$LOG_FILE" 2>&1 || true
    apt-get autoclean -y >> "$LOG_FILE" 2>&1 || true
    apt-get clean >> "$LOG_FILE" 2>&1 || true
    print_status "System cleaned"
    
    # Install essential utilities
    print_step "Installing essential utility packages..."
    local essential_packages=(
        curl wget git vim nano htop
        net-tools dnsutils
        gnupg2 ca-certificates
        software-properties-common
        apt-transport-https
        unzip zip
        rsync
    )
    
    for pkg in "${essential_packages[@]}"; do
        if ! package_installed "$pkg"; then
            apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || \
                print_warning "Failed to install: $pkg"
        fi
    done
    print_status "Essential utilities installed"
    
    mark_completed "system_update"
}

# ----------------------------------------------------------------------------
# Function: harden_ssh
# Purpose: Comprehensive SSH hardening with lockout prevention
# ----------------------------------------------------------------------------
harden_ssh() {
    print_section "SSH HARDENING"
    
    # Install SSH server if not present
    if ! package_installed "openssh-server"; then
        print_step "Installing OpenSSH server..."
        apt-get install -y openssh-server >> "$LOG_FILE" 2>&1
    fi
    
    print_subsection "SSH Port Configuration"
    
    # Show current SSH port
    local current_port
    current_port=$(grep -h "^Port " /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | \
                   head -1 | awk '{print $2}' || echo "22")
    print_info "Current SSH port: ${current_port}"
    
    # Get new SSH port
    while true; do
        prompt_input "Enter desired SSH port" "2222" SSH_PORT
        if validate_port "$SSH_PORT"; then
            if [ "$SSH_PORT" -eq 22 ]; then
                print_warning "Port 22 is the default and frequently attacked."
                if ! confirm "Are you sure you want to use port 22?" "n"; then
                    continue
                fi
            fi
            break
        else
            print_error "Invalid port. Must be 1-65535."
        fi
    done
    
    save_state "SSH_PORT" "$SSH_PORT"
    
    print_subsection "SSH Key Validation"
    
    # Check for existing SSH keys
    local AUTH_KEYS="${USER_HOME}/.ssh/authorized_keys"
    local disable_password="yes"
    local key_count=0
    
    if [ -f "$AUTH_KEYS" ] && [ -s "$AUTH_KEYS" ]; then
        key_count=$(grep -cve '^\s*$\|^\s*#' "$AUTH_KEYS" 2>/dev/null || echo "0")
        print_status "Found ${key_count} SSH key(s) for user: ${TARGET_USER}"
        
        # Display key fingerprints
        if [ "$key_count" -gt 0 ]; then
            print_info "Key fingerprints:"
            while IFS= read -r key_line; do
                if [ -n "$key_line" ] && [[ ! "$key_line" =~ ^# ]]; then
                    local fingerprint
                    fingerprint=$(echo "$key_line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2, $NF}' || echo "invalid key")
                    echo -e "      ${GRAY}• ${fingerprint}${NC}"
                fi
            done < "$AUTH_KEYS"
        fi
    else
        print_warning "No SSH keys found in ${AUTH_KEYS}"
        print_warning "═══════════════════════════════════════════════════════════"
        print_warning "  CRITICAL: Disabling password authentication without SSH"
        print_warning "  keys will PERMANENTLY LOCK YOU OUT of this server!"
        print_warning "═══════════════════════════════════════════════════════════"
        
        if confirm "Do you want to add an SSH key now?" "y"; then
            add_ssh_key
            # Re-check after adding
            if [ -f "$AUTH_KEYS" ] && [ -s "$AUTH_KEYS" ]; then
                key_count=$(grep -cve '^\s*$\|^\s*#' "$AUTH_KEYS" 2>/dev/null || echo "0")
                if [ "$key_count" -eq 0 ]; then
                    disable_password="no"
                fi
            else
                disable_password="no"
            fi
        else
            disable_password="no"
            print_warning "Password authentication will remain ENABLED"
        fi
    fi
    
    print_subsection "Applying SSH Configuration"
    
    # Backup original configuration
    backup_file /etc/ssh/sshd_config
    backup_directory /etc/ssh/sshd_config.d
    
    # Create drop-in configuration directory
    mkdir -p /etc/ssh/sshd_config.d
    chmod 755 /etc/ssh/sshd_config.d
    
    # Build the hardening configuration
    local password_auth_value="no"
    [ "$disable_password" = "no" ] && password_auth_value="yes"
    
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
# ============================================================
# VPS Hardening - SSH Security Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# --- Network ---
Port ${SSH_PORT}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# --- Protocol ---
Protocol 2

# --- Authentication ---
PermitRootLogin no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
StrictModes yes
PermitEmptyPasswords no

# --- Password Authentication ---
PasswordAuthentication ${password_auth_value}
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# --- Public Key Authentication ---
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# --- Host-Based Authentication ---
HostbasedAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts yes

# --- Kerberos & GSSAPI (disable if not used) ---
KerberosAuthentication no
GSSAPIAuthentication no

# --- Forwarding & Tunneling ---
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# --- User Environment ---
PermitUserEnvironment no
PermitUserRC no

# --- Session Timeouts ---
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# --- Logging ---
SyslogFacility AUTH
LogLevel VERBOSE

# --- Ciphers & Algorithms (Modern, Secure) ---
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# --- Banner ---
Banner /etc/issue.net

# --- DNS ---
UseDNS no

# --- Misc ---
Compression no
PrintMotd no
PrintLastLog yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    
    chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf
    print_status "SSH hardening configuration created"
    
    # Create warning banner
    cat > /etc/issue.net << 'EOF'
################################################################
#                                                              #
#           AUTHORIZED ACCESS ONLY                             #
#                                                              #
#  This system is restricted to authorized users only.         #
#  All activities are monitored, logged, and audited.          #
#  Unauthorized access is strictly prohibited and will be      #
#  prosecuted to the fullest extent of the law.                #
#                                                              #
#  By accessing this system, you consent to monitoring.        #
#                                                              #
################################################################
EOF
    chmod 644 /etc/issue.net
    print_status "Login banner created"
    
    # Handle Ubuntu 24.04+ socket activation
    print_subsection "Systemd Socket Activation Check"
    
    if service_active "ssh.socket"; then
        print_info "Detected systemd socket activation (Ubuntu 24.04+ style)"
        print_step "Creating socket override for port ${SSH_PORT}..."
        
        mkdir -p /etc/systemd/system/ssh.socket.d
        cat > /etc/systemd/system/ssh.socket.d/override.conf << EOF
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
        chmod 644 /etc/systemd/system/ssh.socket.d/override.conf
        systemctl daemon-reload
        print_status "SSH socket override configured"
    else
        print_info "Using traditional ssh.service (no socket activation)"
    fi
    
    # Validate SSH configuration before restarting
    print_subsection "Configuration Validation"
    
    print_step "Testing SSH configuration syntax..."
    if sshd -t 2>>"$LOG_FILE"; then
        print_status "SSH configuration syntax is valid"
        
        print_step "Restarting SSH service..."
        if service_active "ssh.socket"; then
            systemctl restart ssh.socket
            print_status "ssh.socket restarted"
        fi
        
        if service_active "ssh"; then
            systemctl restart ssh
            print_status "ssh service restarted"
        elif service_active "sshd"; then
            systemctl restart sshd
            print_status "sshd service restarted"
        fi
        
        # Verify SSH is listening on new port
        sleep 2
        if ss -tlnp | grep -q ":${SSH_PORT} "; then
            print_status "SSH is now listening on port ${SSH_PORT}"
        else
            print_warning "SSH may not be listening on port ${SSH_PORT} yet"
            print_info "Verify with: ss -tlnp | grep ssh"
        fi
        
        mark_completed "harden_ssh"
    else
        print_error "SSH configuration test FAILED!"
        print_step "Reverting changes..."
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
        rm -rf /etc/systemd/system/ssh.socket.d
        systemctl daemon-reload 2>/dev/null || true
        print_error "Configuration reverted. Please check the log file."
        mark_failed "harden_ssh" "Configuration syntax error"
        return 1
    fi
    
    # Final warnings
    echo ""
    print_warning "═══════════════════════════════════════════════════════════"
    print_warning "  IMPORTANT: Test SSH access in a NEW terminal before"
    print_warning "  closing this session!"
    print_warning ""
    print_warning "  Command: ssh -p ${SSH_PORT} ${TARGET_USER}@$(hostname -I | awk '{print $1}')"
    print_warning "═══════════════════════════════════════════════════════════"
    
    if [ "$disable_password" = "no" ]; then
        echo ""
        print_warning "Password authentication is still ENABLED."
        print_warning "To disable it later:"
        print_warning "  1. Add your SSH public key to ~/.ssh/authorized_keys"
        print_warning "  2. Re-run SSH hardening (menu option 2)"
    fi
}

# ----------------------------------------------------------------------------
# Function: add_ssh_key
# Purpose: Helper function to add SSH keys interactively
# ----------------------------------------------------------------------------
add_ssh_key() {
    print_subsection "Add SSH Public Key"
    
    # Ensure .ssh directory exists
    local ssh_dir="${USER_HOME}/.ssh"
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir"
        chown "${TARGET_USER}:${TARGET_USER}" "$ssh_dir"
        chmod 700 "$ssh_dir"
        print_status "Created ${ssh_dir}"
    fi
    
    # Ensure authorized_keys exists
    local auth_keys="${ssh_dir}/authorized_keys"
    if [ ! -f "$auth_keys" ]; then
        touch "$auth_keys"
        chown "${TARGET_USER}:${TARGET_USER}" "$auth_keys"
        chmod 600 "$auth_keys"
    fi
    
    print_info "Paste your SSH public key below (ssh-rsa, ssh-ed25519, ecdsa-*)"
    print_info "Press Enter twice when done, or type 'skip' to skip:"
    echo ""
    
    local ssh_key=""
    read -r ssh_key
    
    if [ "$ssh_key" = "skip" ] || [ -z "$ssh_key" ]; then
        print_warning "Skipped SSH key addition"
        return 1
    fi
    
    # Validate key format
    if echo "$ssh_key" | ssh-keygen -lf - &>/dev/null; then
        echo "$ssh_key" >> "$auth_keys"
        chown "${TARGET_USER}:${TARGET_USER}" "$auth_keys"
        chmod 600 "$auth_keys"
        
        local fingerprint
        fingerprint=$(echo "$ssh_key" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
        print_status "SSH key added successfully"
        print_info "Fingerprint: ${fingerprint}"
        return 0
    else
        print_error "Invalid SSH key format"
        return 1
    fi
}

# End of Section 1
# ============================================================================
# TIER 0 CONTINUED: FIREWALL, FAIL2BAN, KERNEL, AUTO-UPDATES, USER SETUP
# ============================================================================

# ----------------------------------------------------------------------------
# Function: configure_firewall
# Purpose: Configure UFW firewall with interactive port selection
# ----------------------------------------------------------------------------
configure_firewall() {
    print_section "FIREWALL CONFIGURATION (UFW)"
    
    # Install UFW if not present
    if ! command_exists ufw; then
        print_step "Installing UFW..."
        apt-get install -y ufw >> "$LOG_FILE" 2>&1
        print_status "UFW installed"
    fi
    
    # Determine SSH port
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        if [ -z "$SSH_PORT" ]; then
            prompt_input "Enter your SSH port" "2222" SSH_PORT
        fi
    fi
    
    print_subsection "Current Firewall Status"
    ufw status verbose 2>/dev/null || print_info "UFW is not yet configured"
    
    print_subsection "Firewall Configuration"
    
    if confirm "Reset UFW to clean state before configuring?" "n"; then
        print_step "Resetting UFW..."
        ufw --force reset >> "$LOG_FILE" 2>&1
        print_status "UFW reset to defaults"
    fi
    
    # Default policies
    print_step "Setting default policies..."
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    print_status "Default: DENY incoming, ALLOW outgoing"
    
    # Rate limit SSH
    print_step "Configuring SSH access on port ${SSH_PORT}..."
    ufw limit "${SSH_PORT}/tcp" comment "SSH (rate-limited)" >> "$LOG_FILE" 2>&1
    print_status "SSH allowed on port ${SSH_PORT} with rate limiting"
    
    # Standard web services
    print_subsection "Common Service Ports"
    
    if confirm "Allow HTTP (port 80)?"; then
        ufw allow 80/tcp comment "HTTP" >> "$LOG_FILE" 2>&1
        print_status "Allowed HTTP (80)"
    fi
    
    if confirm "Allow HTTPS (port 443)?"; then
        ufw allow 443/tcp comment "HTTPS" >> "$LOG_FILE" 2>&1
        print_status "Allowed HTTPS (443)"
    fi
    
    # Custom ports
    print_subsection "Custom Port Configuration"
    
    if confirm "Add custom ports?"; then
        while true; do
            local custom_port=""
            prompt_input "Enter port number (or 'done' to finish)" "" custom_port
            
            if [ "$custom_port" = "done" ] || [ -z "$custom_port" ]; then
                break
            fi
            
            if ! validate_port "$custom_port"; then
                print_error "Invalid port: ${custom_port}. Must be 1-65535."
                continue
            fi
            
            local proto=""
            prompt_input "Protocol (tcp/udp/both)" "tcp" proto
            
            local comment=""
            prompt_input "Description/comment" "Custom" comment
            
            case "$proto" in
                both)
                    ufw allow "$custom_port" comment "$comment" >> "$LOG_FILE" 2>&1
                    print_status "Allowed ${custom_port} (tcp+udp) - ${comment}"
                    ;;
                tcp|udp)
                    ufw allow "${custom_port}/${proto}" comment "$comment" >> "$LOG_FILE" 2>&1
                    print_status "Allowed ${custom_port}/${proto} - ${comment}"
                    ;;
                *)
                    print_error "Invalid protocol. Skipping."
                    ;;
            esac
        done
    fi
    
    # ICMP rate limiting (optional)
    print_subsection "ICMP Configuration"
    
    if confirm "Rate-limit ICMP (ping) to prevent flood attacks?"; then
        # UFW doesn't directly rate-limit ICMP, but we can allow it
        ufw allow proto icmp comment "ICMP" >> "$LOG_FILE" 2>&1
        print_status "ICMP allowed (kernel sysctl handles rate limiting)"
    fi
    
    # IPv6 support
    if confirm "Enable IPv6 firewall rules?"; then
        backup_file /etc/default/ufw
        sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
        print_status "IPv6 firewall rules enabled"
    fi
    
    # Enable UFW
    print_subsection "Activating Firewall"
    
    if confirm "Enable UFW now? (CRITICAL: ensure SSH port is correct!)" "y"; then
        ufw --force enable >> "$LOG_FILE" 2>&1
        print_status "UFW firewall is now ACTIVE"
    else
        print_warning "UFW is configured but NOT enabled"
        print_info "Enable manually with: ufw enable"
    fi
    
    # Show final status
    echo ""
    print_info "Final firewall rules:"
    ufw status numbered
    
    mark_completed "configure_firewall"
}

# ----------------------------------------------------------------------------
# Function: setup_fail2ban
# Purpose: Install and configure Fail2ban with proper drop-in configuration
# ----------------------------------------------------------------------------
setup_fail2ban() {
    print_section "FAIL2BAN CONFIGURATION"
    
    # Install Fail2ban
    if ! command_exists fail2ban-client; then
        print_step "Installing Fail2ban..."
        apt-get install -y fail2ban >> "$LOG_FILE" 2>&1
        print_status "Fail2ban installed"
    fi
    
    # Determine SSH port
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        if [ -z "$SSH_PORT" ]; then
            prompt_input "Enter your SSH port" "2222" SSH_PORT
        fi
    fi
    
    print_subsection "Fail2ban Parameters"
    
    local bantime="" findtime="" maxretry=""
    prompt_input "Ban duration in minutes" "60" bantime
    prompt_input "Detection window in minutes" "10" findtime
    prompt_input "Max failed attempts before ban" "4" maxretry
    
    # Detect log backend
    local backend="auto"
    if service_active "systemd-journald"; then
        backend="systemd"
        print_info "Detected systemd journal backend"
    else
        backend="auto"
        print_info "Using auto-detect log backend"
    fi
    
    # Detect ban action
    local banaction="ufw"
    if ! command_exists ufw; then
        banaction="iptables-multiport"
        print_info "UFW not found, using iptables ban action"
    fi
    
    print_subsection "Applying Configuration"
    
    # Backup original configs
    backup_file /etc/fail2ban/jail.conf
    backup_directory /etc/fail2ban/jail.d
    
    # Create drop-in configuration (never modify jail.conf directly)
    mkdir -p /etc/fail2ban/jail.d
    
    cat > /etc/fail2ban/jail.d/00-hardening-defaults.local << EOF
# ============================================================
# VPS Hardening - Fail2ban Default Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

[DEFAULT]
bantime  = ${bantime}m
findtime = ${findtime}m
maxretry = ${maxretry}
banaction = ${banaction}
backend = ${backend}
destemail = root@localhost
sender = fail2ban@$(hostname)
action = %(action_mwl)s
ignoreip = 127.0.0.1/8 ::1
EOF
    
    chmod 644 /etc/fail2ban/jail.d/00-hardening-defaults.local
    print_status "Default parameters configured"
    
    # SSH jail
    cat > /etc/fail2ban/jail.d/10-sshd.local << EOF
# SSH Protection
[sshd]
enabled = true
port    = ${SSH_PORT}
filter  = sshd
logpath = %(sshd_log)s
maxretry = ${maxretry}
bantime  = ${bantime}m
EOF
    
    chmod 644 /etc/fail2ban/jail.d/10-sshd.local
    print_status "SSH jail configured for port ${SSH_PORT}"
    
    # Optional additional jails
    print_subsection "Additional Jails"
    
    if confirm "Enable protection against web server attacks (nginx/apache)?" "n"; then
        cat > /etc/fail2ban/jail.d/20-webserver.local << 'EOF'
# Web Server Protection
[nginx-http-auth]
enabled = true
port    = http,https
filter  = nginx-http-auth
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
port    = http,https
filter  = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2

[apache-auth]
enabled = true
port    = http,https
filter  = apache-auth
logpath = /var/log/apache2/error.log
EOF
        chmod 644 /etc/fail2ban/jail.d/20-webserver.local
        print_status "Web server jails configured"
    fi
    
    if confirm "Enable protection against postfix/dovecot brute force?" "n"; then
        cat > /etc/fail2ban/jail.d/30-mail.local << 'EOF'
# Mail Server Protection
[postfix]
enabled = true
port    = smtp,465,submission
filter  = postfix
logpath = /var/log/mail.log

[dovecot]
enabled = true
port    = pop3,pop3s,imap,imaps
filter  = dovecot
logpath = /var/log/mail.log
EOF
        chmod 644 /etc/fail2ban/jail.d/30-mail.local
        print_status "Mail server jails configured"
    fi
    
    if confirm "Enable recidive jail (ban repeat offenders for 1 week)?" "y"; then
        cat > /etc/fail2ban/jail.d/90-recidive.local << 'EOF'
# Repeat Offender Protection
[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = %(banaction_allports)s
bantime  = 1w
findtime = 1d
maxretry = 3
EOF
        chmod 644 /etc/fail2ban/jail.d/90-recidive.local
        print_status "Recidive jail configured (1-week ban for repeat offenders)"
    fi
    
    # Enable and start Fail2ban
    print_subsection "Starting Fail2ban"
    
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    
    if systemctl restart fail2ban >> "$LOG_FILE" 2>&1; then
        print_status "Fail2ban started successfully"
    else
        print_error "Fail2ban failed to start. Check: journalctl -u fail2ban"
        mark_failed "setup_fail2ban" "Service failed to start"
        return 1
    fi
    
    # Show status
    sleep 2
    echo ""
    print_info "Fail2ban status:"
    fail2ban-client status 2>/dev/null || print_warning "Could not retrieve status"
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}fail2ban-client status sshd${NC}       # Check SSH jail"
    echo -e "    ${CYAN}fail2ban-client set sshd banip <IP>${NC}  # Manually ban IP"
    echo -e "    ${CYAN}fail2ban-client set sshd unbanip <IP>${NC} # Unban IP"
    
    mark_completed "setup_fail2ban"
}

# ----------------------------------------------------------------------------
# Function: kernel_hardening
# Purpose: Apply comprehensive kernel security parameters via sysctl
# ----------------------------------------------------------------------------
kernel_hardening() {
    print_section "KERNEL HARDENING (SYSCTL)"
    
    print_subsection "Backing Up Current Configuration"
    backup_file /etc/sysctl.conf
    backup_directory /etc/sysctl.d
    
    print_subsection "Applying Security Parameters"
    
    # Create comprehensive drop-in configuration
    cat > /etc/sysctl.d/99-vps-hardening.conf << 'EOF'
# ============================================================
# VPS Hardening - Comprehensive Kernel Security Parameters
# Generated by VPS Hardening Script v2.0
# ============================================================

# ---- IP Spoofing & Source Routing Protection ----
# Enable reverse path filtering (BCP38)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Disable source routing (prevents IP spoofing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ---- ICMP Hardening ----
# Ignore broadcast pings (prevents Smurf attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Rate limit ICMP (optional, uncomment if needed)
# net.ipv4.icmp_ratelimit = 100
# net.ipv4.icmp_ratemask = 88089

# ---- Redirect Attack Prevention (MITM) ----
# Do not accept ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not send ICMP redirects (not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ---- SYN Flood Protection ----
# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Increase SYN backlog queue
net.ipv4.tcp_max_syn_backlog = 2048

# Reduce SYN-ACK retries
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Enable RFC 1337 (kill TIME_WAIT sockets with RST)
net.ipv4.tcp_rfc1337 = 1

# ---- TCP Hardening ----
# Disable TCP timestamps (info leak)
net.ipv4.tcp_timestamps = 0

# Disable TCP SACK (potential DoS vector)
# net.ipv4.tcp_sack = 0

# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1

# ---- IP Forwarding (disable unless acting as router) ----
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# ---- IPv6 Hardening ----
# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable IPv6 autoconfiguration
# net.ipv6.conf.all.autoconf = 0
# net.ipv6.conf.default.autoconf = 0

# ---- Memory Protection ----
# Full ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# ---- Kernel Information Leak Prevention ----
# Restrict dmesg to root only
kernel.dmesg_restrict = 1

# Hide kernel pointers from non-root
kernel.kptr_restrict = 2

# ---- BPF & Tracing Restrictions ----
# Disable unprivileged BPF
kernel.unprivileged_bpf_disabled = 1

# Restrict ptrace to parent processes only
kernel.yama.ptrace_scope = 2

# ---- File System Protection ----
# Protect hardlinks
fs.protected_hardlinks = 1

# Protect symlinks
fs.protected_symlinks = 1

# Protect FIFOs
fs.protected_fifos = 2

# Protect regular files
fs.protected_regular = 2

# ---- Core Dump Restrictions ----
# Disable setuid core dumps
fs.suid_dumpable = 0

# ---- Network Misc ----
# Log martian packets (spoofed source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IP multicast (unless needed)
# net.ipv4.conf.all.mc_forwarding = 0

# ---- Performance Tuning (safe defaults) ----
# Increase file handles
fs.file-max = 2097152

# Increase inotify watches
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 8192

# Network buffer tuning
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000
EOF
    
    chmod 644 /etc/sysctl.d/99-vps-hardening.conf
    print_status "Kernel parameters written to /etc/sysctl.d/99-vps-hardening.conf"
    
    # Apply parameters
    print_step "Applying kernel parameters..."
    if sysctl --system >> "$LOG_FILE" 2>&1; then
        print_status "All kernel parameters applied successfully"
    else
        print_warning "Some parameters may have failed (see log)"
        print_info "This is normal on some VPS providers with restricted kernels"
    fi
    
    # Verify critical parameters
    print_subsection "Verification"
    
    local checks=(
        "kernel.randomize_va_space:2:ASLR"
        "net.ipv4.tcp_syncookies:1:SYN Cookies"
        "net.ipv4.conf.all.rp_filter:1:Reverse Path Filter"
        "kernel.dmesg_restrict:1:dmesg Restriction"
        "fs.protected_symlinks:1:Symlink Protection"
    )
    
    for check in "${checks[@]}"; do
        IFS=':' read -r param expected label <<< "$check"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [ "$actual" = "$expected" ]; then
            print_status "${label}: ${actual} ✔"
        else
            print_warning "${label}: ${actual} (expected ${expected})"
        fi
    done
    
    mark_completed "kernel_hardening"
}

# ----------------------------------------------------------------------------
# Function: setup_auto_updates
# Purpose: Configure automatic security updates with optional reboot
# ----------------------------------------------------------------------------
setup_auto_updates() {
    print_section "AUTOMATIC SECURITY UPDATES"
    
    # Install required packages
    print_step "Installing unattended-upgrades..."
    apt-get install -y unattended-upgrades apt-listchanges >> "$LOG_FILE" 2>&1
    print_status "Packages installed"
    
    # Backup originals
    backup_file /etc/apt/apt.conf.d/20auto-upgrades
    backup_file /etc/apt/apt.conf.d/50unattended-upgrades
    
    print_subsection "Update Schedule Configuration"
    
    local update_interval=""
    prompt_input "Package list update interval (days)" "1" update_interval
    
    local download_interval=""
    prompt_input "Download upgradeable packages interval (days)" "1" download_interval
    
    local autoclean_interval=""
    prompt_input "Autoclean interval (days)" "7" autoclean_interval
    
    # Configure auto-upgrades schedule
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
// VPS Hardening - Automatic Updates Schedule
APT::Periodic::Update-Package-Lists "${update_interval}";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "${download_interval}";
APT::Periodic::AutocleanInterval "${autoclean_interval}";
APT::Periodic::Verbose "1";
EOF
    
    chmod 644 /etc/apt/apt.conf.d/20auto-upgrades
    print_status "Update schedule configured"
    
    # Configure unattended-upgrades behavior
    print_subsection "Upgrade Behavior"
    
    local auto_reboot="false"
    local reboot_time="03:30"
    
    if confirm "Enable automatic reboot after kernel updates?"; then
        auto_reboot="true"
        prompt_input "Reboot time (HH:MM, 24h format)" "03:30" reboot_time
        print_warning "System will automatically reboot at ${reboot_time} when needed"
    fi
    
    cat > /etc/apt/apt.conf.d/51unattended-upgrades-custom << EOF
// VPS Hardening - Unattended Upgrades Configuration
// Generated: $(date '+%Y-%m-%d %H:%M:%S')

// Automatically reboot if required
Unattended-Upgrade::Automatic-Reboot "${auto_reboot}";
Unattended-Upgrade::Automatic-Reboot-Time "${reboot_time}";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";

// Clean up unused packages after upgrade
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Only upgrade security packages by default
// (Ubuntu/Debian security repos are already in 50unattended-upgrades)

// Email notifications (optional, configure if needed)
// Unattended-Upgrade::Mail "admin@example.com";
// Unattended-Upgrade::MailReport "only-on-error";

// Log to syslog
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

// Minimal steps to reduce lock time
Unattended-Upgrade::MinimalSteps "true";

// Allow package downgrade if needed for security
Unattended-Upgrade::Allow-downgrade "true";
EOF
    
    chmod 644 /etc/apt/apt.conf.d/51unattended-upgrades-custom
    print_status "Unattended-upgrades behavior configured"
    
    # Enable and start the service
    print_subsection "Activating Service"
    
    systemctl enable unattended-upgrades >> "$LOG_FILE" 2>&1
    systemctl restart unattended-upgrades >> "$LOG_FILE" 2>&1
    
    if service_active "unattended-upgrades"; then
        print_status "Unattended-upgrades service is active"
    else
        print_warning "Service may not be running. Check: systemctl status unattended-upgrades"
    fi
    
    # Enable apt-daily timers
    systemctl enable apt-daily.timer >> "$LOG_FILE" 2>&1
    systemctl enable apt-daily-upgrade.timer >> "$LOG_FILE" 2>&1
    systemctl start apt-daily.timer >> "$LOG_FILE" 2>&1
    systemctl start apt-daily-upgrade.timer >> "$LOG_FILE" 2>&1
    print_status "APT daily timers enabled"
    
    # Test dry run
    if confirm "Perform a dry-run test now?"; then
        print_step "Running dry-run (no actual changes)..."
        unattended-upgrades --dry-run --debug 2>&1 | tail -20
        print_status "Dry-run completed (check output above)"
    fi
    
    echo ""
    print_info "Log location: /var/log/unattended-upgrades/"
    print_info "Manual trigger: unattended-upgrades --debug"
    
    mark_completed "setup_auto_updates"
}

# ----------------------------------------------------------------------------
# Function: setup_user_account
# Purpose: Create hardened user account with restricted sudo
# ----------------------------------------------------------------------------
setup_user_account() {
    print_section "USER ACCOUNT & SUDO SETUP"
    
    print_info "Current user: ${TARGET_USER}"
    print_info "Home directory: ${USER_HOME}"
    
    print_subsection "Admin User Configuration"
    
    if confirm "Create a new dedicated admin user?" "n"; then
        local new_user=""
        while true; do
            prompt_input "Enter new admin username" "" new_user
            if [ -z "$new_user" ]; then
                print_error "Username cannot be empty"
                continue
            fi
            if [[ ! "$new_user" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
                print_error "Invalid username. Use lowercase letters, numbers, underscores, hyphens."
                continue
            fi
            if id "$new_user" &>/dev/null; then
                print_warning "User '${new_user}' already exists"
                if ! confirm "Configure this existing user?" "n"; then
                    continue
                fi
            fi
            break
        done
        
        # Create user if doesn't exist
        if ! id "$new_user" &>/dev/null; then
            print_step "Creating user: ${new_user}"
            useradd -m -s /bin/bash -G sudo "$new_user"
            print_status "User created"
            
            # Set password
            print_step "Setting password for ${new_user}..."
            passwd "$new_user"
        fi
        
        # Setup SSH keys for new user
        local new_home
        new_home=$(eval echo "~${new_user}")
        local new_ssh_dir="${new_home}/.ssh"
        
        mkdir -p "$new_ssh_dir"
        chown "${new_user}:${new_user}" "$new_ssh_dir"
        chmod 700 "$new_ssh_dir"
        
        if [ ! -f "${new_ssh_dir}/authorized_keys" ]; then
            touch "${new_ssh_dir}/authorized_keys"
            chown "${new_user}:${new_user}" "${new_ssh_dir}/authorized_keys"
            chmod 600 "${new_ssh_dir}/authorized_keys"
        fi
        
        # Copy current user's keys if available
        if [ -f "${USER_HOME}/.ssh/authorized_keys" ] && [ -s "${USER_HOME}/.ssh/authorized_keys" ]; then
            if confirm "Copy SSH keys from ${TARGET_USER} to ${new_user}?"; then
                cp "${USER_HOME}/.ssh/authorized_keys" "${new_ssh_dir}/authorized_keys"
                chown "${new_user}:${new_user}" "${new_ssh_dir}/authorized_keys"
                chmod 600 "${new_ssh_dir}/authorized_keys"
                print_status "SSH keys copied to ${new_user}"
            fi
        fi
        
        TARGET_USER="$new_user"
        USER_HOME="$new_home"
        save_state "ADMIN_USER" "$new_user"
        print_status "Admin user configured: ${new_user}"
    fi
    
    print_subsection "Sudo Hardening"
    
    if confirm "Restrict sudo to require password every time (no caching)?" "n"; then
        mkdir -p /etc/sudoers.d
        cat > /etc/sudoers.d/99-hardening-timestamp << 'EOF'
# VPS Hardening - No sudo password caching
Defaults timestamp_timeout=0
EOF
        chmod 440 /etc/sudoers.d/99-hardening-timestamp
        print_status "Sudo password caching disabled"
    fi
    
    if confirm "Log all sudo commands to a separate log file?"; then
        mkdir -p /etc/sudoers.d
        cat > /etc/sudoers.d/99-hardening-logging << 'EOF'
# VPS Hardening - Sudo command logging
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults iolog_dir="/var/log/sudo-io"
EOF
        chmod 440 /etc/sudoers.d/99-hardening-logging
        mkdir -p /var/log/sudo-io
        chmod 700 /var/log/sudo-io
        print_status "Sudo command logging enabled"
    fi
    
    if confirm "Restrict 'su' command to sudo group members only?"; then
        backup_file /etc/pam.d/su
        if ! grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
            sed -i 's/^#\s*auth\s*required\s*pam_wheel.so/auth required pam_wheel.so/' /etc/pam.d/su
            # If the line doesn't exist at all, add it
            if ! grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
                echo "auth required pam_wheel.so" >> /etc/pam.d/su
            fi
            print_status "'su' restricted to sudo group"
        else
            print_info "'su' is already restricted"
        fi
    fi
    
    # Disable root SSH login reminder
    print_subsection "Root Account Security"
    
    if confirm "Lock the root account password? (sudo still works)"; then
        passwd -l root >> "$LOG_FILE" 2>&1
        print_status "Root password locked"
        print_info "Root login via SSH is already disabled in sshd_config"
        print_info "Use 'sudo -i' or 'sudo su -' for root shell"
    fi
    
    mark_completed "setup_user_account"
}

# End of Section 2
# ============================================================================
# TIER 1: HIGH IMPACT DEFENSES
# ============================================================================

# ----------------------------------------------------------------------------
# Function: secure_shared_memory
# Purpose: Secure /dev/shm to prevent in-memory malware execution
# ----------------------------------------------------------------------------
secure_shared_memory() {
    print_section "SECURE SHARED MEMORY (/dev/shm)"
    
    print_info "/dev/shm is a world-writable tmpfs used for shared memory."
    print_info "Attackers exploit it to execute malicious payloads in RAM."
    echo ""
    
    # Check current mount status
    print_subsection "Current Status"
    if mount | grep -q " /dev/shm "; then
        local current_opts
        current_opts=$(mount | grep " /dev/shm " | sed 's/.*(\(.*\))/\1/')
        print_info "Current mount options: ${current_opts}"
    else
        print_info "/dev/shm is using default mount options"
    fi
    
    # Check fstab
    if grep -q " /dev/shm " /etc/fstab 2>/dev/null; then
        print_warning "/dev/shm already has an fstab entry"
        if ! confirm "Update the existing entry with hardened options?"; then
            return 0
        fi
        backup_file /etc/fstab
        sed -i '/ \/dev\/shm /d' /etc/fstab
    else
        backup_file /etc/fstab
    fi
    
    # Add hardened mount entry
    print_step "Adding hardened /dev/shm mount..."
    echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=1G 0 0" >> /etc/fstab
    chmod 644 /etc/fstab
    
    # Remount immediately
    print_step "Remounting /dev/shm..."
    if mount -o remount /dev/shm 2>>"$LOG_FILE"; then
        print_status "/dev/shm remounted with noexec,nosuid,nodev"
    else
        print_warning "Remount failed. Changes will apply on next reboot."
        print_info "Some running services may be using /dev/shm currently."
    fi
    
    # Verify
    print_subsection "Verification"
    local verify_opts
    verify_opts=$(mount | grep " /dev/shm " | sed 's/.*(\(.*\))/\1/')
    print_info "Active mount options: ${verify_opts}"
    
    if echo "$verify_opts" | grep -q "noexec"; then
        print_status "noexec: active ✔"
    else
        print_warning "noexec: not active"
    fi
    
    if echo "$verify_opts" | grep -q "nosuid"; then
        print_status "nosuid: active ✔"
    else
        print_warning "nosuid: not active"
    fi
    
    if echo "$verify_opts" | grep -q "nodev"; then
        print_status "nodev: active ✔"
    else
        print_warning "nodev: not active"
    fi
    
    mark_completed "secure_shared_memory"
}

# ----------------------------------------------------------------------------
# Function: disable_unused_protocols
# Purpose: Disable unused and vulnerable kernel network modules
# ----------------------------------------------------------------------------
disable_unused_protocols() {
    print_section "DISABLE UNUSED NETWORK PROTOCOLS"
    
    print_info "Disabling rarely-used kernel protocols reduces the attack surface"
    print_info "for local privilege escalation and remote kernel exploits."
    echo ""
    
    backup_directory /etc/modprobe.d
    
    print_subsection "Core Protocol Disabling"
    
    # Always disable these high-risk protocols
    cat > /etc/modprobe.d/99-vps-disable-protocols.conf << 'EOF'
# ============================================================
# VPS Hardening - Disable Unused Network Protocols
# Generated by VPS Hardening Script v2.0
# ============================================================

# DCCP - Datagram Congestion Control Protocol
# CVE-2017-6074: heap out-of-bounds write
install dccp /bin/true
install dccp_ipv4 /bin/true
install dccp_ipv6 /bin/true

# SCTP - Stream Control Transmission Protocol
# Multiple CVEs in kernel SCTP implementation
install sctp /bin/true
install sctp_diag /bin/true

# RDS - Reliable Datagram Sockets
# CVE-2010-3904: local privilege escalation
install rds /bin/true
install rds_tcp /bin/true
install rds_rdma /bin/true

# TIPC - Transparent Inter-Process Communication
# CVE-2021-43267: heap overflow, remote code execution
install tipc /bin/true

# ATM - Asynchronous Transfer Mode (legacy)
install atm /bin/true

# AX.25 - Amateur Radio protocol
install ax25 /bin/true

# NETROM - Amateur Radio protocol
install netrom /bin/true

# ROSE - Amateur Radio protocol
install rose /bin/true

# X.25 - Legacy packet switching
install x25 /bin/true

# DECnet - Legacy DEC protocol
install decnet /bin/true

# Econet - Legacy Acorn protocol
install econet /bin/true

# AF_802154 - IEEE 802.15.4 (IoT, rarely needed on VPS)
install af_802154 /bin/true

# CAN - Controller Area Network (automotive, not for VPS)
install can /bin/true

# NFC - Near Field Communication (not for VPS)
install nfc /bin/true
EOF
    
    chmod 644 /etc/modprobe.d/99-vps-disable-protocols.conf
    print_status "Core dangerous protocols disabled"
    
    # Optional additional modules
    print_subsection "Optional Module Disabling"
    
    local optional_modules=()
    
    if confirm "Disable USB storage? (recommended for remote VPS)" "y"; then
        optional_modules+=("install usb-storage /bin/true")
        optional_modules+=("install uas /bin/true")
        print_status "USB storage modules disabled"
    fi
    
    if confirm "Disable FireWire (IEEE 1394)? (DMA attack vector)" "y"; then
        optional_modules+=("install firewire-core /bin/true")
        optional_modules+=("install firewire-ohci /bin/true")
        optional_modules+=("install firewire-sbp2 /bin/true")
        print_status "FireWire modules disabled"
    fi
    
    if confirm "Disable Thunderbolt? (DMA attack vector)" "y"; then
        optional_modules+=("install thunderbolt /bin/true")
        print_status "Thunderbolt module disabled"
    fi
    
    if confirm "Disable PC speaker? (minor info leak)" "n"; then
        optional_modules+=("install pcspkr /bin/true")
        optional_modules+=("blacklist pcspkr")
        print_status "PC speaker disabled"
    fi
    
    if confirm "Disable Bluetooth? (not needed on VPS)" "y"; then
        optional_modules+=("install bluetooth /bin/true")
        optional_modules+=("install btusb /bin/true")
        print_status "Bluetooth modules disabled"
    fi
    
    if confirm "Disable CIFS/SMB client? (unless mounting Windows shares)" "y"; then
        optional_modules+=("install cifs /bin/true")
        print_status "CIFS/SMB client disabled"
    fi
    
    if confirm "Disable NFS client? (unless mounting NFS shares)" "y"; then
        optional_modules+=("install nfs /bin/true")
        optional_modules+=("install nfsv3 /bin/true")
        optional_modules+=("install nfsv4 /bin/true")
        print_status "NFS client modules disabled"
    fi
    
    # Append optional modules
    if [ ${#optional_modules[@]} -gt 0 ]; then
        echo "" >> /etc/modprobe.d/99-vps-disable-protocols.conf
        echo "# ---- Optional Disabled Modules ----" >> /etc/modprobe.d/99-vps-disable-protocols.conf
        for mod in "${optional_modules[@]}"; do
            echo "$mod" >> /etc/modprobe.d/99-vps-disable-protocols.conf
        done
    fi
    
    # Unload currently loaded dangerous modules
    print_subsection "Unloading Active Modules"
    
    local modules_to_unload=("dccp" "sctp" "rds" "tipc")
    for mod in "${modules_to_unload[@]}"; do
        if lsmod | grep -q "^${mod} "; then
            if rmmod "$mod" 2>>"$LOG_FILE"; then
                print_status "Unloaded active module: ${mod}"
            else
                print_warning "Could not unload ${mod} (may be in use)"
            fi
        fi
    done
    
    echo ""
    print_info "Changes take full effect after reboot"
    print_info "Verify with: lsmod | grep -E 'dccp|sctp|rds|tipc'"
    
    mark_completed "disable_unused_protocols"
}

# ----------------------------------------------------------------------------
# Function: setup_apparmor
# Purpose: Enable and enforce AppArmor mandatory access control
# ----------------------------------------------------------------------------
setup_apparmor() {
    print_section "APPARMOR - MANDATORY ACCESS CONTROL"
    
    print_info "AppArmor confines programs to a limited set of resources,"
    print_info "preventing compromised services from accessing unauthorized files."
    echo ""
    
    # Install AppArmor packages
    if ! command_exists apparmor_status && ! command_exists aa-status; then
        print_step "Installing AppArmor..."
        apt-get install -y apparmor apparmor-utils >> "$LOG_FILE" 2>&1
        print_status "AppArmor base packages installed"
    fi
    
    print_step "Installing additional AppArmor profiles..."
    apt-get install -y apparmor-profiles apparmor-profiles-extra >> "$LOG_FILE" 2>&1 || \
        print_warning "Some extra profiles may not be available for your OS version"
    print_status "AppArmor profiles installed"
    
    # Check if AppArmor is enabled in kernel
    print_subsection "Kernel Support Check"
    
    if [ -d /sys/kernel/security/apparmor ]; then
        print_status "AppArmor kernel module is loaded"
    else
        print_warning "AppArmor kernel module not detected"
        print_info "You may need to add 'apparmor=1 security=apparmor' to GRUB"
        
        if confirm "Add AppArmor to kernel boot parameters?"; then
            backup_file /etc/default/grub
            
            if ! grep -q "apparmor=1" /etc/default/grub; then
                sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 apparmor=1 security=apparmor"/' /etc/default/grub
                
                if command_exists update-grub; then
                    update-grub >> "$LOG_FILE" 2>&1
                elif command_exists grub2-mkconfig; then
                    grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1
                fi
                
                print_status "AppArmor boot parameters added (active after reboot)"
            else
                print_info "AppArmor already in boot parameters"
            fi
        fi
    fi
    
    # Enforce all profiles
    print_subsection "Profile Enforcement"
    
    local enforced_count=0
    local complain_count=0
    local failed_count=0
    
    if command_exists aa-enforce; then
        print_step "Switching all profiles to enforce mode..."
        
        for profile in /etc/apparmor.d/*; do
            # Skip directories and special files
            local basename
            basename=$(basename "$profile")
            
            if [ -d "$profile" ]; then
                continue
            fi
            
            case "$basename" in
                local|abstractions|tunables|disable|force-complain|lxc|README|*.dpkg-*|*.rpmsave|*.rpmnew)
                    continue
                    ;;
            esac
            
            if aa-enforce "$profile" >> "$LOG_FILE" 2>&1; then
                ((enforced_count++))
            else
                ((failed_count++))
                print_debug "Failed to enforce: ${basename}"
            fi
        done
        
        print_status "Enforced: ${enforced_count} profiles"
        [ "$failed_count" -gt 0 ] && print_warning "Failed: ${failed_count} profiles (see log)"
    else
        print_warning "aa-enforce command not available"
    fi
    
    # Enable and restart AppArmor
    print_subsection "Service Activation"
    
    systemctl enable apparmor >> "$LOG_FILE" 2>&1
    systemctl restart apparmor >> "$LOG_FILE" 2>&1
    
    if service_active "apparmor"; then
        print_status "AppArmor service is active"
    else
        print_warning "AppArmor service may not be running"
    fi
    
    # Show status
    print_subsection "Current Status"
    if command_exists aa-status; then
        aa-status 2>/dev/null | head -15
    fi
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}aa-status${NC}                    # Show profile status"
    echo -e "    ${CYAN}aa-complain /path/to/bin${NC}     # Set profile to complain mode"
    echo -e "    ${CYAN}aa-enforce /path/to/bin${NC}      # Set profile to enforce mode"
    echo -e "    ${CYAN}aa-logprof${NC}                   # Review and update profiles"
    
    mark_completed "setup_apparmor"
}

# ----------------------------------------------------------------------------
# Function: setup_aide
# Purpose: Install and configure AIDE file integrity monitoring
# ----------------------------------------------------------------------------
setup_aide() {
    print_section "FILE INTEGRITY MONITORING (AIDE)"
    
    print_info "AIDE creates a database of file checksums and attributes."
    print_info "It detects unauthorized changes to system binaries and configs."
    echo ""
    
    # Install AIDE
    if ! command_exists aide; then
        print_step "Installing AIDE..."
        apt-get install -y aide aide-common >> "$LOG_FILE" 2>&1
        print_status "AIDE installed"
    fi
    
    # Backup configuration
    backup_file /etc/aide/aide.conf
    
    print_subsection "AIDE Configuration"
    
    # Customize AIDE rules for VPS
    cat > /etc/aide/aide.conf.d/99_vps_hardening << 'EOF'
# VPS Hardening - Custom AIDE Rules

# Monitor SSH configuration closely
/etc/ssh/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Monitor sudo configuration
/etc/sudoers$ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/sudoers.d/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Monitor PAM configuration
/etc/pam.d/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Monitor systemd services
/etc/systemd/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Monitor cron jobs
/etc/cron.* p+i+n+u+g+s+b+acl+xattrs+sha512
/var/spool/cron/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Monitor kernel modules
/etc/modprobe.d/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Monitor firewall rules
/etc/ufw/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Monitor Fail2ban
/etc/fail2ban/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Monitor AppArmor
/etc/apparmor/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/apparmor.d/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Exclude noisy directories
!/var/log/.*
!/var/cache/.*
!/var/tmp/.*
!/run/.*
!/dev/.*
!/proc/.*
!/sys/.*
!/tmp/.*
EOF
    
    chmod 644 /etc/aide/aide.conf.d/99_vps_hardening
    print_status "Custom AIDE rules created"
    
    # Initialize database
    print_subsection "Database Initialization"
    print_warning "This process may take 5-15 minutes depending on disk size..."
    
    if confirm "Initialize AIDE database now?"; then
        print_step "Initializing AIDE database (please wait)..."
        
        local start_time
        start_time=$(date +%s)
        
        if aideinit >> "$LOG_FILE" 2>&1; then
            local end_time
            end_time=$(date +%s)
            local duration=$(( end_time - start_time ))
            print_status "AIDE database initialized in ${duration} seconds"
        else
            print_warning "AIDE initialization had warnings (see log)"
        fi
        
        # Copy new database to active location
        if [ -f /var/lib/aide/aide.db.new ]; then
            cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            chmod 600 /var/lib/aide/aide.db
            print_status "Database activated"
        elif [ -f /var/lib/aide/aide.db.new.gz ]; then
            cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            chmod 600 /var/lib/aide/aide.db.gz
            print_status "Database activated (compressed)"
        else
            print_warning "Database file not found in expected location"
        fi
    else
        print_info "Skipping initialization. Run manually: aideinit"
    fi
    
    # Setup automated daily checks
    print_subsection "Automated Integrity Checks"
    
    cat > /etc/cron.daily/aide-integrity-check << 'CRONEOF'
#!/bin/bash
# VPS Hardening - Daily AIDE Integrity Check

REPORT_FILE="/var/log/aide/aide-check-$(date +%Y%m%d).log"
mkdir -p /var/log/aide

# Run AIDE check
/usr/bin/aide --check > "$REPORT_FILE" 2>&1
EXIT_CODE=$?

# Log to syslog
if [ $EXIT_CODE -ne 0 ]; then
    logger -t aide-check -p auth.warning "AIDE detected changes! See $REPORT_FILE"
    
    # Optional: email alert (configure MAILTO in crontab)
    if [ -n "${MAILTO:-}" ]; then
        mail -s "AIDE ALERT: File changes detected on $(hostname)" "$MAILTO" < "$REPORT_FILE"
    fi
else
    logger -t aide-check -p auth.info "AIDE check passed - no changes detected"
fi

# Clean old reports (keep 30 days)
find /var/log/aide/ -name "aide-check-*.log" -mtime +30 -delete 2>/dev/null

exit 0
CRONEOF
    
    chmod 755 /etc/cron.daily/aide-integrity-check
    mkdir -p /var/log/aide
    print_status "Daily AIDE integrity check scheduled"
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}aide --check${NC}              # Run integrity check"
    echo -e "    ${CYAN}aide --update${NC}             # Update database after legitimate changes"
    echo -e "    ${CYAN}cat /var/log/aide/*.log${NC}   # View check reports"
    
    mark_completed "setup_aide"
}

# ----------------------------------------------------------------------------
# Function: setup_auditd
# Purpose: Install and configure kernel audit daemon
# ----------------------------------------------------------------------------
setup_auditd() {
    print_section "KERNEL AUDIT DAEMON (auditd)"
    
    print_info "auditd logs security-relevant events at the kernel level."
    print_info "Attackers cannot easily hide from kernel-level auditing."
    echo ""
    
    # Install auditd
    if ! command_exists auditctl; then
        print_step "Installing auditd..."
        apt-get install -y auditd audispd-plugins >> "$LOG_FILE" 2>&1
        print_status "auditd installed"
    fi
    
    # Backup
    backup_directory /etc/audit
    backup_directory /etc/audit/rules.d
    
    print_subsection "Audit Rules Configuration"
    
    mkdir -p /etc/audit/rules.d
    
    cat > /etc/audit/rules.d/99-vps-hardening.rules << 'EOF'
# ============================================================
# VPS Hardening - Comprehensive Audit Rules
# ============================================================

# Delete all existing rules
-D

# Increase buffer size (default 320 may be too small)
-b 8192

# Failure mode: 0=silent, 1=printk, 2=panic
# Use 1 for production (log failures), 2 only for high-security
-f 1

# ---- Identity & Authentication Changes ----
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# ---- Sudo & Privilege Escalation ----
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /usr/bin/sudo -p x -k sudo_exec
-w /usr/bin/su -p x -k su_exec

# ---- SSH Configuration & Keys ----
-w /etc/ssh/ -p wa -k sshd_config
-w /root/.ssh/ -p wa -k root_ssh_keys
-w /etc/ssh/sshd_config -p wa -k sshd_main_config

# ---- Cron Job Monitoring ----
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/at.allow -p wa -k cron
-w /etc/cron.allow -p wa -k cron

# ---- Kernel Module Operations ----
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules

# ---- Network Configuration ----
-w /etc/hosts -p wa -k network
-w /etc/resolv.conf -p wa -k network
-w /etc/hostname -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/ufw/ -p wa -k firewall

# ---- System Time Changes ----
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# ---- Login/Logout Events ----
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/run/utmp -p wa -k session

# ---- AppArmor Policy Changes ----
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor

# ---- Fail2ban Changes ----
-w /etc/fail2ban/ -p wa -k fail2ban

# ---- File Deletion by Users ----
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k file_delete

# ---- Failed Access Attempts ----
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EPERM -k access_denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EPERM -k access_denied

# ---- Executable File Modifications ----
-w /usr/bin/ -p wa -k bin_modification
-w /usr/sbin/ -p wa -k sbin_modification
-w /usr/local/bin/ -p wa -k local_bin_modification

# ---- Make rules immutable (requires reboot to change) ----
-e 2
EOF
    
    chmod 640 /etc/audit/rules.d/99-vps-hardening.rules
    print_status "Comprehensive audit rules created"
    
    # Configure auditd daemon settings
    print_subsection "Daemon Configuration"
    
    backup_file /etc/audit/auditd.conf
    
    cat > /etc/audit/auditd.conf << 'EOF'
# VPS Hardening - auditd Configuration
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 50
num_logs = 10
priority_boost = 4
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
distribute_network = no
q_depth = 1200
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
EOF
    
    chmod 640 /etc/audit/auditd.conf
    print_status "Audit daemon configured"
    
    # Enable and start
    print_subsection "Service Activation"
    
    systemctl enable auditd >> "$LOG_FILE" 2>&1
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || true
    
    if service_active "auditd"; then
        print_status "auditd is active and running"
    else
        print_warning "auditd may not be running (some VPS kernels restrict it)"
    fi
    
    # Show loaded rules count
    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | wc -l || echo "0")
    print_info "Loaded audit rules: ${rule_count}"
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}ausearch -k sudoers${NC}        # Search sudo events"
    echo -e "    ${CYAN}ausearch -k identity${NC}       # Search identity changes"
    echo -e "    ${CYAN}ausearch -k access_denied${NC}  # Search failed access"
    echo -e "    ${CYAN}aureport --auth${NC}            # Authentication report"
    echo -e "    ${CYAN}aureport -x${NC}                # Executable report"
    echo -e "    ${CYAN}aureport --failed${NC}          # Failed events report"
    
    mark_completed "setup_auditd"
}

# ----------------------------------------------------------------------------
# Function: secure_tmp_directories
# Purpose: Secure /tmp and /var/tmp with restrictive mount options
# ----------------------------------------------------------------------------
secure_tmp_directories() {
    print_section "SECURE TEMPORARY DIRECTORIES"
    
    print_info "Attackers often use /tmp and /var/tmp to stage exploits."
    print_info "Mounting them with noexec,nosuid,nodev prevents execution."
    echo ""
    
    backup_file /etc/fstab
    
    print_subsection "Securing /tmp"
    
    if mount | grep -q " /tmp " && mount | grep " /tmp " | grep -q "noexec"; then
        print_info "/tmp is already mounted with noexec"
    else
        if confirm "Mount /tmp with noexec,nosuid,nodev?"; then
            # Remove existing /tmp fstab entry if present
            if grep -q " /tmp " /etc/fstab; then
                sed -i '/ \/tmp /d' /etc/fstab
            fi
            
            echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
            
            # Remount
            if mount -o remount /tmp 2>>"$LOG_FILE"; then
                print_status "/tmp secured and remounted"
            else
                print_warning "/tmp remount failed. Will apply on next reboot."
                print_info "Some services may be using /tmp. Reboot to apply."
            fi
        fi
    fi
    
    print_subsection "Securing /var/tmp"
    
    if mount | grep -q " /var/tmp " && mount | grep " /var/tmp " | grep -q "noexec"; then
        print_info "/var/tmp is already mounted with noexec"
    else
        if confirm "Mount /var/tmp with noexec,nosuid,nodev?"; then
            if grep -q " /var/tmp " /etc/fstab; then
                sed -i '/ \/var\/tmp /d' /etc/fstab
            fi
            
            echo "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=1G 0 0" >> /etc/fstab
            
            if mount -o remount /var/tmp 2>>"$LOG_FILE"; then
                print_status "/var/tmp secured and remounted"
            else
                print_warning "/var/tmp remount failed. Will apply on next reboot."
            fi
        fi
    fi
    
    print_subsection "Securing /home (optional)"
    
    if confirm "Mount /home with nosuid? (prevents setuid binaries in user homes)"; then
        if ! grep -q " /home " /etc/fstab; then
            print_warning "/home is not a separate partition in fstab."
            print_warning "This option only works if /home is a separate mount."
        else
            if ! mount | grep " /home " | grep -q "nosuid"; then
                # Add nosuid to existing /home mount
                sed -i 's|\(.*\s/home\s\+\S\+\s\+\)\(\S\+\)|\1\2,nosuid|' /etc/fstab
                mount -o remount /home 2>>"$LOG_FILE" || true
                print_status "/home remounted with nosuid"
            else
                print_info "/home already has nosuid"
            fi
        fi
    fi
    
    # Setup systemd tmpfiles cleanup
    print_subsection "Temporary File Cleanup"
    
    if confirm "Configure aggressive /tmp cleanup (files older than 7 days)?" "n"; then
        mkdir -p /etc/tmpfiles.d
        cat > /etc/tmpfiles.d/99-vps-hardening.conf << 'EOF'
# VPS Hardening - Aggressive temp cleanup
# Clean /tmp files older than 7 days
q /tmp 1777 root root 7d
q /var/tmp 1777 root root 7d
EOF
        chmod 644 /etc/tmpfiles.d/99-vps-hardening.conf
        print_status "Temp file cleanup configured (7-day retention)"
    fi
    
    echo ""
    print_info "Verify mounts: mount | grep -E '/tmp|/var/tmp'"
    
    mark_completed "secure_tmp_directories"
}

# End of Section 3
# ============================================================================
# TIER 2: ADVANCED SECURITY CONTROLS (PART 1)
# ============================================================================

# ----------------------------------------------------------------------------
# Function: setup_resource_limits
# Purpose: Configure resource limits to prevent fork bombs and DoS
# ----------------------------------------------------------------------------
setup_resource_limits() {
    print_section "RESOURCE LIMITS & FORK BOMB PROTECTION"
    
    print_info "Resource limits prevent a single user or compromised process"
    print_info "from consuming all system resources (CPU, RAM, processes)."
    echo ""
    
    backup_directory /etc/security/limits.d
    backup_file /etc/security/limits.conf
    
    print_subsection "Process & Memory Limits"
    
    local nproc_hard="" nproc_soft="" nofile_hard=""
    prompt_input "Max processes per user (hard)" "512" nproc_hard
    prompt_input "Max processes per user (soft)" "256" nproc_soft
    prompt_input "Max open files per user (hard)" "65536" nofile_hard
    
    cat > /etc/security/limits.d/99-vps-hardening.conf << EOF
# ============================================================
# VPS Hardening - Resource Limits
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# ---- Fork Bomb Protection ----
# Limit number of processes per user
*               hard    nproc           ${nproc_hard}
*               soft    nproc           ${nproc_soft}
root            hard    nproc           unlimited
root            soft    nproc           unlimited

# ---- File Descriptor Limits ----
*               hard    nofile          ${nofile_hard}
*               soft    nofile          8192
root            hard    nofile          1048576
root            soft    nofile          65536

# ---- Memory Lock Limits ----
# Prevent users from locking excessive RAM
*               hard    memlock         65536
*               soft    memlock         65536

# ---- Core Dump Prevention ----
# Disable core dumps to prevent memory scraping
*               hard    core            0
*               soft    core            0
root            hard    core            0

# ---- Stack Size Limits ----
*               hard    stack           8192
*               soft    stack           8192

# ---- Max Logins ----
# Limit concurrent logins per user
*               hard    maxlogins       5
root            hard    maxlogins       unlimited

# ---- Address Space Limits (optional, may break some apps) ----
# *            hard    as              2097152
# *            soft    as              1048576

# ---- CPU Time Limits (seconds, 0 = unlimited) ----
# *            hard    cpu             0
EOF
    
    chmod 644 /etc/security/limits.d/99-vps-hardening.conf
    print_status "Resource limits configured"
    
    # Ensure PAM limits module is loaded
    print_subsection "PAM Integration"
    
    local pam_files=("/etc/pam.d/common-session" "/etc/pam.d/common-session-noninteractive")
    for pam_file in "${pam_files[@]}"; do
        if [ -f "$pam_file" ]; then
            if ! grep -q "pam_limits.so" "$pam_file" 2>/dev/null; then
                echo "session required pam_limits.so" >> "$pam_file"
                print_status "pam_limits.so added to ${pam_file}"
            else
                print_info "pam_limits.so already in ${pam_file}"
            fi
        fi
    done
    
    # Systemd coredump configuration
    print_subsection "Systemd Core Dump Control"
    
    mkdir -p /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/99-vps-hardening.conf << 'EOF'
# VPS Hardening - Disable systemd core dumps
[Coredump]
Storage=none
ProcessSizeMax=0
ExternalSizeMax=0
JournalSizeMax=0
EOF
    
    chmod 644 /etc/systemd/coredump.conf.d/99-vps-hardening.conf
    systemctl daemon-reload 2>/dev/null || true
    print_status "Systemd core dumps disabled"
    
    # Sysctl core dump control
    cat > /etc/sysctl.d/98-coredump.conf << 'EOF'
# Disable core dumps system-wide
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
EOF
    
    chmod 644 /etc/sysctl.d/98-coredump.conf
    sysctl --system >> "$LOG_FILE" 2>&1 || true
    print_status "Kernel core dump pattern disabled"
    
    echo ""
    print_info "Verify limits: ulimit -a"
    print_info "Verify for user: su - ${TARGET_USER} -c 'ulimit -a'"
    
    mark_completed "setup_resource_limits"
}

# ----------------------------------------------------------------------------
# Function: disable_unnecessary_services
# Purpose: Audit and disable unnecessary running services
# ----------------------------------------------------------------------------
disable_unnecessary_services() {
    print_section "DISABLE UNNECESSARY SERVICES"
    
    print_info "Every running service is a potential attack surface."
    print_info "This function helps identify and disable services you don't need."
    echo ""
    
    print_subsection "Currently Listening Services"
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{printf "    %-30s %s\n", $4, $6}' || \
        print_warning "Could not list listening services"
    echo ""
    
    # Define services to check with descriptions
    local -A service_descriptions=(
        ["rpcbind"]="RPC Bind (NFS/SUN-RPC, rarely needed on VPS)"
        ["rpc-statd"]="NFS Status Monitor"
        ["nfs-server"]="NFS File Server"
        ["nfs-kernel-server"]="NFS Kernel Server"
        ["cups"]="CUPS Print Server (not needed on VPS)"
        ["avahi-daemon"]="Avahi mDNS/DNS-SD (local network discovery)"
        ["bluetooth"]="Bluetooth Service"
        ["apache2"]="Apache HTTP Server"
        ["nginx"]="Nginx HTTP Server"
        ["postfix"]="Postfix Mail Transfer Agent"
        ["exim4"]="Exim Mail Transfer Agent"
        ["dovecot"]="Dovecot IMAP/POP3 Server"
        ["mysql"]="MySQL Database Server"
        ["mariadb"]="MariaDB Database Server"
        ["postgresql"]="PostgreSQL Database Server"
        ["redis-server"]="Redis In-Memory Database"
        ["memcached"]="Memcached Cache Server"
        ["mongodb"]="MongoDB Database"
        ["snapd"]="Snap Package Manager Daemon"
        ["multipathd"]="Multipath Device Mapper"
        ["lvm2-lvmpolld"]="LVM Poll Daemon"
        ["rsync"]="Rsync Daemon"
        ["telnetd"]="Telnet Server (INSECURE)"
        ["vsftpd"]="vsftpd FTP Server"
        ["proftpd"]="ProFTPD FTP Server"
        ["named"]="BIND DNS Server"
        ["dnsmasq"]="Dnsmasq DNS/DHCP"
        ["docker"]="Docker Container Engine"
        ["containerd"]="Containerd Runtime"
        ["libvirtd"]="Libvirt Virtualization"
        ["qemu-kvm"]="QEMU/KVM Virtualization"
        ["smbd"]="Samba SMB File Sharing"
        ["nmbd"]="Samba NetBIOS"
        ["atd"]="At Job Scheduler"
        ["rsyslog"]="Rsyslog System Logger"
        ["systemd-journal-remote"]="Remote Journal Receiver"
        ["systemd-journal-upload"]="Remote Journal Uploader"
    )
    
    # Sort service names
    local sorted_services
    sorted_services=($(echo "${!service_descriptions[@]}" | tr ' ' '\n' | sort))
    
    print_subsection "Service Audit"
    print_info "Review each service. Only disable what you are sure you don't need."
    print_warning "Disabling the wrong service can break your applications!"
    echo ""
    
    local disabled_count=0
    
    for svc in "${sorted_services[@]}"; do
        local desc="${service_descriptions[$svc]}"
        
        # Check if service exists and is active/enabled
        if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
            local state
            state=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
            local active
            active=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            
            if [ "$state" != "not-found" ] && [ "$state" != "masked" ]; then
                local status_color="${GREEN}"
                [ "$active" = "active" ] && status_color="${RED}"
                
                echo -e "  ${status_color}[${active}]${NC} ${BOLD}${svc}${NC} - ${desc}"
                
                if confirm "  Disable and mask ${svc}?" "n"; then
                    systemctl stop "$svc" 2>>"$LOG_FILE" || true
                    systemctl disable "$svc" 2>>"$LOG_FILE" || true
                    systemctl mask "$svc" 2>>"$LOG_FILE" || true
                    print_status "Disabled and masked: ${svc}"
                    ((disabled_count++))
                fi
            fi
        fi
    done
    
    # Handle systemd sockets
    print_subsection "Systemd Socket Hardening"
    
    local sockets_to_mask=(
        "systemd-journal-remote.socket"
        "systemd-journal-upload.socket"
        "systemd-journal-gatewayd.socket"
    )
    
    for sock in "${sockets_to_mask[@]}"; do
        if systemctl list-unit-files "$sock" &>/dev/null 2>&1; then
            local sock_state
            sock_state=$(systemctl is-enabled "$sock" 2>/dev/null || echo "not-found")
            if [ "$sock_state" != "not-found" ] && [ "$sock_state" != "masked" ]; then
                if confirm "Mask ${sock}?"; then
                    systemctl stop "$sock" 2>/dev/null || true
                    systemctl mask "$sock" 2>/dev/null || true
                    print_status "Masked: ${sock}"
                    ((disabled_count++))
                fi
            fi
        fi
    done
    
    echo ""
    print_status "Service audit complete. ${disabled_count} services disabled."
    print_info "To unmask a service: systemctl unmask <service>"
    
    mark_completed "disable_unnecessary_services"
}

# ----------------------------------------------------------------------------
# Function: restrict_cron_at
# Purpose: Restrict cron and at scheduler access
# ----------------------------------------------------------------------------
restrict_cron_at() {
    print_section "RESTRICT CRON & AT ACCESS"
    
    print_info "Limiting cron and at access prevents unauthorized scheduled tasks."
    echo ""
    
    print_subsection "Cron Access Control"
    
    # Get current users who should have cron access
    local cron_users_input=""
    prompt_input "Users allowed to use cron (comma-separated)" "root" cron_users_input
    
    # Remove deny file, create allow file
    rm -f /etc/cron.deny
    
    : > /etc/cron.allow
    IFS=',' read -ra CRON_ARRAY <<< "$cron_users_input"
    for user in "${CRON_ARRAY[@]}"; do
        user=$(echo "$user" | xargs)  # trim whitespace
        if [ -n "$user" ]; then
            # Verify user exists
            if id "$user" &>/dev/null; then
                echo "$user" >> /etc/cron.allow
                print_status "Cron access granted: ${user}"
            else
                print_warning "User '${user}' does not exist. Skipping."
            fi
        fi
    done
    
    chmod 640 /etc/cron.allow
    chown root:root /etc/cron.allow
    print_status "Cron allow list configured"
    
    # Secure cron directories
    print_subsection "Cron Directory Permissions"
    
    local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
    for dir in "${cron_dirs[@]}"; do
        if [ -d "$dir" ]; then
            chmod 700 "$dir" 2>/dev/null || true
            chown root:root "$dir" 2>/dev/null || true
        fi
    done
    
    if [ -f /etc/crontab ]; then
        chmod 600 /etc/crontab
        chown root:root /etc/crontab
    fi
    
    if [ -f /etc/anacrontab ]; then
        chmod 600 /etc/anacrontab
        chown root:root /etc/anacrontab
    fi
    
    print_status "Cron directories secured (700/600 permissions)"
    
    # Handle at scheduler
    print_subsection "At Scheduler Control"
    
    if command_exists at; then
        if confirm "Remove 'at' scheduler entirely? (recommended for VPS)" "y"; then
            apt-get purge -y at >> "$LOG_FILE" 2>&1
            print_status "'at' scheduler removed"
        else
            rm -f /etc/at.deny
            : > /etc/at.allow
            echo "root" >> /etc/at.allow
            chmod 640 /etc/at.allow
            chown root:root /etc/at.allow
            print_status "'at' restricted to root only"
        fi
    else
        print_info "'at' scheduler is not installed"
    fi
    
    # Audit existing cron jobs
    print_subsection "Existing Cron Jobs Audit"
    
    echo -e "  ${BOLD}System crontab:${NC}"
    if [ -f /etc/crontab ]; then
        grep -v '^#\|^$\|^SHELL\|^PATH\|^MAILTO' /etc/crontab 2>/dev/null | \
            while IFS= read -r line; do
                echo -e "    ${GRAY}${line}${NC}"
            done
    fi
    
    echo -e "  ${BOLD}User crontabs:${NC}"
    for cron_user in $(cut -f1 -d: /etc/passwd 2>/dev/null); do
        local user_cron
        user_cron=$(crontab -l -u "$cron_user" 2>/dev/null | grep -v '^#\|^$' || true)
        if [ -n "$user_cron" ]; then
            echo -e "    ${CYAN}${cron_user}:${NC}"
            echo "$user_cron" | while IFS= read -r line; do
                echo -e "      ${GRAY}${line}${NC}"
            done
        fi
    done
    
    mark_completed "restrict_cron_at"
}

# ----------------------------------------------------------------------------
# Function: setup_dns_over_tls
# Purpose: Configure encrypted DNS to prevent DNS snooping
# ----------------------------------------------------------------------------
setup_dns_over_tls() {
    print_section "DNS OVER TLS (ENCRYPTED DNS)"
    
    print_info "Standard DNS queries are sent in plaintext."
    print_info "DNS over TLS encrypts queries to prevent snooping and manipulation."
    echo ""
    
    # Check current DNS
    print_subsection "Current DNS Configuration"
    if [ -f /etc/resolv.conf ]; then
        grep "^nameserver" /etc/resolv.conf | while IFS= read -r line; do
            echo -e "    ${GRAY}${line}${NC}"
        done
    fi
    echo ""
    
    # Install systemd-resolved if needed
    if ! service_exists "systemd-resolved"; then
        print_step "Installing systemd-resolved..."
        apt-get install -y systemd-resolved >> "$LOG_FILE" 2>&1
    fi
    
    backup_file /etc/systemd/resolved.conf
    
    print_subsection "DNS Provider Selection"
    
    local dns_choice=""
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select DNS provider:"
    echo -e "      ${CYAN}1)${NC} Cloudflare (1.1.1.1) - Fast, privacy-focused"
    echo -e "      ${CYAN}2)${NC} Quad9 (9.9.9.9) - Security-focused, malware blocking"
    echo -e "      ${CYAN}3)${NC} Google (8.8.8.8) - Reliable, widely used"
    echo -e "      ${CYAN}4)${NC} Cloudflare + Quad9 (recommended, redundant)"
    echo -e "      ${CYAN}5)${NC} Custom DNS servers"
    echo ""
    prompt_input "Choice" "4" dns_choice
    
    local dns_servers="" fallback_dns=""
    
    case "$dns_choice" in
        1)
            dns_servers="1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com"
            fallback_dns="9.9.9.9#dns.quad9.net"
            ;;
        2)
            dns_servers="9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net"
            fallback_dns="1.1.1.1#cloudflare-dns.com"
            ;;
        3)
            dns_servers="8.8.8.8#dns.google 8.8.4.4#dns.google"
            fallback_dns="1.1.1.1#cloudflare-dns.com"
            ;;
        4)
            dns_servers="1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net"
            fallback_dns="1.0.0.1#cloudflare-dns.com 149.112.112.112#dns.quad9.net"
            ;;
        5)
            prompt_input "Primary DNS (IP#hostname)" "" dns_servers
            prompt_input "Fallback DNS (IP#hostname)" "" fallback_dns
            ;;
        *)
            dns_servers="1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net"
            fallback_dns="1.0.0.1#cloudflare-dns.com 149.112.112.112#dns.quad9.net"
            ;;
    esac
    
    # Configure systemd-resolved
    print_subsection "Applying Configuration"
    
    cat > /etc/systemd/resolved.conf << EOF
# ============================================================
# VPS Hardening - DNS over TLS Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

[Resolve]
DNS=${dns_servers}
FallbackDNS=${fallback_dns}
DNSOverTLS=yes
DNSSEC=allow-downgrade
Cache=yes
CacheFromLocalhost=no
DNSStubListener=yes
DNSStubListenerExtra=
MulticastDNS=no
LLMNR=no
EOF
    
    chmod 644 /etc/systemd/resolved.conf
    print_status "systemd-resolved configured"
    
    # Enable and restart
    systemctl enable systemd-resolved >> "$LOG_FILE" 2>&1
    systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1
    
    if service_active "systemd-resolved"; then
        print_status "systemd-resolved is active"
    else
        print_warning "systemd-resolved failed to start"
    fi
    
    # Link resolv.conf
    print_subsection "Resolv.conf Integration"
    
    local current_link=""
    if [ -L /etc/resolv.conf ]; then
        current_link=$(readlink /etc/resolv.conf)
    fi
    
    if [ "$current_link" != "/run/systemd/resolve/stub-resolv.conf" ]; then
        if confirm "Replace /etc/resolv.conf with systemd-resolved stub? (recommended)"; then
            backup_file /etc/resolv.conf
            rm -f /etc/resolv.conf
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            print_status "/etc/resolv.conf linked to systemd-resolved stub"
        else
            print_info "Keeping existing /etc/resolv.conf"
            print_warning "DNS over TLS may not be fully effective"
        fi
    else
        print_info "/etc/resolv.conf already linked correctly"
    fi
    
    # Disable LLMNR and mDNS (prevent local network spoofing)
    print_subsection "Local Network Spoofing Prevention"
    
    if service_active "systemd-resolved"; then
        print_status "LLMNR disabled (configured in resolved.conf)"
        print_status "MulticastDNS disabled (configured in resolved.conf)"
    fi
    
    echo ""
    print_info "Verify with: resolvectl status"
    print_info "Test DNS: resolvectl query example.com"
    
    mark_completed "setup_dns_over_tls"
}

# ----------------------------------------------------------------------------
# Function: setup_login_security
# Purpose: Configure login timeouts, password quality, and PAM hardening
# ----------------------------------------------------------------------------
setup_login_security() {
    print_section "LOGIN & PASSWORD SECURITY"
    
    print_subsection "Password Quality Requirements"
    
    if confirm "Install and configure password quality enforcement?"; then
        apt-get install -y libpam-pwquality >> "$LOG_FILE" 2>&1
        backup_file /etc/security/pwquality.conf
        
        local min_len="" min_class=""
        prompt_input "Minimum password length" "14" min_len
        prompt_input "Minimum character classes (upper,lower,digit,special)" "3" min_class
        
        cat > /etc/security/pwquality.conf << EOF
# ============================================================
# VPS Hardening - Password Quality Requirements
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# Minimum password length
minlen = ${min_len}

# Minimum number of character classes required
minclass = ${min_class}

# Maximum number of consecutive same characters
maxrepeat = 3

# Maximum number of consecutive characters from same class
maxclassrepeat = 4

# Require at least N characters from each class
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1

# Reject passwords containing the username
reject_username

# Enforce for root as well
enforce_for_root

# Minimum number of characters that must differ from old password
difok = 4

# Reject passwords that are palindromes
palindrome

# Check against dictionary words
# dictcheck = 1

# Minimum password age (days, set in /etc/login.defs)
# PASS_MIN_DAYS 1
EOF
        
        chmod 644 /etc/security/pwquality.conf
        print_status "Password quality requirements configured"
    fi
    
    print_subsection "Login Failure Delay"
    
    if confirm "Add delay after failed login attempts? (anti-brute-force)"; then
        local delay_seconds=""
        prompt_input "Delay in seconds" "4" delay_seconds
        local delay_micro=$(( delay_seconds * 1000000 ))
        
        backup_file /etc/pam.d/common-auth
        
        if ! grep -q "pam_faildelay.so" /etc/pam.d/common-auth 2>/dev/null; then
            # Add at the beginning of auth section
            sed -i "1i auth optional pam_faildelay.so delay=${delay_micro}" /etc/pam.d/common-auth
            print_status "Login failure delay: ${delay_seconds} seconds"
        else
            sed -i "s/pam_faildelay.so delay=[0-9]*/pam_faildelay.so delay=${delay_micro}/" /etc/pam.d/common-auth
            print_status "Login failure delay updated: ${delay_seconds} seconds"
        fi
    fi
    
    print_subsection "Shell Session Timeout"
    
    local timeout_val=""
    prompt_input "Auto-logout after inactivity (seconds, 0 to skip)" "900" timeout_val
    
    if [ "$timeout_val" != "0" ] && [ -n "$timeout_val" ]; then
        cat > /etc/profile.d/99-vps-timeout.sh << EOF
# VPS Hardening - Shell Session Timeout
# Auto-logout after ${timeout_val} seconds of inactivity
TMOUT=${timeout_val}
readonly TMOUT
export TMOUT
EOF
        chmod 644 /etc/profile.d/99-vps-timeout.sh
        print_status "Shell auto-logout: ${timeout_val} seconds ($(( timeout_val / 60 )) minutes)"
    fi
    
    print_subsection "Login History & MOTD"
    
    # Configure login.defs
    backup_file /etc/login.defs
    
    if confirm "Set minimum password age to 1 day? (prevents rapid cycling)"; then
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
        print_status "Minimum password age: 1 day"
    fi
    
    if confirm "Set maximum password age to 90 days?"; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
        print_status "Maximum password age: 90 days"
    fi
    
    if confirm "Set password warning period to 14 days?"; then
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
        print_status "Password expiry warning: 14 days"
    fi
    
    # History size
    if confirm "Increase bash history size and add timestamps?"; then
        cat > /etc/profile.d/99-vps-history.sh << 'EOF'
# VPS Hardening - Enhanced Bash History
HISTSIZE=10000
HISTFILESIZE=20000
HISTCONTROL=ignoredups:erasedups
HISTTIMEFORMAT="%F %T "
shopt -s histappend
PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"
readonly HISTFILE
EOF
        chmod 644 /etc/profile.d/99-vps-history.sh
        print_status "Bash history enhanced (10000 entries, timestamps, read-only)"
    fi
    
    mark_completed "setup_login_security"
}

# ----------------------------------------------------------------------------
# Function: setup_user_hardening
# Purpose: Lock unused accounts, restrict umask, harden user defaults
# ----------------------------------------------------------------------------
setup_user_hardening() {
    print_section "USER ACCOUNT HARDENING"
    
    print_subsection "Lock Unused System Accounts"
    
    if confirm "Lock default system accounts that should never log in?"; then
        local accounts_to_lock=(
            "daemon" "bin" "sys" "games" "man" "lp"
            "mail" "news" "uucp" "proxy" "www-data"
            "backup" "list" "irc" "gnats" "nobody"
            "systemd-network" "systemd-resolve" "messagebus"
            "syslog" "uuidd" "tcpdump" "sshd" "pollinate"
        )
        
        local locked_count=0
        for acct in "${accounts_to_lock[@]}"; do
            if id "$acct" &>/dev/null; then
                # Don't lock the current user or root
                if [ "$acct" != "$TARGET_USER" ] && [ "$acct" != "root" ]; then
                    usermod -L "$acct" 2>>"$LOG_FILE" || true
                    usermod -s /usr/sbin/nologin "$acct" 2>>"$LOG_FILE" || true
                    ((locked_count++))
                fi
            fi
        done
        
        print_status "Locked ${locked_count} unused system accounts"
    fi
    
    print_subsection "Default Umask"
    
    local umask_val=""
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select default umask:"
    echo -e "      ${CYAN}1)${NC} 022 - Default (owner: rw, group: r, others: r)"
    echo -e "      ${CYAN}2)${NC} 027 - Restrictive (owner: rw, group: r, others: none) [recommended]"
    echo -e "      ${CYAN}3)${NC} 077 - Strict (owner: rw, group: none, others: none)"
    echo ""
    prompt_input "Choice" "2" umask_val
    
    case "$umask_val" in
        1) umask_val="022" ;;
        2) umask_val="027" ;;
        3) umask_val="077" ;;
        *) umask_val="027" ;;
    esac
    
    backup_file /etc/login.defs
    sed -i "s/^UMASK.*/UMASK           ${umask_val}/" /etc/login.defs
    
    cat > /etc/profile.d/99-vps-umask.sh << EOF
# VPS Hardening - Default Umask
umask ${umask_val}
EOF
    chmod 644 /etc/profile.d/99-vps-umask.sh
    print_status "Default umask set to ${umask_val}"
    
    print_subsection "Home Directory Permissions"
    
    if confirm "Restrict home directory permissions to 750?"; then
        # Only affect existing human users (UID >= 1000)
        while IFS=: read -r username _ uid _ _ homedir shell; do
            if [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ] && [ -d "$homedir" ]; then
                if [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
                    chmod 750 "$homedir" 2>/dev/null || true
                    print_status "Restricted: ${homedir} -> 750"
                fi
            fi
        done < /etc/passwd
        
        # Set default for new users
        backup_file /etc/adduser.conf
        if [ -f /etc/adduser.conf ]; then
            sed -i 's/^DIR_MODE=.*/DIR_MODE=0750/' /etc/adduser.conf
        fi
        print_status "New user home directories will default to 750"
    fi
    
    print_subsection "Account Expiration Defaults"
    
    if confirm "Set default account inactivity lock to 30 days?"; then
        backup_file /etc/default/useradd
        if [ -f /etc/default/useradd ]; then
            sed -i 's/^INACTIVE=.*/INACTIVE=30/' /etc/default/useradd
        else
            echo "INACTIVE=30" > /etc/default/useradd
        fi
        print_status "Accounts locked after 30 days of inactivity"
    fi
    
    print_subsection "TTY Access Restriction"
    
    if confirm "Restrict root login to specific TTYs? (console only)"; then
        backup_file /etc/securetty
        cat > /etc/securetty << 'EOF'
# VPS Hardening - Restrict root TTY access
# Only allow root login from console
console
tty1
tty2
EOF
        chmod 600 /etc/securetty
        print_status "Root TTY access restricted to console"
    fi
    
    mark_completed "setup_user_hardening"
}

# End of Section 4
# ============================================================================
# TIER 2 CONTINUED: AUDITING, LOG FORWARDING, KERNEL LOCKDOWN
# ============================================================================

# ----------------------------------------------------------------------------
# Function: install_lynis
# Purpose: Install Lynis security auditing tool with automated scans
# ----------------------------------------------------------------------------
install_lynis() {
    print_section "SECURITY AUDITING (LYNIS)"
    
    print_info "Lynis performs a comprehensive security audit based on"
    print_info "CIS benchmarks, checking hundreds of security controls."
    echo ""
    
    # Install Lynis
    if ! command_exists lynis; then
        print_step "Installing Lynis..."
        apt-get install -y lynis >> "$LOG_FILE" 2>&1
        print_status "Lynis installed"
    else
        print_info "Lynis is already installed"
        local lynis_version
        lynis_version=$(lynis --version 2>/dev/null | head -1 || echo "unknown")
        print_info "Version: ${lynis_version}"
    fi
    
    print_subsection "Initial Security Audit"
    
    if confirm "Run a quick Lynis security audit now? (takes 2-5 minutes)"; then
        print_step "Running Lynis audit (this may take a few minutes)..."
        echo ""
        
        local audit_output
        audit_output=$(lynis audit system --quick --no-colors 2>&1) || true
        
        # Extract key metrics
        local hardening_index
        hardening_index=$(echo "$audit_output" | grep -i "Hardening index" | grep -oP '\d+' | head -1 || echo "N/A")
        
        local warnings_count
        warnings_count=$(echo "$audit_output" | grep -i "Warnings" | grep -oP '\d+' | head -1 || echo "N/A")
        
        local suggestions_count
        suggestions_count=$(echo "$audit_output" | grep -i "Suggestions" | grep -oP '\d+' | head -1 || echo "N/A")
        
        echo ""
        print_separator
        echo -e "  ${BOLD}Lynis Audit Summary:${NC}"
        echo -e "    Hardening Index: ${CYAN}${hardening_index}/100${NC}"
        echo -e "    Warnings:        ${YELLOW}${warnings_count}${NC}"
        echo -e "    Suggestions:     ${MAGENTA}${suggestions_count}${NC}"
        print_separator
        
        # Save full report
        echo "$audit_output" > /root/lynis-initial-audit-${TIMESTAMP}.txt
        print_status "Full report saved: /root/lynis-initial-audit-${TIMESTAMP}.txt"
    fi
    
    print_subsection "Automated Weekly Audits"
    
    if confirm "Schedule weekly automated Lynis audits?"; then
        cat > /etc/cron.weekly/lynis-security-audit << 'CRONEOF'
#!/bin/bash
# VPS Hardening - Weekly Lynis Security Audit

REPORT_DIR="/var/log/lynis"
mkdir -p "$REPORT_DIR"

DATE=$(date +%Y%m%d)
REPORT_FILE="${REPORT_DIR}/lynis-report-${DATE}.txt"
LOG_FILE="${REPORT_DIR}/lynis-log-${DATE}.log"

# Run audit
/usr/bin/lynis audit system --cronjob --report-file "$REPORT_FILE" > "$LOG_FILE" 2>&1

# Extract hardening index
HARDENING=$(grep -i "Hardening index" "$REPORT_FILE" 2>/dev/null | grep -oP '\d+' | head -1)

# Log to syslog
logger -t lynis-audit -p auth.info "Weekly audit complete. Hardening index: ${HARDENING:-unknown}"

# Alert if hardening index drops below threshold
THRESHOLD=65
if [ -n "$HARDENING" ] && [ "$HARDENING" -lt "$THRESHOLD" ]; then
    logger -t lynis-audit -p auth.warning "ALERT: Hardening index ${HARDENING} is below threshold ${THRESHOLD}!"
fi

# Clean old reports (keep 12 weeks)
find "$REPORT_DIR" -name "lynis-*" -mtime +84 -delete 2>/dev/null

exit 0
CRONEOF
        
        chmod 755 /etc/cron.weekly/lynis-security-audit
        mkdir -p /var/log/lynis
        print_status "Weekly Lynis audit scheduled"
    fi
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}lynis audit system${NC}           # Full interactive audit"
    echo -e "    ${CYAN}lynis audit system --quick${NC}   # Quick audit"
    echo -e "    ${CYAN}lynis show details${NC}           # Show test details"
    echo -e "    ${CYAN}cat /var/log/lynis/*.txt${NC}     # View reports"
    
    mark_completed "install_lynis"
}

# ----------------------------------------------------------------------------
# Function: setup_log_forwarding
# Purpose: Configure remote log forwarding for anti-tampering
# ----------------------------------------------------------------------------
setup_log_forwarding() {
    print_section "LOG FORWARDING (ANTI-TAMPERING)"
    
    print_info "If an attacker gains root, their first move is deleting logs."
    print_info "Remote log forwarding sends copies to an external server"
    print_info "so evidence survives even if the VPS is fully compromised."
    echo ""
    
    print_subsection "Remote Syslog Server"
    
    local remote_server=""
    prompt_input "Remote syslog server address (e.g., logs.example.com)" "" remote_server
    
    if [ -z "$remote_server" ]; then
        print_warning "No server specified. Skipping log forwarding."
        print_info "You can configure this later by re-running this option."
        return 0
    fi
    
    local remote_port=""
    prompt_input "Remote syslog port" "514" remote_port
    
    local remote_proto=""
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Protocol:"
    echo -e "      ${CYAN}1)${NC} TCP (reliable, recommended)"
    echo -e "      ${CYAN}2)${NC} UDP (faster, may lose packets)"
    echo -e "      ${CYAN}3)${NC} TLS (encrypted, requires certificates)"
    echo ""
    prompt_input "Choice" "1" remote_proto
    
    # Install rsyslog if needed
    if ! command_exists rsyslogd; then
        print_step "Installing rsyslog..."
        apt-get install -y rsyslog >> "$LOG_FILE" 2>&1
    fi
    
    backup_directory /etc/rsyslog.d
    
    print_subsection "Configuring Forwarding"
    
    local proto_prefix="@"
    local proto_label="UDP"
    
    case "$remote_proto" in
        1)
            proto_prefix="@@"
            proto_label="TCP"
            ;;
        2)
            proto_prefix="@"
            proto_label="UDP"
            ;;
        3)
            proto_prefix="@@"
            proto_label="TLS"
            # Install TLS support
            apt-get install -y rsyslog-gnutls >> "$LOG_FILE" 2>&1
            
            cat > /etc/rsyslog.d/10-tls.conf << 'EOF'
# VPS Hardening - TLS Configuration for Remote Logging
global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="/etc/ssl/certs/ca-certificates.crt"
    DefaultNetstreamDriverCertFile="/etc/ssl/certs/ssl-cert-snakeoil.pem"
    DefaultNetstreamDriverKeyFile="/etc/ssl/private/ssl-cert-snakeoil.key"
)
EOF
            chmod 640 /etc/rsyslog.d/10-tls.conf
            print_status "TLS support configured"
            ;;
    esac
    
    cat > /etc/rsyslog.d/50-remote-forwarding.conf << EOF
# ============================================================
# VPS Hardening - Remote Log Forwarding
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Target: ${remote_server}:${remote_port} (${proto_label})
# ============================================================

# Forward all logs to remote server
*.* ${proto_prefix}${remote_server}:${remote_port}

# Optional: Forward only specific facilities
# auth,authpriv.*    ${proto_prefix}${remote_server}:${remote_port}
# kern.*             ${proto_prefix}${remote_server}:${remote_port}
# *.emerg            ${proto_prefix}${remote_server}:${remote_port}
EOF
    
    chmod 640 /etc/rsyslog.d/50-remote-forwarding.conf
    
    # Validate and restart rsyslog
    if rsyslogd -N1 >> "$LOG_FILE" 2>&1; then
        systemctl restart rsyslog >> "$LOG_FILE" 2>&1
        print_status "Log forwarding active: ${remote_server}:${remote_port} (${proto_label})"
    else
        print_error "Rsyslog configuration validation failed"
        print_info "Check: rsyslogd -N1"
    fi
    
    # Optional: local log encryption
    print_subsection "Local Log Protection"
    
    if confirm "Make log files immutable (append-only) with chattr?"; then
        local log_files=(
            "/var/log/auth.log"
            "/var/log/syslog"
            "/var/log/kern.log"
            "/var/log/fail2ban.log"
        )
        
        for log_file in "${log_files[@]}"; do
            if [ -f "$log_file" ]; then
                chattr +a "$log_file" 2>>"$LOG_FILE" || true
                print_status "Append-only: ${log_file}"
            fi
        done
        
        print_warning "Immutable logs may interfere with log rotation."
        print_info "To remove: chattr -a /var/log/auth.log"
    fi
    
    echo ""
    print_info "Verify forwarding: logger 'test message' && check remote server"
    
    mark_completed "setup_log_forwarding"
}

# ----------------------------------------------------------------------------
# Function: setup_kernel_lockdown
# Purpose: Enable kernel lockdown and module signing enforcement
# ----------------------------------------------------------------------------
setup_kernel_lockdown() {
    print_section "KERNEL LOCKDOWN & MODULE RESTRICTIONS"
    
    print_warning "═══════════════════════════════════════════════════════════"
    print_warning "  Kernel lockdown restricts even root from accessing raw"
    print_warning "  memory, loading unsigned modules, and modifying kernel"
    print_warning "  code. This may break some monitoring tools, custom"
    print_warning "  kernel modules, or hibernation."
    print_warning "═══════════════════════════════════════════════════════════"
    echo ""
    
    # Check current lockdown status
    print_subsection "Current Kernel Status"
    
    if [ -f /sys/kernel/security/lockdown ]; then
        local current_lockdown
        current_lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "unknown")
        print_info "Current lockdown: ${current_lockdown}"
    else
        print_info "Kernel lockdown not available (may need newer kernel)"
    fi
    
    print_info "Kernel: ${KERNEL_VERSION}"
    print_info "Secure Boot: $(mokutil --sb-state 2>/dev/null || echo 'unknown/not available')"
    echo ""
    
    print_subsection "Kernel Lockdown Mode"
    
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select lockdown mode:"
    echo -e "      ${CYAN}1)${NC} None - No lockdown (default)"
    echo -e "      ${CYAN}2)${NC} Integrity - Prevent kernel modification (recommended)"
    echo -e "      ${CYAN}3)${NC} Confidentiality - Prevent kernel data extraction (strict)"
    echo ""
    
    local lockdown_choice=""
    prompt_input "Choice" "2" lockdown_choice
    
    local lockdown_mode=""
    case "$lockdown_choice" in
        1) lockdown_mode="" ;;
        2) lockdown_mode="integrity" ;;
        3) lockdown_mode="confidentiality" ;;
        *) lockdown_mode="integrity" ;;
    esac
    
    if [ -n "$lockdown_mode" ]; then
        backup_file /etc/default/grub
        
        if grep -q "lockdown=" /etc/default/grub; then
            sed -i "s/lockdown=[a-z]*/lockdown=${lockdown_mode}/" /etc/default/grub
        else
            sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 lockdown=${lockdown_mode}\"/" /etc/default/grub
        fi
        
        if command_exists update-grub; then
            update-grub >> "$LOG_FILE" 2>&1
            print_status "Kernel lockdown '${lockdown_mode}' configured (active after reboot)"
        elif command_exists grub2-mkconfig; then
            grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1
            print_status "Kernel lockdown '${lockdown_mode}' configured (active after reboot)"
        else
            print_warning "GRUB update command not found. Add manually:"
            print_info "  lockdown=${lockdown_mode} to GRUB_CMDLINE_LINUX_DEFAULT"
        fi
    else
        print_info "No lockdown mode selected"
    fi
    
    print_subsection "Kernel Module Restrictions"
    
    if confirm "Prevent loading new kernel modules after boot?"; then
        print_warning "After reboot, NO new kernel modules can be loaded."
        print_warning "Ensure all needed modules (network, disk) are built-in."
        
        if confirm "Are you sure? This is difficult to reverse without console access."; then
            cat > /etc/sysctl.d/97-module-lock.conf << 'EOF'
# VPS Hardening - Prevent module loading after boot
# WARNING: This is irreversible until reboot
kernel.modules_disabled = 1
EOF
            chmod 644 /etc/sysctl.d/97-module-lock.conf
            print_status "Module loading will be disabled on next boot"
            print_warning "Do NOT apply this now if you need to load modules!"
        fi
    fi
    
    if confirm "Enforce kernel module signature verification?"; then
        cat > /etc/modprobe.d/99-module-signing.conf << 'EOF'
# VPS Hardening - Enforce module signatures
# Only signed modules can be loaded
options module.sig_enforce=1
EOF
        chmod 644 /etc/modprobe.d/99-module-signing.conf
        print_status "Module signature enforcement configured"
    fi
    
    print_subsection "Additional Kernel Protections"
    
    if confirm "Disable kernel profiling for non-root?"; then
        cat >> /etc/sysctl.d/99-vps-hardening.conf << 'EOF'

# Restrict perf events to root
kernel.perf_event_paranoid = 3
EOF
        sysctl --system >> "$LOG_FILE" 2>&1 || true
        print_status "Kernel profiling restricted"
    fi
    
    if confirm "Restrict access to /proc/kcore?"; then
        chmod 400 /proc/kcore 2>/dev/null || true
        print_status "/proc/kcore access restricted"
    fi
    
    echo ""
    print_info "Most kernel lockdown features require a reboot to activate"
    
    mark_completed "setup_kernel_lockdown"
}

# ============================================================================
# TIER 3: ZERO TRUST NETWORKING
# ============================================================================

# ----------------------------------------------------------------------------
# Function: setup_tailscale
# Purpose: Install Tailscale VPN for zero-trust SSH access
# ----------------------------------------------------------------------------
setup_tailscale() {
    print_section "TAILSCALE VPN (ZERO TRUST NETWORK)"
    
    print_info "Tailscale creates an encrypted WireGuard mesh network."
    print_info "Once connected, you can remove SSH from the public internet"
    print_info "entirely, making your VPS invisible to port scanners."
    echo ""
    
    # Check if already installed
    if command_exists tailscale; then
        print_info "Tailscale is already installed"
        local ts_status
        ts_status=$(tailscale status 2>/dev/null | head -3 || echo "not connected")
        echo -e "    ${GRAY}${ts_status}${NC}"
        echo ""
    else
        if ! confirm "Install Tailscale?"; then
            return 0
        fi
        
        print_step "Installing Tailscale..."
        if curl -fsSL https://tailscale.com/install.sh | sh >> "$LOG_FILE" 2>&1; then
            print_status "Tailscale installed"
        else
            print_error "Tailscale installation failed"
            return 1
        fi
    fi
    
    print_subsection "Tailscale Authentication"
    
    if ! tailscale status &>/dev/null 2>&1; then
        print_step "Starting Tailscale authentication..."
        print_info "You will need to open a URL in your browser to authenticate."
        echo ""
        
        tailscale up 2>&1 || true
        echo ""
    else
        print_info "Tailscale is already authenticated"
    fi
    
    # Show Tailscale IP
    print_subsection "Tailscale Network Info"
    
    local ts_ip
    ts_ip=$(tailscale ip -4 2>/dev/null || echo "pending...")
    print_info "Tailscale IP: ${ts_ip}"
    
    local ts_hostname
    ts_hostname=$(tailscale status 2>/dev/null | head -1 | awk '{print $1}' || echo "unknown")
    print_info "Tailscale hostname: ${ts_hostname}"
    
    # Restrict SSH to Tailscale
    print_subsection "SSH Access Restriction"
    
    if command_exists ufw; then
        if [ -z "$SSH_PORT" ]; then
            SSH_PORT=$(load_state "SSH_PORT")
            SSH_PORT="${SSH_PORT:-2222}"
        fi
        
        print_warning "This will remove public SSH access and only allow"
        print_warning "connections through the Tailscale network interface."
        echo ""
        
        if confirm "Restrict SSH to Tailscale interface ONLY?"; then
            # Remove public SSH rule
            ufw delete allow "${SSH_PORT}/tcp" 2>/dev/null || true
            ufw delete limit "${SSH_PORT}/tcp" 2>/dev/null || true
            
            # Add Tailscale-only rule
            ufw allow in on tailscale0 to any port "${SSH_PORT}" proto tcp \
                comment "SSH via Tailscale only" >> "$LOG_FILE" 2>&1
            
            ufw reload >> "$LOG_FILE" 2>&1
            print_status "SSH restricted to Tailscale interface"
            
            echo ""
            print_warning "═══════════════════════════════════════════════════════════"
            print_warning "  SSH is now ONLY accessible via Tailscale!"
            print_warning ""
            print_warning "  Connect with: ssh -p ${SSH_PORT} ${ts_ip}"
            print_warning "  Or:           ssh -p ${SSH_PORT} ${ts_hostname}"
            print_warning ""
            print_warning "  Make sure Tailscale is running on your local machine!"
            print_warning "═══════════════════════════════════════════════════════════"
        fi
    else
        print_warning "UFW not found. Configure iptables manually for Tailscale-only SSH."
    fi
    
    # Enable Tailscale SSH (optional)
    print_subsection "Tailscale SSH (Optional)"
    
    if confirm "Enable Tailscale SSH? (SSH through Tailscale without managing keys)"; then
        tailscale up --ssh >> "$LOG_FILE" 2>&1
        print_status "Tailscale SSH enabled"
        print_info "Access via: ssh user@${ts_hostname}"
    fi
    
    # Auto-update Tailscale
    if confirm "Enable Tailscale auto-updates?"; then
        tailscale set --auto-update >> "$LOG_FILE" 2>&1 || true
        print_status "Tailscale auto-updates enabled"
    fi
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}tailscale status${NC}          # Show network status"
    echo -e "    ${CYAN}tailscale ip${NC}              # Show Tailscale IPs"
    echo -e "    ${CYAN}tailscale ping <host>${NC}     # Test connectivity"
    echo -e "    ${CYAN}tailscale down${NC}            # Disconnect"
    
    mark_completed "setup_tailscale"
}

# ----------------------------------------------------------------------------
# Function: setup_fwknop
# Purpose: Configure Single Packet Authorization for invisible SSH
# ----------------------------------------------------------------------------
setup_fwknop() {
    print_section "SINGLE PACKET AUTHORIZATION (fwknop)"
    
    print_info "fwknop keeps your SSH port completely CLOSED and invisible."
    print_info "You send one encrypted UDP 'knock' packet from your device"
    print_info "to temporarily open the port for your IP only (30 seconds)."
    echo ""
    print_info "Workflow:"
    echo -e "    ${GRAY}1. Port is BLOCKED (invisible to scanners)${NC}"
    echo -e "    ${GRAY}2. You send encrypted knock from phone/laptop${NC}"
    echo -e "    ${GRAY}3. Port opens for YOUR IP for 30 seconds${NC}"
    echo -e "    ${GRAY}4. You SSH in during the window${NC}"
    echo -e "    ${GRAY}5. Port closes automatically${NC}"
    echo ""
    
    if ! confirm "Install and configure fwknop?"; then
        return 0
    fi
    
    # Install fwknop
    if ! command_exists fwknopd; then
        print_step "Installing fwknop..."
        apt-get install -y fwknop-server >> "$LOG_FILE" 2>&1
        print_status "fwknop installed"
    fi
    
    # Determine SSH port
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        SSH_PORT="${SSH_PORT:-2222}"
    fi
    
    backup_file /etc/fwknop/fwknopd.conf
    backup_file /etc/fwknop/access.conf
    
    print_subsection "Key Generation"
    
    # Generate strong keys
    local spa_key
    spa_key=$(openssl rand -base64 32)
    local hmac_key
    hmac_key=$(openssl rand -base64 32)
    
    print_status "Encryption keys generated"
    
    print_subsection "Server Configuration"
    
    # Detect primary network interface
    local primary_iface
    primary_iface=$(ip route | grep default | awk '{print $5}' | head -1)
    primary_iface="${primary_iface:-eth0}"
    
    cat > /etc/fwknop/access.conf << EOF
# ============================================================
# VPS Hardening - fwknop Access Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

SOURCE                  ANY
OPEN_PORTS              tcp/${SSH_PORT}
FW_ACCESS_TIMEOUT       30
REQUIRE_SOURCE_ADDRESS  Y
KEY_BASE64              ${spa_key}
HMAC_KEY_BASE64         ${hmac_key}
EOF
    
    chmod 600 /etc/fwknop/access.conf
    
    # Configure fwknopd
    if [ -f /etc/fwknop/fwknopd.conf ]; then
        sed -i "s/^#\?PCAP_INTF .*/PCAP_INTF             ${primary_iface};/" /etc/fwknop/fwknopd.conf 2>/dev/null || true
        sed -i "s/^#\?ENABLE_IPT_FORWARDING .*/ENABLE_IPT_FORWARDING   N;/" /etc/fwknop/fwknopd.conf 2>/dev/null || true
    fi
    
    # Enable and start
    systemctl enable fwknop-server >> "$LOG_FILE" 2>&1
    
    if systemctl restart fwknop-server >> "$LOG_FILE" 2>&1; then
        print_status "fwknop server started"
    else
        print_warning "fwknop failed to start. Check: journalctl -u fwknop-server"
    fi
    
    # Configure UFW to block SSH by default
    if command_exists ufw; then
        if confirm "Block SSH port in UFW (fwknop will open it on demand)?"; then
            ufw delete allow "${SSH_PORT}/tcp" 2>/dev/null || true
            ufw delete limit "${SSH_PORT}/tcp" 2>/dev/null || true
            print_status "SSH port blocked in UFW (fwknop manages access)"
        fi
    fi
    
    # Display client instructions
    print_subsection "Client Configuration (SAVE THIS!)"
    
    echo ""
    print_warning "═══════════════════════════════════════════════════════════"
    print_warning "  SAVE THESE CREDENTIALS IN A SECURE LOCATION!"
    print_warning "  You will need them on every device that connects."
    print_warning "═══════════════════════════════════════════════════════════"
    echo ""
    echo -e "  ${BOLD}SPA Key:${NC}     ${YELLOW}${spa_key}${NC}"
    echo -e "  ${BOLD}HMAC Key:${NC}    ${YELLOW}${hmac_key}${NC}"
    echo -e "  ${BOLD}SSH Port:${NC}    ${YELLOW}${SSH_PORT}${NC}"
    echo -e "  ${BOLD}Server IP:${NC}   ${YELLOW}$(hostname -I | awk '{print $1}')${NC}"
    echo ""
    echo -e "  ${BOLD}Client Command (Linux/macOS):${NC}"
    echo -e "    ${CYAN}fwknop -A tcp/${SSH_PORT} -D <SERVER_IP> \\${NC}"
    echo -e "    ${CYAN}  --key-base64 ${spa_key} \\${NC}"
    echo -e "    ${CYAN}  --hmac-base64 ${hmac_key}${NC}"
    echo ""
    echo -e "  ${BOLD}Then immediately SSH:${NC}"
    echo -e "    ${CYAN}ssh -p ${SSH_PORT} user@<SERVER_IP>${NC}"
    echo ""
    echo -e "  ${BOLD}Mobile Apps:${NC}"
    echo -e "    ${GRAY}• Android: FWKnop2 (Play Store)${NC}"
    echo -e "    ${GRAY}• iOS: FWKnop (App Store)${NC}"
    echo ""
    
    # Save credentials to a file
    local creds_file="/root/.fwknop-credentials-${TIMESTAMP}.txt"
    cat > "$creds_file" << EOF
fwknop Credentials - Generated $(date)
========================================
Server IP:  $(hostname -I | awk '{print $1}')
SSH Port:   ${SSH_PORT}
SPA Key:    ${spa_key}
HMAC Key:   ${hmac_key}

Client Command:
fwknop -A tcp/${SSH_PORT} -D <SERVER_IP> \
  --key-base64 ${spa_key} \
  --hmac-base64 ${hmac_key}
EOF
    chmod 600 "$creds_file"
    print_info "Credentials saved to: ${creds_file}"
    
    mark_completed "setup_fwknop"
}

# End of Section 5
# ============================================================================
# SECURITY STATUS DASHBOARD
# ============================================================================

# ----------------------------------------------------------------------------
# Function: show_security_status
# Purpose: Display comprehensive security status of the system
# ----------------------------------------------------------------------------
show_security_status() {
    print_section "CURRENT SECURITY STATUS DASHBOARD"
    
    # ---- System Info ----
    print_subsection "System Information"
    echo -e "    ${BOLD}Hostname:${NC}      $(hostname)"
    echo -e "    ${BOLD}OS:${NC}            ${OS_NAME}"
    echo -e "    ${BOLD}Kernel:${NC}        ${KERNEL_VERSION}"
    echo -e "    ${BOLD}Architecture:${NC}  ${ARCH}"
    echo -e "    ${BOLD}Uptime:${NC}        $(uptime -p 2>/dev/null || uptime)"
    echo -e "    ${BOLD}Current User:${NC}  ${TARGET_USER}"
    echo ""
    
    # ---- SSH Status ----
    print_subsection "SSH Configuration"
    local ssh_port_current
    ssh_port_current=$(grep -h "^Port " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | \
                       head -1 | awk '{print $2}' || echo "22")
    echo -e "    ${BOLD}Port:${NC}                 ${CYAN}${ssh_port_current}${NC}"
    
    local pass_auth
    pass_auth=$(grep -h "^PasswordAuthentication " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | \
                head -1 | awk '{print $2}' || echo "unknown")
    if [ "$pass_auth" = "no" ]; then
        echo -e "    ${BOLD}Password Auth:${NC}        ${GREEN}disabled ✔${NC}"
    else
        echo -e "    ${BOLD}Password Auth:${NC}        ${RED}enabled ✘${NC}"
    fi
    
    local root_login
    root_login=$(grep -h "^PermitRootLogin " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | \
                 head -1 | awk '{print $2}' || echo "unknown")
    if [ "$root_login" = "no" ]; then
        echo -e "    ${BOLD}Root Login:${NC}           ${GREEN}disabled ✔${NC}"
    else
        echo -e "    ${BOLD}Root Login:${NC}           ${RED}${root_login} ✘${NC}"
    fi
    
    local pubkey_auth
    pubkey_auth=$(grep -h "^PubkeyAuthentication " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | \
                  head -1 | awk '{print $2}' || echo "unknown")
    echo -e "    ${BOLD}Pubkey Auth:${NC}          ${pubkey_auth}"
    echo ""
    
    # ---- Firewall ----
    print_subsection "Firewall (UFW)"
    if command_exists ufw; then
        local ufw_status
        ufw_status=$(ufw status | head -1 | awk '{print $2}')
        if [ "$ufw_status" = "active" ]; then
            echo -e "    ${BOLD}Status:${NC}               ${GREEN}active ✔${NC}"
            local rule_count
            rule_count=$(ufw status numbered | grep -c '^\[' || echo "0")
            echo -e "    ${BOLD}Active Rules:${NC}         ${rule_count}"
        else
            echo -e "    ${BOLD}Status:${NC}               ${RED}inactive ✘${NC}"
        fi
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""
    
    # ---- Fail2ban ----
    print_subsection "Intrusion Prevention (Fail2ban)"
    if command_exists fail2ban-client; then
        local f2b_status
        f2b_status=$(systemctl is-active fail2ban 2>/dev/null || echo "inactive")
        if [ "$f2b_status" = "active" ]; then
            echo -e "    ${BOLD}Status:${NC}               ${GREEN}active ✔${NC}"
            local jails
            jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/^\s*//' || echo "none")
            echo -e "    ${BOLD}Active Jails:${NC}         ${CYAN}${jails}${NC}"
            
            local total_banned=0
            for jail in $(echo "$jails" | tr ',' ' '); do
                jail=$(echo "$jail" | xargs)
                if [ -n "$jail" ]; then
                    local banned
                    banned=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | grep -oP '\d+' || echo "0")
                    total_banned=$(( total_banned + banned ))
                fi
            done
            echo -e "    ${BOLD}Currently Banned:${NC}     ${total_banned} IPs"
        else
            echo -e "    ${BOLD}Status:${NC}               ${RED}inactive ✘${NC}"
        fi
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""
    
    # ---- AppArmor ----
    print_subsection "Mandatory Access Control (AppArmor)"
    if command_exists aa-status; then
        local aa_status
        aa_status=$(systemctl is-active apparmor 2>/dev/null || echo "inactive")
        if [ "$aa_status" = "active" ]; then
            echo -e "    ${BOLD}Status:${NC}               ${GREEN}active ✔${NC}"
            local aa_enforced
            aa_enforced=$(aa-status 2>/dev/null | grep -oP '\d+(?= profiles are in enforce mode)' | head -1 || echo "0")
            local aa_complain
            aa_complain=$(aa-status 2>/dev/null | grep -oP '\d+(?= profiles are in complain mode)' | head -1 || echo "0")
            echo -e "    ${BOLD}Enforced Profiles:${NC}    ${GREEN}${aa_enforced}${NC}"
            echo -e "    ${BOLD}Complain Profiles:${NC}    ${YELLOW}${aa_complain}${NC}"
        else
            echo -e "    ${BOLD}Status:${NC}               ${YELLOW}inactive${NC}"
        fi
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""
    
    # ---- Audit Daemon ----
    print_subsection "Kernel Auditing (auditd)"
    if command_exists auditctl; then
        local audit_status
        audit_status=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
        if [ "$audit_status" = "active" ]; then
            echo -e "    ${BOLD}Status:${NC}               ${GREEN}active ✔${NC}"
            local audit_rules
            audit_rules=$(auditctl -l 2>/dev/null | wc -l || echo "0")
            echo -e "    ${BOLD}Loaded Rules:${NC}         ${audit_rules}"
        else
            echo -e "    ${BOLD}Status:${NC}               ${YELLOW}inactive${NC}"
        fi
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""
    
    # ---- File Integrity (AIDE) ----
    print_subsection "File Integrity Monitoring (AIDE)"
    if command_exists aide; then
        echo -e "    ${BOLD}Status:${NC}               ${GREEN}installed ✔${NC}"
        if [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ]; then
            echo -e "    ${BOLD}Database:${NC}             ${GREEN}initialized ✔${NC}"
        else
            echo -e "    ${BOLD}Database:${NC}             ${YELLOW}not initialized${NC}"
        fi
        if [ -f /etc/cron.daily/aide-integrity-check ]; then
            echo -e "    ${BOLD}Daily Check:${NC}          ${GREEN}scheduled ✔${NC}"
        else
            echo -e "    ${BOLD}Daily Check:${NC}          ${YELLOW}not scheduled${NC}"
        fi
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""
    
    # ---- Automatic Updates ----
    print_subsection "Automatic Updates"
    if package_installed "unattended-upgrades"; then
        local unattended_status
        unattended_status=$(systemctl is-active unattended-upgrades 2>/dev/null || echo "inactive")
        if [ "$unattended_status" = "active" ]; then
            echo -e "    ${BOLD}Status:${NC}               ${GREEN}active ✔${NC}"
            if [ -f /etc/apt/apt.conf.d/51unattended-upgrades-custom ]; then
                local auto_reboot
                auto_reboot=$(grep "Automatic-Reboot " /etc/apt/apt.conf.d/51unattended-upgrades-custom 2>/dev/null | \
                              grep -oP '"[^"]+"' | tr -d '"' | head -1)
                echo -e "    ${BOLD}Auto-Reboot:${NC}          ${auto_reboot:-false}"
            fi
        else
            echo -e "    ${BOLD}Status:${NC}               ${YELLOW}inactive${NC}"
        fi
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""
    
    # ---- Kernel Hardening ----
    print_subsection "Kernel Security Parameters"
    echo -e "    ${BOLD}ASLR:${NC}                 $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo 'N/A')/2"
    echo -e "    ${BOLD}dmesg_restrict:${NC}       $(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo 'N/A')"
    echo -e "    ${BOLD}kptr_restrict:${NC}        $(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo 'N/A')"
    echo -e "    ${BOLD}SYN Cookies:${NC}          $(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo 'N/A')"
    echo -e "    ${BOLD}RP Filter:${NC}            $(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo 'N/A')"
    echo -e "    ${BOLD}ptrace_scope:${NC}         $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 'N/A')"
    echo ""
    
    # ---- Tailscale ----
    print_subsection "Zero Trust Network (Tailscale)"
    if command_exists tailscale; then
        local ts_backend
        ts_backend=$(tailscale status --json 2>/dev/null | grep -oP '"BackendState":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
        if [ "$ts_backend" = "Running" ]; then
            echo -e "    ${BOLD}Status:${NC}               ${GREEN}connected ✔${NC}"
            local ts_ip
            ts_ip=$(tailscale ip -4 2>/dev/null | head -1 || echo "N/A")
            echo -e "    ${BOLD}Tailscale IP:${NC}         ${CYAN}${ts_ip}${NC}"
        else
            echo -e "    ${BOLD}Status:${NC}               ${YELLOW}${ts_backend}${NC}"
        fi
    else
        echo -e "    ${BOLD}Status:${NC}               ${GRAY}not installed${NC}"
    fi
    echo ""
    
    # ---- fwknop ----
    print_subsection "Single Packet Authorization (fwknop)"
    if command_exists fwknopd; then
        local fwknop_status
        fwknop_status=$(systemctl is-active fwknop-server 2>/dev/null || echo "inactive")
        if [ "$fwknop_status" = "active" ]; then
            echo -e "    ${BOLD}Status:${NC}               ${GREEN}active ✔${NC}"
        else
            echo -e "    ${BOLD}Status:${NC}               ${YELLOW}inactive${NC}"
        fi
    else
        echo -e "    ${BOLD}Status:${NC}               ${GRAY}not installed${NC}"
    fi
    echo ""
    
    # ---- Listening Ports ----
    print_subsection "Listening Network Ports"
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{printf "    %-30s %s\n", $4, $6}' | head -15
    local total_ports
    total_ports=$(ss -tlnp 2>/dev/null | grep -c LISTEN || echo "0")
    echo ""
    echo -e "    ${BOLD}Total listening ports:${NC} ${total_ports}"
    echo ""
    
    # ---- Recent Auth Failures ----
    print_subsection "Recent Authentication Activity"
    if [ -f /var/log/auth.log ]; then
        local failed_logins
        failed_logins=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "0")
        echo -e "    ${BOLD}Failed logins today:${NC}  ${failed_logins}"
        
        local successful_logins
        successful_logins=$(grep -c "Accepted publickey\|Accepted password" /var/log/auth.log 2>/dev/null || echo "0")
        echo -e "    ${BOLD}Successful logins:${NC}    ${successful_logins}"
    elif journalctl -u ssh &>/dev/null; then
        local failed_logins
        failed_logins=$(journalctl -u ssh --since today 2>/dev/null | grep -c "Failed password" || echo "0")
        echo -e "    ${BOLD}Failed logins today:${NC}  ${failed_logins}"
    fi
    echo ""
    
    # ---- Disk & Memory ----
    print_subsection "System Resources"
    local disk_usage
    disk_usage=$(df -h / 2>/dev/null | awk 'NR==2 {print $5}')
    echo -e "    ${BOLD}Disk Usage (/):${NC}       ${disk_usage}"
    
    local mem_usage
    mem_usage=$(free -h 2>/dev/null | awk 'NR==2 {printf "%s / %s (%.0f%%)\n", $3, $2, $3/$2*100}')
    echo -e "    ${BOLD}Memory Usage:${NC}         ${mem_usage}"
    
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    echo -e "    ${BOLD}Load Average:${NC}         ${load_avg}"
    echo ""
    
    print_separator
    echo -e "  ${DIM}Log file: ${LOG_FILE}${NC}"
    echo -e "  ${DIM}Backups:  ${BACKUP_DIR}${NC}"
    echo ""
}

# ============================================================================
# GENERATE FINAL REPORT
# ============================================================================

generate_report() {
    print_step "Generating hardening report..."
    
    {
        echo "================================================================"
        echo "  VPS HARDENING REPORT"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Script Version: ${SCRIPT_VERSION}"
        echo "================================================================"
        echo ""
        echo "System Information:"
        echo "  Hostname: $(hostname)"
        echo "  OS: ${OS_NAME}"
        echo "  Kernel: ${KERNEL_VERSION}"
        echo "  IP: $(hostname -I 2>/dev/null | awk '{print $1}')"
        echo ""
        echo "Completed Tasks:"
        for task in "${!COMPLETED_TASKS[@]}"; do
            echo "  ✔ ${task} (${COMPLETED_TASKS[$task]})"
        done
        echo ""
        
        if [ ${#FAILED_TASKS[@]} -gt 0 ]; then
            echo "Failed Tasks:"
            for task in "${!FAILED_TASKS[@]}"; do
                echo "  ✘ ${task}: ${FAILED_TASKS[$task]}"
            done
            echo ""
        fi
        
        echo "SSH Access:"
        [ -n "$SSH_PORT" ] && echo "  New Port: ${SSH_PORT}"
        echo "  Command: ssh -p ${SSH_PORT:-22} ${TARGET_USER}@$(hostname -I | awk '{print $1}')"
        echo ""
        echo "Configuration Backups:"
        echo "  Location: ${BACKUP_DIR}"
        echo ""
        echo "Log Files:"
        echo "  Script log: ${LOG_FILE}"
        echo "  System log: /var/log/syslog"
        echo "  Auth log:   /var/log/auth.log"
        echo ""
        echo "================================================================"
    } > "$REPORT_FILE"
    
    chmod 600 "$REPORT_FILE"
    print_status "Report saved to: ${REPORT_FILE}"
}

# ============================================================================
# BATCH OPERATIONS
# ============================================================================

run_tier0_essential() {
    print_section "RUNNING ALL TIER 0 - ESSENTIAL HARDENING"
    print_warning "This will run: System Update, SSH, Firewall, Fail2ban, Kernel, Auto-Updates"
    
    if ! confirm "Continue with Tier 0 batch execution?"; then
        return 0
    fi
    
    system_update
    harden_ssh
    configure_firewall
    setup_fail2ban
    kernel_hardening
    setup_auto_updates
    setup_user_account
    
    print_section "TIER 0 COMPLETE"
    print_status "All essential hardening tasks completed"
}

run_tier0_plus_tier1() {
    print_section "RUNNING TIER 0 + TIER 1 - ESSENTIAL + HIGH IMPACT"
    print_warning "This runs all essential hardening plus AppArmor, AIDE, auditd, etc."
    
    if ! confirm "Continue with Tier 0+1 batch execution?"; then
        return 0
    fi
    
    # Tier 0
    system_update
    harden_ssh
    configure_firewall
    setup_fail2ban
    kernel_hardening
    setup_auto_updates
    setup_user_account
    
    # Tier 1
    secure_shared_memory
    disable_unused_protocols
    setup_apparmor
    setup_aide
    setup_auditd
    secure_tmp_directories
    
    print_section "TIER 0 + TIER 1 COMPLETE"
    print_status "Essential and high-impact hardening completed"
}

run_full_hardening() {
    print_section "RUNNING FULL HARDENING (TIER 0 + 1 + 2)"
    print_warning "This runs ALL Tier 0, 1, and 2 functions (21 hardening tasks)"
    print_warning "This may take 20-40 minutes depending on your system."
    
    if ! confirm "Continue with full batch execution?"; then
        return 0
    fi
    
    # Tier 0
    system_update
    harden_ssh
    configure_firewall
    setup_fail2ban
    kernel_hardening
    setup_auto_updates
    setup_user_account
    
    # Tier 1
    secure_shared_memory
    disable_unused_protocols
    setup_apparmor
    setup_aide
    setup_auditd
    secure_tmp_directories
    
    # Tier 2
    setup_resource_limits
    disable_unnecessary_services
    restrict_cron_at
    setup_dns_over_tls
    setup_login_security
    setup_user_hardening
    install_lynis
    setup_kernel_lockdown
    
    print_section "FULL HARDENING COMPLETE"
    print_status "All Tier 0, 1, and 2 hardening completed"
    print_info "For Zero Trust networking, run options 22 (Tailscale) or 23 (fwknop)"
}

# ============================================================================
# INTERACTIVE MENU
# ============================================================================

show_menu() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║        VPS HARDENING - INTERACTIVE MENU v2.0                     ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "  ${GREEN}${BOLD}━━━ TIER 0: ESSENTIAL HARDENING ━━━${NC}"
    echo -e "   ${WHITE} 1)${NC} System Update & Cleanup"
    echo -e "   ${WHITE} 2)${NC} SSH Hardening (with lockout prevention)"
    echo -e "   ${WHITE} 3)${NC} Firewall Configuration (UFW)"
    echo -e "   ${WHITE} 4)${NC} Fail2ban Setup"
    echo -e "   ${WHITE} 5)${NC} Kernel Hardening (sysctl)"
    echo -e "   ${WHITE} 6)${NC} Automatic Security Updates"
    echo -e "   ${WHITE} 7)${NC} User Account & Sudo Setup"
    echo ""
    
    echo -e "  ${YELLOW}${BOLD}━━━ TIER 1: HIGH IMPACT DEFENSES ━━━${NC}"
    echo -e "   ${WHITE} 8)${NC} Secure Shared Memory (/dev/shm)"
    echo -e "   ${WHITE} 9)${NC} Disable Unused Network Protocols"
    echo -e "   ${WHITE}10)${NC} AppArmor (Mandatory Access Control)"
    echo -e "   ${WHITE}11)${NC} File Integrity Monitoring (AIDE)"
    echo -e "   ${WHITE}12)${NC} Kernel Audit Daemon (auditd)"
    echo -e "   ${WHITE}13)${NC} Secure Temporary Directories"
    echo ""
    
    echo -e "  ${MAGENTA}${BOLD}━━━ TIER 2: ADVANCED CONTROLS ━━━${NC}"
    echo -e "   ${WHITE}14)${NC} Resource Limits & Fork Bomb Protection"
    echo -e "   ${WHITE}15)${NC} Disable Unnecessary Services"
    echo -e "   ${WHITE}16)${NC} Restrict Cron & At Access"
    echo -e "   ${WHITE}17)${NC} DNS over TLS (Encrypted DNS)"
    echo -e "   ${WHITE}18)${NC} Login & Password Security"
    echo -e "   ${WHITE}19)${NC} User Account Hardening"
    echo -e "   ${WHITE}20)${NC} Security Auditing (Lynis)"
    echo -e "   ${WHITE}21)${NC} Log Forwarding (Anti-Tampering)"
    echo -e "   ${WHITE}22)${NC} Kernel Lockdown & Module Restrictions"
    echo ""
    
    echo -e "  ${RED}${BOLD}━━━ TIER 3: ZERO TRUST NETWORKING ━━━${NC}"
    echo -e "   ${WHITE}23)${NC} Tailscale VPN (recommended)"
    echo -e "   ${WHITE}24)${NC} Single Packet Authorization (fwknop)"
    echo ""
    
    echo -e "  ${CYAN}${BOLD}━━━ BATCH OPERATIONS ━━━${NC}"
    echo -e "   ${WHITE}30)${NC} Run ALL Tier 0 (Essential)"
    echo -e "   ${WHITE}31)${NC} Run Tier 0 + Tier 1 (Essential + High Impact)"
    echo -e "   ${WHITE}32)${NC} Run Full Hardening (Tier 0 + 1 + 2)"
    echo ""
    
    echo -e "  ${BLUE}${BOLD}━━━ INFORMATION & UTILITIES ━━━${NC}"
    echo -e "   ${WHITE} s)${NC} Show Current Security Status"
    echo -e "   ${WHITE} r)${NC} Generate Hardening Report"
    echo -e "   ${WHITE} l)${NC} View Log File"
    echo -e "   ${WHITE} b)${NC} List Backups"
    echo -e "   ${WHITE} q)${NC} Quit"
    echo ""
    
    print_separator
}

# ============================================================================
# MAIN EXECUTION LOOP
# ============================================================================

main() {
    # Initial checks
    check_root
    init_logging
    print_banner
    
    # System detection
    detect_os
    check_internet
    create_backup_dir
    
    # Load any saved state
    if [ -f "$STATE_FILE" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        local saved_user
        saved_user=$(load_state "ADMIN_USER")
        [ -n "$saved_user" ] && TARGET_USER="$saved_user"
    fi
    
    echo ""
    print_info "Ready to begin. Press Enter to continue..."
    read -r
    
    # Main menu loop
    while true; do
        show_menu
        echo -ne "  ${BOLD}${MAGENTA}Select option: ${NC}"
        read -r choice
        
        echo ""
        
        case "$choice" in
            # Tier 0
            1)  system_update ;;
            2)  harden_ssh ;;
            3)  configure_firewall ;;
            4)  setup_fail2ban ;;
            5)  kernel_hardening ;;
            6)  setup_auto_updates ;;
            7)  setup_user_account ;;
            
            # Tier 1
            8)  secure_shared_memory ;;
            9)  disable_unused_protocols ;;
            10) setup_apparmor ;;
            11) setup_aide ;;
            12) setup_auditd ;;
            13) secure_tmp_directories ;;
            
            # Tier 2
            14) setup_resource_limits ;;
            15) disable_unnecessary_services ;;
            16) restrict_cron_at ;;
            17) setup_dns_over_tls ;;
            18) setup_login_security ;;
            19) setup_user_hardening ;;
            20) install_lynis ;;
            21) setup_log_forwarding ;;
            22) setup_kernel_lockdown ;;
            
            # Tier 3
            23) setup_tailscale ;;
            24) setup_fwknop ;;
            
            # Batch operations
            30) run_tier0_essential ;;
            31) run_tier0_plus_tier1 ;;
            32) run_full_hardening ;;
            
            # Information & utilities
            s|S)
                show_security_status
                ;;
            r|R)
                generate_report
                echo ""
                if confirm "View the report now?"; then
                    less "$REPORT_FILE"
                fi
                ;;
            l|L)
                if [ -f "$LOG_FILE" ]; then
                    less "$LOG_FILE"
                else
                    print_error "Log file not found"
                fi
                ;;
            b|B)
                print_section "CONFIGURATION BACKUPS"
                if [ -d "/root/.vps-hardening-backups" ]; then
                    print_info "Backup directory: /root/.vps-hardening-backups/"
                    echo ""
                    ls -lah /root/.vps-hardening-backups/ 2>/dev/null | tail -20
                    echo ""
                    print_info "Current session backups: ${BACKUP_DIR}"
                else
                    print_warning "No backups found"
                fi
                ;;
            q|Q|quit|exit)
                # Exit gracefully
                print_section "HARDENING SESSION COMPLETE"
                
                # Generate final report
                generate_report
                
                echo ""
                print_info "Session Summary:"
                echo -e "    ${BOLD}Completed tasks:${NC} ${#COMPLETED_TASKS[@]}"
                echo -e "    ${BOLD}Failed tasks:${NC}    ${#FAILED_TASKS[@]}"
                echo -e "    ${BOLD}Log file:${NC}        ${LOG_FILE}"
                echo -e "    ${BOLD}Report:${NC}          ${REPORT_FILE}"
                echo -e "    ${BOLD}Backups:${NC}         ${BACKUP_DIR}"
                echo ""
                
                if [ -n "$SSH_PORT" ]; then
                    print_warning "═══════════════════════════════════════════════════════════"
                    print_warning "  IMPORTANT: SSH is now on port ${SSH_PORT}"
                    print_warning ""
                    print_warning "  Test connection in a NEW terminal BEFORE closing:"
                    print_warning "    ${BOLD}ssh -p ${SSH_PORT} ${TARGET_USER}@$(hostname -I | awk '{print $1}')${NC}${YELLOW}"
                    print_warning "═══════════════════════════════════════════════════════════"
                    echo ""
                fi
                
                print_info "Recommended Next Steps:"
                echo -e "    ${CYAN}1.${NC} Test SSH login in a NEW terminal before closing this session"
                echo -e "    ${CYAN}2.${NC} Run: ${BOLD}lynis audit system${NC} for full security assessment"
                echo -e "    ${CYAN}3.${NC} Review: ${BOLD}cat ${LOG_FILE}${NC}"
                echo -e "    ${CYAN}4.${NC} Set up VPS snapshots via your provider"
                echo -e "    ${CYAN}5.${NC} Consider Tailscale (option 23) for zero-trust SSH"
                echo -e "    ${CYAN}6.${NC} Reboot when convenient to apply kernel changes"
                echo ""
                
                # Check if reboot needed
                if [ -f /var/run/reboot-required ]; then
                    print_warning "═══════════════════════════════════════════════════════════"
                    print_warning "  REBOOT REQUIRED to apply all changes"
                    print_warning "  Run: ${BOLD}sudo reboot${NC}${YELLOW}"
                    print_warning "═══════════════════════════════════════════════════════════"
                fi
                
                echo ""
                echo -e "  ${GREEN}${BOLD}Thank you for using VPS Hardening Script v${SCRIPT_VERSION}!${NC}"
                echo -e "  ${DIM}Stay secure. 🔒${NC}"
                echo ""
                
                exit 0
                ;;
            *)
                print_error "Invalid option: ${choice}"
                print_info "Please select a valid option from the menu"
                ;;
        esac
        
        pause
    done
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

# Run main function with all arguments
main "$@"

# End of Script
